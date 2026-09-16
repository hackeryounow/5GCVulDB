
## Bug Description

A resource exhaustion issue exists in Free5GC v4.2.3 during PFCP Session Establishment failure handling.

During PDU Session establishment, Free5GC uses PFCP signaling over the N4 interface for SMF-UPF communication. If PFCP Session Establishment Responses from the UPF are not received, the SMF continuously retransmits PFCP Session Establishment Requests. However, the resources allocated during the failed session establishment procedure are not properly released.

As a result, repeated failed session establishment attempts can gradually consume UE IP address pool resources. Once the available IP address resources are exhausted, new UEs may fail to establish PDU sessions, causing a denial-of-service (DoS) condition.

## To Reproduce

Steps to reproduce the behavior:
1. Deploy Free5GC v4.2.3 with a Docker-based 5G Core Network environment.
2. Register multiple UEs and establish normal PDU sessions using UERANSIM.
` docker exec ueransim /ueransim/nr-ue -c /ueransim/config/uecfg.yaml -n 5`
3. Deploy N4Replay between the SMF and UPF as a PFCP interceptor.
    Repository:   https://github.com/hackeryounow/n4repaly/
4. Enable PFCP message interception and drop PFCP Session Establishment Response messages from the UPF.
5. Start a new UE to trigger another PDU Session Establishment procedure.    ```
`docker exec ueransim /ueransim/nr-ue -c /ueransim/config/uecfg.yaml`
6. Observe that the SMF continuously retransmits PFCP Session Establishment Requests after the responses are dropped.
7. Repeat the procedure multiple times until the available UE IP address pool is exhausted.
8. The continuous PFCP retransmission behavior and resource exhaustion process are shown in the attached animation.

## Expected Behavior

When PFCP Session Establishment fails after retransmission timeout or retry exhaustion, Free5GC should properly release all temporarily allocated resources associated with the failed session establishment procedure.
The SMF should terminate the failed procedure and allow subsequent UEs to establish PDU sessions normally.

## Screenshots

A demonstration video is provided: [https://youtu.be/E1e14Nr_3OA](https://youtu.be/E1e14Nr_3OA)

## Environment

**Please complete the following information:**

- free5GC Version: v4.2.3
- Deployment: Docker-based 5G Core Network
- OS: Ubuntu 22.04 Desktop
- Kernel version: 138~22.04.1-Ubuntu
- go version: 1.21.8 linux/amd64

## Trace Files

- Configuration Files:
The Free5GC configuration files are provided under `n4repaly/5gc/free5gc/` in the attached archive.
The UE IP address pool network prefix was modified to `/29` to facilitate reproduction of the resource exhaustion behavior.
- PCAP File:
  `multi-est-pfcp-session-free5gc.pcapng` contains the PFCP signaling traces between SMF and UPF.
- Log File:
  `smf.log` contains the SMF log output during the reproduction.

## System Architecture (Optional)
The test environment consists of: 
- 5G Core Network: Free5GC v4.2.3
- UE simulator: UERANSIM
- PFCP test component: [N4Replay](https://github.com/hackeryounow/n4repaly)
- Interface under test: N4 interface between SMF and UPF
Architecture:
```
UERANSIM
   |
   |
Free5GC AMF/SMF -------- N4Replay -------- UPF
                              |
                              |
                    PFCP message interception
                    and response dropping
```
Deployment environment:
- Containerized deployment using Docker
- SMF and UPF communicate through PFCP over the N4 interface
## Additional Context

- Vulnerability Type:  Resource Exhaustion（Denial of Service）
- CVSS v4：`CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:L/VI:H/VA:H/SC:L/SI:L/SA:H`


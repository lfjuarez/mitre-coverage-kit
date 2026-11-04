#!/usr/bin/env bash
# Start Splunk Enterprise (trial) with the lab app, load the sample events and export what coveragekit needs.
set -euo pipefail
cd "$(dirname "$0")"
source ../.env
OUT=../out/splunk; mkdir -p "$OUT"
python3 build.py >/dev/null
[ "${REUSE:-0}" = 1 ] || {
docker rm -f ck-splunk >/dev/null 2>&1 || true
docker run -d --name ck-splunk --platform linux/amd64 -p 8000:8000 -p 8089:8089 \
  -e SPLUNK_START_ARGS=--accept-license -e SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com \
  -e SPLUNK_PASSWORD="$LAB_PASSWORD" -v "$PWD/coverage_lab:/opt/splunk/etc/apps/coverage_lab" splunk/splunk:latest >/dev/null
}
echo "waiting for Splunk..."
# Wait for the management API. On Apple Silicon (Rosetta) the KV store cannot start and the container never
# reports healthy; neither matters for this lab.
until curl -skf -u "admin:$LAB_PASSWORD" https://localhost:8089/services/server/info -o /dev/null 2>/dev/null; do sleep 10; done
API="https://localhost:8089"
for f in events/*.log; do
  st=$(basename "$f" .log); case "$st" in
    XmlWinEventLog_Security) idx=wineventlog; st="XmlWinEventLog:Security";;
    XmlWinEventLog_Microsoft-Windows-Sysmon_Operational) idx=wineventlog; st="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational";;
    stream_dns) idx=network; st="stream:dns";;
  esac
  # receivers/simple: one HTTP POST per file, each line becomes an event.
  curl -skf -u "admin:$LAB_PASSWORD" "$API/services/receivers/simple?index=$idx&sourcetype=$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$st")" \
    --data-binary @"$f" -o /dev/null
done
sleep 20
# 1. Correlation searches (what an ES admin would export).
curl -sk -u "admin:$LAB_PASSWORD" "https://localhost:8089/servicesNS/-/-/saved/searches?output_mode=json&count=0&search=action.correlationsearch.enabled%3D1" \
  -o "$OUT/correlation-searches.json"
# 2. Sources with events in the last 7 days.
curl -sk -u "admin:$LAB_PASSWORD" https://localhost:8089/services/search/jobs/export \
  --data-urlencode 'search=| tstats count where index=* by index sourcetype' -d earliest_time=-7d -d output_mode=csv \
  -o "$OUT/active-sources.csv"
echo "exported to $OUT"

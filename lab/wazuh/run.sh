#!/usr/bin/env bash
# Start a Wazuh manager, install the lab rules, send real log lines and export for coveragekit.
set -euo pipefail
cd "$(dirname "$0")"
source ../.env
VERSION=${WAZUH_VERSION:-4.12.0}
OUT=../out/wazuh; mkdir -p "$OUT"
python3 build.py >/dev/null
docker rm -f ck-wazuh >/dev/null 2>&1 || true
docker run -d --name ck-wazuh -p 55000:55000 -e API_USERNAME=lab-api -e API_PASSWORD="$LAB_PASSWORD" \
  wazuh/wazuh-manager:$VERSION >/dev/null
API=https://localhost:55000
echo "waiting for the Wazuh API..."
until TOKEN=$(curl -skf -u "lab-api:$LAB_PASSWORD" -X POST "$API/security/user/authenticate?raw=true" 2>/dev/null); do sleep 5; done
H=(-sk -H "Authorization: Bearer $TOKEN")
curl "${H[@]}" -X PUT "$API/rules/files/local_rules.xml?overwrite=true" -H Content-Type:application/octet-stream \
  --data-binary @local_rules.xml | python3 -c 'import json,sys; d=json.load(sys.stdin); print("rules upload:", d.get("message"))'
curl "${H[@]}" -X PUT "$API/manager/restart" -o /dev/null
sleep 30
until TOKEN=$(curl -skf -u "lab-api:$LAB_PASSWORD" -X POST "$API/security/user/authenticate?raw=true" 2>/dev/null); do sleep 5; done
H=(-sk -H "Authorization: Bearer $TOKEN")
# Real log lines that the default ruleset decodes: sshd failures and sudo. No Windows, audit or FIM data.
NOW=$(date -u '+%b %e %H:%M:%S')
EVENTS=$(python3 - "$NOW" <<'PY'
import json, sys
now = sys.argv[1]
lines = [f"{now} lab-linux1 sshd[{1200+i}]: Failed password for invalid user admin from 203.0.113.{i} port 4{i}22 ssh2"
         for i in range(10)]
lines += [f"{now} lab-linux1 sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash"]
print(json.dumps({"events": lines}))
PY
)
curl "${H[@]}" -X POST "$API/events" -H Content-Type:application/json -d "$EVENTS" -o /dev/null
sleep 15
# 1. Rules: the lab's custom file (add nothing to export the whole ruleset).
curl "${H[@]}" "$API/rules?filename=local_rules.xml&limit=500" -o "$OUT/rules-local.json"
curl "${H[@]}" "$API/rules?limit=100000" -o "$OUT/rules-all.json"
# 2. Rule groups seen in alerts: the log families that are actually arriving.
docker exec ck-wazuh sh -c 'cat /var/ossec/logs/alerts/alerts.json' \
  | python3 -c 'import json,sys; print("\n".join(sorted({"group:"+g for l in sys.stdin if l.strip() for g in json.loads(l)["rule"].get("groups",[])})))' \
  > "$OUT/active-groups.txt"
echo "exported to $OUT"

#!/usr/bin/env bash
# Full Wazuh single-node stack (indexer + manager + dashboard) from the official wazuh-docker repository,
# with the lab rules and a few real log lines, so the rules and alerts can be seen in the dashboard.
# Uses the repository's default demo credentials: local lab only.
set -euo pipefail
cd "$(dirname "$0")"
VERSION=${WAZUH_VERSION:-4.12.0}
SRC=../out/wazuh-docker
[ -d "$SRC" ] || git clone -q --depth 1 --branch "v$VERSION" https://github.com/wazuh/wazuh-docker.git "$SRC"
cd "$SRC/single-node"
[ -f config/wazuh_indexer_ssl_certs/root-ca.pem ] || docker compose -f generate-indexer-certs.yml run --rm generator >/dev/null
# The generator does not write the copy of the root CA that the manager mounts.
C=config/wazuh_indexer_ssl_certs
[ -f $C/root-ca-manager.pem ] || { chmod u+w $C; cp $C/root-ca.pem $C/root-ca-manager.pem; }
docker compose up -d
API=https://localhost:55000; USER=wazuh-wui; PASS='MyS3cr37P450r.*-'
echo "waiting for the Wazuh API..."
until TOKEN=$(curl -skf -u "$USER:$PASS" -X POST "$API/security/user/authenticate?raw=true" 2>/dev/null); do sleep 10; done
H=(-sk -H "Authorization: Bearer $TOKEN")
python3 "$OLDPWD/build.py" >/dev/null
curl "${H[@]}" -X PUT "$API/rules/files/local_rules.xml?overwrite=true" -H Content-Type:application/octet-stream \
  --data-binary @"$OLDPWD/local_rules.xml" | python3 -c 'import json,sys; print("rules upload:", json.load(sys.stdin).get("message"))'
curl "${H[@]}" -X PUT "$API/manager/restart" -o /dev/null
sleep 40
until TOKEN=$(curl -skf -u "$USER:$PASS" -X POST "$API/security/user/authenticate?raw=true" 2>/dev/null); do sleep 10; done
H=(-sk -H "Authorization: Bearer $TOKEN")
NOW=$(date -u '+%b %e %H:%M:%S')
EVENTS=$(python3 - "$NOW" <<'PY'
import json, sys
now = sys.argv[1]
lines = [f"{now} lab-linux1 sshd[{1200+i}]: Failed password for invalid user admin from 203.0.113.{i} port 4{i}22 ssh2" for i in range(10)]
lines += [f"{now} lab-linux1 sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash"]
print(json.dumps({"events": lines}))
PY
)
curl "${H[@]}" -X POST "$API/events" -H Content-Type:application/json -d "$EVENTS" -o /dev/null
echo "dashboard: https://localhost (admin / SecretPassword, the repository default)"

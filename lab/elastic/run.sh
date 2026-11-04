#!/usr/bin/env bash
# Start Elasticsearch + Kibana, create the lab detection rules, index sample data and export for coveragekit.
# REUSE=1 skips starting the containers.
set -euo pipefail
cd "$(dirname "$0")"
source ../.env
VERSION=${ELASTIC_VERSION:-8.17.4}
OUT=../out/elastic; mkdir -p "$OUT"
python3 build.py >/dev/null
ES="curl -s -u elastic:$LAB_PASSWORD -H Content-Type:application/json http://localhost:9200"
KB="curl -s -u elastic:$LAB_PASSWORD -H kbn-xsrf:true -H Content-Type:application/json http://localhost:5601"
KEY=$(printf '%s' "$LAB_PASSWORD$LAB_PASSWORD$LAB_PASSWORD" | head -c 32)
if [ "${REUSE:-0}" != 1 ]; then
  docker network create ck-elastic >/dev/null 2>&1 || true
  docker rm -f ck-es ck-kibana >/dev/null 2>&1 || true
  docker run -d --name ck-es --net ck-elastic -p 9200:9200 -e discovery.type=single-node \
    -e ELASTIC_PASSWORD="$LAB_PASSWORD" -e xpack.security.http.ssl.enabled=false -e xpack.security.transport.ssl.enabled=false \
    -e ES_JAVA_OPTS="-Xms768m -Xmx768m" docker.elastic.co/elasticsearch/elasticsearch:$VERSION >/dev/null
  until $ES/_cluster/health 2>/dev/null | grep -q '"status"'; do sleep 5; done
  # Security may not be ready on the first try; retry until the password is accepted.
  until $ES/_security/user/kibana_system/_password -d "{\"password\":\"$LAB_PASSWORD\"}" -o /dev/null -w '%{http_code}' | grep -q 200; do sleep 5; done
  docker run -d --name ck-kibana --net ck-elastic -p 5601:5601 -e ELASTICSEARCH_HOSTS=http://ck-es:9200 \
    -e ELASTICSEARCH_USERNAME=kibana_system -e ELASTICSEARCH_PASSWORD="$LAB_PASSWORD" \
    -e XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY="$KEY" -e XPACK_SECURITY_ENCRYPTIONKEY="$KEY" \
    -e XPACK_REPORTING_ENCRYPTIONKEY="$KEY" docker.elastic.co/kibana/kibana:$VERSION >/dev/null
fi
echo "waiting for Kibana..."
until $KB/api/status 2>/dev/null | grep -qE '"level":"(available|degraded)"'; do sleep 10; done
$KB/api/detection_engine/index -X POST >/dev/null || true
# One idempotent request for all rules (the same file the Security app's "Import rules" button takes).
curl -s -u "elastic:$LAB_PASSWORD" -H kbn-xsrf:true -m 300 -X POST \
  "http://localhost:5601/api/detection_engine/rules/_import?overwrite=true" -F "file=@rules.ndjson" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print("rules import:", d.get("success_count"), "ok,", len(d.get("errors", [])), "errors")'
# Sample data in some of the data streams the rules read.
for ds in logs-endpoint.events.process-default logs-aws.cloudtrail-default logs-network.http-default logs-llm.gateway-default logs-system.auth-default; do
  $ES/$ds/_doc -d "{\"@timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"message\":\"lab event\"}" >/dev/null
done
$ES/_refresh -X POST >/dev/null
# 1. Detection rules, as the Security app returns them.
$KB/api/detection_engine/rules/_find?per_page=1000 -o "$OUT/rules.json"
# 2. Indices with events in the last 7 days.
$ES/'logs-*/_search?size=0' -d '{"query":{"range":{"@timestamp":{"gte":"now-7d"}}},"aggs":{"i":{"terms":{"field":"_index","size":1000}}}}' \
  | python3 -c 'import json,sys; [print(b["key"]) for b in json.load(sys.stdin)["aggregations"]["i"]["buckets"]]' > "$OUT/active-indices.txt"
echo "exported to $OUT"

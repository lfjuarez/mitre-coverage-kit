"""Read-only connectors: pull the rule export and the active data sources straight from a SIEM.

Each connector performs two reads, writes the same files that ``coveragekit import`` takes, and hands them to the
importers, so nothing is parsed twice. Secrets come from environment variables, are sent only in request headers,
and are never written to disk or printed.

Authentication, from most to least preferred:

* Splunk: an authentication token (``SPLUNK_TOKEN``, Settings > Tokens) sent as ``Authorization: Bearer``.
  ``SPLUNK_USER`` and ``SPLUNK_PASSWORD`` work for deployments where tokens are disabled.
* Elastic: an API key (``ELASTIC_API_KEY``, either the encoded form Kibana shows or ``id:key``),
  sent as ``Authorization: ApiKey`` to Kibana and to Elasticsearch.
* Wazuh: the server API has no API keys, so a user with the built-in ``readonly`` role
  (``WAZUH_USER``, ``WAZUH_PASSWORD``) obtains a short-lived JWT. The indexer takes ``WAZUH_INDEXER_USER`` and
  ``WAZUH_INDEXER_PASSWORD`` (basic auth), falling back to the API user.
"""

from __future__ import annotations

import base64
import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ConnectorError(Exception):
    """A connection, authentication or response problem; the message never contains a secret."""


class _Retry(Exception):
    """A server-side error worth retrying."""


@dataclass
class Http:
    verify: bool = True
    ca: str | None = None
    timeout: int = 120
    retries: int = 3  # for 5xx answers, which SIEM APIs return when they are busy (Wazuh error 3021)
    backoff: float = 5.0

    def _context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context(cafile=self.ca)
        if not self.verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        *,
        form: dict[str, str] | None = None,
        json_body: Any = None,
    ) -> bytes:
        data = None
        headers = dict(headers or {})
        headers.setdefault("User-Agent", "mitre-coverage-kit")
        if form is not None:
            data = urllib.parse.urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif json_body is not None:
            data = json.dumps(json_body).encode()
            headers["Content-Type"] = "application/json"
        for attempt in range(self.retries + 1):
            try:
                return self._once(method, url, headers, data)
            except _Retry as exc:
                if attempt == self.retries:
                    raise ConnectorError(str(exc)) from None
                time.sleep(self.backoff * (attempt + 1))
        raise AssertionError("unreachable")

    def _once(self, method: str, url: str, headers: dict[str, str], data: bytes | None) -> bytes:
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._context()) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read()[:200].decode("utf-8", "replace").replace("\n", " ")
            if exc.code in (401, 403):
                raise ConnectorError(
                    f"{exc.code} from {_host(url)}: authentication failed or missing permission"
                ) from exc
            if exc.code >= 500:
                raise _Retry(f"{exc.code} from {_host(url)}: {detail}") from exc
            raise ConnectorError(
                f"{exc.code} from {_host(url)}{exc.reason and ': ' + str(exc.reason)} {detail}"
            ) from exc
        except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise ConnectorError(f"cannot reach {_host(url)}: {reason}") from exc

    def get_json(self, url: str, headers: dict[str, str] | None = None, **kw: Any) -> Any:
        return _json(self.request("GET", url, headers, **kw), url)

    def post_json(self, url: str, headers: dict[str, str] | None = None, **kw: Any) -> Any:
        return _json(self.request("POST", url, headers, **kw), url)


def _host(url: str) -> str:
    return urllib.parse.urlsplit(url).netloc or url


def _json(raw: bytes, url: str) -> Any:
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConnectorError(f"{_host(url)} did not return JSON") from exc


def _env(*names: str) -> str | None:
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return None


def _basic(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def _write(path: Path, content: str | bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, str):
        path.write_text(content, encoding="utf-8")
    else:
        path.write_bytes(content)
    return path


# --------------------------------------------------------------------------- Splunk


def pull_splunk(
    url: str, out_dir: Path, *, days: int = 7, http: Http | None = None, env_prefix: str = "SPLUNK"
) -> tuple[Path, Path]:
    """Correlation searches (REST) and the indexes/sourcetypes with events in the last ``days``."""
    http = http or Http()
    url = url.rstrip("/")
    p = env_prefix
    token = _env(f"{p}_TOKEN")
    user, password = _env(f"{p}_USER"), _env(f"{p}_PASSWORD")
    if token:
        auth = {"Authorization": f"Bearer {token}"}
    elif user and password:
        auth = {"Authorization": _basic(user, password)}
    else:
        raise ConnectorError(f"set {p}_TOKEN (preferred) or {p}_USER and {p}_PASSWORD")
    query = urllib.parse.urlencode({"output_mode": "json", "count": 0, "search": "action.correlationsearch.enabled=1"})
    rules = http.request("GET", f"{url}/servicesNS/-/-/saved/searches?{query}", auth)
    if b'"entry"' not in rules:
        raise ConnectorError(f"{_host(url)} returned no saved searches; check the role can read them")
    active = http.request(
        "POST",
        f"{url}/services/search/jobs/export",
        auth,
        form={
            "search": "| tstats count where index=* by index sourcetype",
            "earliest_time": f"-{days}d",
            "output_mode": "csv",
        },
    )
    return _write(out_dir / "correlation-searches.json", rules), _write(out_dir / "active-sources.csv", active)


# --------------------------------------------------------------------------- Elastic Security


def _elastic_key(prefix: str = "ELASTIC") -> str:
    key = _env(f"{prefix}_API_KEY")
    if not key:
        raise ConnectorError(
            f"set {prefix}_API_KEY (an API key with read access to Kibana Security and the log indices)"
        )
    if ":" in key:  # id:key form, as created by the API; Kibana shows the encoded form
        key = base64.b64encode(key.encode()).decode()
    return key


def pull_elastic(
    kibana_url: str,
    out_dir: Path,
    *,
    es_url: str | None = None,
    days: int = 7,
    indices: str = "logs-*,*beat-*",
    http: Http | None = None,
    env_prefix: str = "ELASTIC",
) -> tuple[Path, Path | None]:
    """Detection rules from Kibana and, when ``es_url`` is given, the indices with events in the last ``days``."""
    http = http or Http()
    auth = {"Authorization": f"ApiKey {_elastic_key(env_prefix)}", "kbn-xsrf": "true"}
    kibana_url = kibana_url.rstrip("/")
    page, per_page, data = 1, 1000, []
    while True:
        found = http.get_json(f"{kibana_url}/api/detection_engine/rules/_find?per_page={per_page}&page={page}", auth)
        data.extend(found.get("data", []))
        if len(data) >= int(found.get("total", 0)) or not found.get("data"):
            break
        page += 1
    rules_path = _write(out_dir / "rules.json", json.dumps({"data": data, "total": len(data)}, indent=1))
    if not es_url:
        return rules_path, None
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": f"now-{days}d"}}},
        "aggs": {"i": {"terms": {"field": "_index", "size": 5000}}},
    }
    target = urllib.parse.quote(indices, safe=",*")
    found = http.post_json(f"{es_url.rstrip('/')}/{target}/_search?ignore_unavailable=true", auth, json_body=body)
    buckets = found.get("aggregations", {}).get("i", {}).get("buckets", [])
    lines = "\n".join(b["key"] for b in buckets) + ("\n" if buckets else "")
    return rules_path, _write(out_dir / "active-indices.txt", lines)


# --------------------------------------------------------------------------- Wazuh


def pull_wazuh(
    api_url: str,
    out_dir: Path,
    *,
    indexer_url: str | None = None,
    days: int = 7,
    http: Http | None = None,
    env_prefix: str = "WAZUH",
) -> tuple[Path, Path | None]:
    """All rules from the server API and, when ``indexer_url`` is given, the rule groups seen in recent alerts."""
    http = http or Http()
    p = env_prefix
    user, password = _env(f"{p}_USER"), _env(f"{p}_PASSWORD")
    if not (user and password):
        raise ConnectorError(f"set {p}_USER and {p}_PASSWORD (a user with the readonly role)")
    api_url = api_url.rstrip("/")
    token = http.request(
        "POST", f"{api_url}/security/user/authenticate?raw=true", {"Authorization": _basic(user, password)}
    )
    auth = {"Authorization": f"Bearer {token.decode().strip()}"}
    items: list[dict[str, Any]] = []
    offset, limit = 0, 500
    while True:
        found = http.get_json(f"{api_url}/rules?limit={limit}&offset={offset}", auth)
        page = found.get("data", {}).get("affected_items", [])
        items.extend(page)
        total = int(found.get("data", {}).get("total_affected_items", 0))
        offset += limit
        if not page or offset >= total:
            break
    rules_path = _write(
        out_dir / "rules.json", json.dumps({"data": {"affected_items": items, "total_affected_items": len(items)}})
    )
    if not indexer_url:
        return rules_path, None
    iuser = _env(f"{p}_INDEXER_USER") or user
    ipassword = _env(f"{p}_INDEXER_PASSWORD") or password
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": f"now-{days}d"}}},
        "aggs": {"g": {"terms": {"field": "rule.groups", "size": 5000}}},
    }
    found = http.post_json(
        f"{indexer_url.rstrip('/')}/wazuh-alerts-*/_search", {"Authorization": _basic(iuser, ipassword)}, json_body=body
    )
    buckets = found.get("aggregations", {}).get("g", {}).get("buckets", [])
    lines = "\n".join(f"group:{b['key']}" for b in buckets) + ("\n" if buckets else "")
    return rules_path, _write(out_dir / "active-groups.txt", lines)


CONNECTORS = {"splunk": pull_splunk, "elastic": pull_elastic, "wazuh": pull_wazuh}

"""Connectors against a local fake SIEM: auth headers, pagination, outputs, and that no secret reaches disk."""

import base64
import csv
import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from coveragekit import connectors
from coveragekit.cli import main

EXPORTS = Path(__file__).parent / "fixtures" / "exports"
SECRET = "s3cr3t-value-never-on-disk"


class Fake(BaseHTTPRequestHandler):
    seen: list[tuple[str, str, str]] = []
    searches: list[str] = []
    models: dict[str, int] = {"Endpoint": 12}

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(raw)

    def _route(self):
        auth = self.headers.get("Authorization", "")
        Fake.seen.append((self.command, self.path, auth))
        length = int(self.headers.get("Content-Length") or 0)
        self.body = self.rfile.read(length) if length else b""
        p = self.path
        if p.startswith("/busy"):
            Fake.busy = getattr(Fake, "busy", 0) + 1
            return self._send(500, {"error": 3021}) if Fake.busy < 3 else self._send(200, {"ok": True})
        # Splunk
        if p.startswith("/servicesNS/-/-/saved/searches"):
            if auth != f"Bearer {SECRET}":
                return self._send(401, {"messages": [{"text": "unauthorized"}]})
            return self._send(200, (EXPORTS / "splunk-rest.json").read_bytes())
        if p == "/services/search/jobs/export":
            assert b"earliest_time=-3d" in self.body or b"earliest_time=-7d" in self.body
            form = urllib.parse.parse_qs(self.body.decode())
            search = form["search"][0]
            Fake.searches.append(search)
            if "datamodel=" in search:
                model = search.split("datamodel=")[1]
                if model in Fake.models:
                    return self._send(200, f"count\n{Fake.models[model]}\n".encode(), "text/csv")
                return self._send(400, {"messages": [{"text": "Error in tstats: unknown data model"}]})
            return self._send(200, b"index,sourcetype,count\nlinux,linux_secure,4\n", "text/csv")
        # Kibana / Elasticsearch
        if p.startswith("/api/detection_engine/rules/_find"):
            if auth != "ApiKey " + base64.b64encode(f"id:{SECRET}".encode()).decode():
                return self._send(401, {})
            rules = [json.loads(line) for line in (EXPORTS / "elastic-export.ndjson").read_text().splitlines()][:4]
            page = int(p.split("page=")[-1])
            return self._send(200, {"data": rules[(page - 1) * 2 : page * 2], "total": 4})  # two pages of two
        if p.startswith("/logs-*,*beat-*/_search"):
            return self._send(
                200,
                {
                    "aggregations": {
                        "i": {"buckets": [{"key": ".ds-logs-endpoint.events.process-default-2026.11.04-000001"}]}
                    }
                },
            )
        # Wazuh
        if p.startswith("/security/user/authenticate"):
            if auth != "Basic " + base64.b64encode(f"ro:{SECRET}".encode()).decode():
                return self._send(401, {})
            return self._send(200, b"jwt-token", "text/plain")
        if p.startswith("/rules?"):
            assert auth == "Bearer jwt-token"
            items = json.loads((EXPORTS / "wazuh-api.json").read_text())["data"]["affected_items"]
            offset = int(p.split("offset=")[-1])
            return self._send(
                200, {"data": {"affected_items": items[offset : offset + 500], "total_affected_items": len(items)}}
            )
        if p.startswith("/wazuh-alerts-*/_search"):
            return self._send(200, {"aggregations": {"g": {"buckets": [{"key": "sshd"}, {"key": "syslog"}]}}})
        return self._send(404, {})

    do_GET = do_POST = _route


@pytest.fixture()
def fake():
    Fake.seen, Fake.searches, Fake.models = [], [], {"Endpoint": 12}
    server = ThreadingHTTPServer(("127.0.0.1", 0), Fake)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def no_secret_in(path: Path):
    for f in path.rglob("*"):
        if f.is_file():
            assert SECRET not in f.read_text(errors="replace"), f


def test_pull_splunk_with_token(fake, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SPLUNK_TOKEN", SECRET)
    out = tmp_path / "splunk.csv"
    args = ["pull", "splunk", "--url", fake, "--days", "3", "--save-exports", str(tmp_path / "raw"), "--out", str(out)]
    assert main(args) == 0
    rows = {r["rule_id"]: r for r in csv.DictReader(open(out))}
    assert rows["ESCU - Linux Sudo Brute Force"]["data_available"] == "true"
    # the rule reads the Endpoint data model, which had events: it is not dead
    assert rows["ESCU - Windows PowerShell Encoded Command"]["data_available"] == "true"
    assert "| tstats count from datamodel=Endpoint" in Fake.searches
    assert (tmp_path / "raw" / "correlation-searches.json").is_file()
    active = list(csv.DictReader(open(tmp_path / "raw" / "active-sources.csv")))
    assert {"index": "", "sourcetype": "", "datamodel": "Endpoint", "count": "12"} in active
    no_secret_in(tmp_path)
    assert SECRET not in capsys.readouterr().out


@pytest.mark.parametrize("models", [{"Endpoint": 0}, {}], ids=["no-events", "unknown-model"])
def test_pull_splunk_datamodel_without_data_is_dead(fake, tmp_path, monkeypatch, models):
    Fake.models = models
    monkeypatch.setenv("SPLUNK_TOKEN", SECRET)
    out = tmp_path / "splunk.csv"
    assert main(["pull", "splunk", "--url", fake, "--days", "3", "--out", str(out)]) == 0
    rows = {r["rule_id"]: r for r in csv.DictReader(open(out))}
    assert rows["ESCU - Windows PowerShell Encoded Command"]["data_available"] == "false"
    assert rows["ESCU - Windows PowerShell Encoded Command"]["missing_data"] == "datamodel:Endpoint"
    assert rows["ESCU - Linux Sudo Brute Force"]["data_available"] == "true"


def test_splunk_datamodel_names_are_validated():
    raw = json.dumps(
        {
            "entry": [
                {"content": {"search": "| tstats count from datamodel=Network_Traffic.All_Traffic by x"}},
                {"content": {"search": "| datamodel Authentication search | stats count"}},
                {"content": {"search": "index=main sourcetype=foo"}},
            ]
        }
    ).encode()
    assert connectors._splunk_datamodels(raw) == ["Authentication", "Network_Traffic"]
    assert connectors._splunk_datamodels(b"not json") == []


def test_pull_splunk_bad_token_is_a_clean_error(fake, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SPLUNK_TOKEN", "wrong")
    assert main(["pull", "splunk", "--url", fake, "--out", str(tmp_path / "x.csv")]) == 1
    err = capsys.readouterr().err
    assert "401" in err and "authentication failed" in err and "wrong" not in err


def test_pull_requires_credentials(tmp_path, monkeypatch, capsys):
    for name in ("SPLUNK_TOKEN", "SPLUNK_USER", "SPLUNK_PASSWORD"):
        monkeypatch.delenv(name, raising=False)
    assert main(["pull", "splunk", "--url", "http://127.0.0.1:9", "--out", str(tmp_path / "x.csv")]) == 1
    assert "SPLUNK_TOKEN" in capsys.readouterr().err


def test_pull_elastic_api_key_and_pagination(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("ELASTIC_API_KEY", f"id:{SECRET}")
    out = tmp_path / "elastic.csv"
    assert main(["pull", "elastic", "--url", fake, "--es-url", fake, "--out", str(out)]) == 0
    rows = {r["rule_id"]: r for r in csv.DictReader(open(out))}
    assert set(rows) == {"e1", "e2", "e3"}  # four rules over two pages; e4 has no technique
    assert rows["e1"]["data_available"] == "true" and rows["e2"]["data_available"] == "false"
    assert sum(1 for m, p, _ in Fake.seen if p.startswith("/api/detection_engine")) == 2
    no_secret_in(tmp_path)


def test_pull_wazuh_jwt_and_indexer(fake, tmp_path, monkeypatch):
    monkeypatch.setenv("WAZUH_USER", "ro")
    monkeypatch.setenv("WAZUH_PASSWORD", SECRET)
    out = tmp_path / "wazuh.csv"
    assert main(["pull", "wazuh", "--url", fake, "--indexer-url", fake, "--out", str(out)]) == 0
    rows = {r["rule_id"]: r for r in csv.DictReader(open(out))}
    assert rows["5712"]["data_available"] == "true"
    assert [a for m, p, a in Fake.seen if p.startswith("/rules")] == ["Bearer jwt-token"]
    no_secret_in(tmp_path)


def test_unreachable_host(tmp_path, monkeypatch):
    monkeypatch.setenv("SPLUNK_TOKEN", SECRET)
    with pytest.raises(connectors.ConnectorError, match="cannot reach"):
        connectors.pull_splunk("http://127.0.0.1:9", tmp_path, http=connectors.Http(timeout=2))


def test_diff_reports_improvements_regressions_and_dead_rules(tmp_path, capsys):
    header = "rule_id,name,techniques,enabled,data_available,tested,tuned\n"
    (tmp_path / "a.csv").write_text(
        header + "A,a,T1059,true,true,false,false\nB,b,T1110,true,false,false,false\nC,c,T1003,true,true,true,true\n"
    )
    (tmp_path / "b.csv").write_text(
        header + "A,a,T1059,true,true,true,true\nB,b,T1110,true,true,false,false\nC,c,T1003,true,false,true,true\n"
    )
    for n in ("a", "b"):
        assert (
            main(
                [
                    "score",
                    "--rules",
                    str(tmp_path / f"{n}.csv"),
                    "--framework",
                    "attack",
                    "--out",
                    str(tmp_path / f"{n}.json"),
                    "--history",
                    str(tmp_path / "hist"),
                ]
            )
            == 0
        )
    assert len(list((tmp_path / "hist").glob("coverage-*.json"))) >= 1
    capsys.readouterr()
    assert main(["diff", str(tmp_path / "a.json"), str(tmp_path / "b.json"), "--out", str(tmp_path / "d.json")]) == 0
    text = capsys.readouterr().out
    assert "+ T1059 Command and Scripting Interpreter: Low -> High" in text
    assert "+ T1110 Brute Force: None -> Low" in text
    assert "- T1003 OS Credential Dumping: High -> None" in text
    assert "new dead rules (1): C" in text and "dead rules resolved (1): B" in text
    d = json.loads((tmp_path / "d.json").read_text())["frameworks"]["attack"]
    assert len(d["improved"]) == 2 and len(d["regressed"]) == 1


def test_retries_server_errors(fake):
    Fake.busy = 0
    http = connectors.Http(backoff=0.01)
    assert http.get_json(fake + "/busy") == {"ok": True}
    Fake.busy = -10
    with pytest.raises(connectors.ConnectorError, match="500"):
        connectors.Http(retries=1, backoff=0.01).get_json(fake + "/busy")

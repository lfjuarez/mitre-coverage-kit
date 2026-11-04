import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from coveragekit.server import ConfigError, Workspace, load_config, make_handler

EXPORTS = Path(__file__).parent / "fixtures" / "exports"


def write_config(tmp_path, body):
    cfg = tmp_path / "coveragekit.toml"
    cfg.write_text(f'[server]\ntitle = "Test SOC"\ndata_dir = "data"\nrefresh_hours = 0\n\n{body}')
    return cfg


TWO_SPLUNKS = f"""
[[source]]
name = "Splunk Producción"
type = "import"
siem = "splunk"
export = "{EXPORTS / "splunk-rest.json"}"

[[source]]
name = "Splunk DR"
type = "import"
siem = "splunk"
export = "{EXPORTS / "splunk-rest.csv"}"

[[source]]
name = "Elastic Cloud"
type = "import"
siem = "elastic"
export = "{EXPORTS / "elastic-export.ndjson"}"

[[source]]
name = "Hand kept"
type = "inventory"
path = "{Path("examples/rules.csv").resolve()}"
"""


def test_config_validation(tmp_path):
    cfg = load_config(write_config(tmp_path, TWO_SPLUNKS))
    assert [s.name for s in cfg.sources] == ["Splunk Producción", "Splunk DR", "Elastic Cloud", "Hand kept"]
    assert cfg.data_dir == (tmp_path / "data").resolve()
    bad = {
        'type = "qradar"\nname = "x"': "type must be one of",
        'type = "splunk"\nname = "x"': "missing url",
        'type = "splunk"\nname = "x"\nurl = "https://s"\ntoken = "abc"': "environment variables",
        'type = "splunk"\nname = "x"\nurl = "https://s"\nenv_prefix = "bad-prefix"': "env_prefix",
    }
    for body, message in bad.items():
        with pytest.raises(ConfigError, match=message):
            load_config(write_config(tmp_path, f"[[source]]\n{body}\n"))
    with pytest.raises(ConfigError, match="duplicate name"):
        load_config(
            write_config(
                tmp_path,
                '[[source]]\nname="a"\ntype="inventory"\npath="x"\n[[source]]\nname="a"\ntype="inventory"\npath="y"\n',
            )
        )


def test_refresh_several_named_sources_and_history(tmp_path):
    ws = Workspace(load_config(write_config(tmp_path, TWO_SPLUNKS)))
    assert ws.refresh()["ok"]
    state = ws.state()
    assert {s["name"]: s["rules"] for s in state["sources"]} == {
        "Splunk Producción": 3,
        "Splunk DR": 1,
        "Elastic Cloud": 3,
        "Hand kept": 85,
    }
    sources = {r["source"] for r in state["rules"]}
    assert {
        "Splunk Producción",
        "Splunk DR",
        "Elastic Cloud",
        "EDR",
    } <= sources  # inventories keep their own source column
    assert state["coverage"]["attack"]["sources"]  # the per-source breakdown sees every named source
    assert ws.refresh()["ok"]
    assert len(ws.state()["history"]) == 2 and ws.state()["change"]["frameworks"]["attack"]
    assert (tmp_path / "data" / "inventories" / "splunk-producci-n.csv").is_file()


def test_failing_source_keeps_its_last_good_inventory(tmp_path):
    cfg_path = write_config(tmp_path, TWO_SPLUNKS)
    ws = Workspace(load_config(cfg_path))
    ws.refresh()
    broken = load_config(cfg_path)
    broken.sources[2].options["export"] = str(tmp_path / "gone.ndjson")
    ws2 = Workspace(broken)
    assert ws2.refresh()["ok"] is False
    elastic = next(s for s in ws2.state()["sources"] if s["name"] == "Elastic Cloud")
    assert elastic["ok"] is False and elastic["stale"] and "gone.ndjson" in elastic["error"]
    assert any(r["source"] == "Elastic Cloud" for r in ws2.state()["rules"])


@pytest.fixture()
def running(tmp_path):
    ws = Workspace(load_config(write_config(tmp_path, TWO_SPLUNKS)))
    ws.refresh()
    ws.refresh()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(ws, {"127.0.0.1", "localhost"}))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_port}", ws
    httpd.shutdown()


def call(url, method="GET", headers=None):
    req = urllib.request.Request(url, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


def test_api_pages_and_downloads(running):
    base, ws = running
    code, body, headers = call(base + "/")
    assert code == 200 and b"coverage<span>kit</span>" in body
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"] and headers["X-Frame-Options"] == "DENY"
    code, body, _ = call(base + "/api/state")
    state = json.loads(body)
    assert code == 200 and state["title"] == "Test SOC" and len(state["history"]) == 2
    h = state["history"]
    code, body, _ = call(f"{base}/api/diff?from={h[0]['id']}&to={h[1]['id']}")
    assert code == 200 and "attack" in json.loads(body)["frameworks"]
    assert call(f"{base}/api/diff?from=../../etc/passwd&to=x")[0] == 404
    assert call(base + "/report.html")[0] == 200
    code, _, headers = call(base + "/attack-layer.json")
    assert code == 200 and "attachment" in headers["Content-Disposition"]


def test_api_protections(running):
    base, ws = running
    assert call(base + "/api/state", headers={"Host": "evil.example"})[0] == 403  # DNS rebinding
    assert call(base + "/api/refresh", "POST")[0] == 403  # no custom header: a cross-site form cannot do this
    code, body, _ = call(base + "/api/refresh", "POST", {"X-Coveragekit": "1"})
    assert code == 202 and json.loads(body)["started"]

"""``coveragekit serve``: a local web app that refreshes coverage on a schedule and lets you browse it.

The server keeps a workspace directory with one inventory per source, the history of ``coverage.json``
snapshots and the status of the last refresh. It uses only the standard library.

Configuration (TOML)::

    [server]
    title = "Example SOC"
    data_dir = "coveragekit-data"      # relative to the config file
    refresh_hours = 6                  # 0 disables the schedule; "Refresh now" still works
    host = "127.0.0.1"
    port = 8700

    [[source]]                         # pulled with a connector; credentials come from the environment
    name = "Splunk ES"
    type = "splunk"                    # splunk | elastic | wazuh
    url = "https://splunk.example.com:8089"
    days = 7
    env_prefix = "SPLUNK_PROD"         # reads SPLUNK_PROD_TOKEN, or SPLUNK_PROD_USER and _PASSWORD
    # es_url / indexer_url / indices / ca / insecure, as in `coveragekit pull`

    [[source]]                         # as many of each type as you need, each with its own name and prefix
    name = "Splunk DR"
    type = "splunk"
    url = "https://splunk-dr.example.com:8089"
    env_prefix = "SPLUNK_DR"

    [[source]]                         # a native export on disk, read with an importer
    name = "Sigma"
    type = "import"
    siem = "sigma"
    export = "sigma/rules"
    data_sources = "logsources.txt"

    [[source]]                         # an inventory CSV maintained by hand
    name = "EDR"
    type = "inventory"
    path = "edr.csv"
"""

from __future__ import annotations

import csv
import datetime as dt
import json
import re
import threading
import tomllib
import traceback
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from . import __version__, connectors, frameworks, importers
from .diff import diff
from .html import render_html
from .navigator import build_layer
from .rules import Rule, RuleError, load_rules
from .scoring import Coverage, rule_quality, score

SOURCE_TYPES = ("splunk", "elastic", "wazuh", "import", "inventory", "catalog")
STAMP = "%Y-%m-%dT%H%M%S-%f"


class ConfigError(ValueError):
    """The configuration file cannot be used."""


@dataclass
class Source:
    name: str
    type: str
    options: dict[str, Any]

    @property
    def slug(self) -> str:
        return re.sub(r"[^a-z0-9]+", "-", self.name.lower()).strip("-") or "source"


@dataclass
class Config:
    path: Path
    title: str = "Detection coverage"
    data_dir: Path = Path("coveragekit-data")
    refresh_hours: float = 6.0
    host: str = "127.0.0.1"
    port: int = 8700
    frameworks_dir: str | None = None
    sources: list[Source] = field(default_factory=list)


def load_config(path: str | Path) -> Config:
    path = Path(path)
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    server = raw.get("server", {})
    base = path.resolve().parent
    cfg = Config(
        path=path,
        title=str(server.get("title", "Detection coverage")),
        data_dir=(base / server.get("data_dir", "coveragekit-data")).resolve(),
        refresh_hours=float(server.get("refresh_hours", 6)),
        host=str(server.get("host", "127.0.0.1")),
        port=int(server.get("port", 8700)),
        frameworks_dir=server.get("frameworks_dir"),
    )
    seen: set[str] = set()
    for i, s in enumerate(raw.get("source", []), 1):
        kind = str(s.get("type", ""))
        if kind not in SOURCE_TYPES:
            raise ConfigError(f"source {i}: type must be one of {', '.join(SOURCE_TYPES)}")
        name = str(s.get("name") or kind)
        if name in seen:
            raise ConfigError(f"source {i}: duplicate name '{name}'")
        seen.add(name)
        opts = {k: v for k, v in s.items() if k not in ("name", "type")}
        for key in ("export", "data_sources", "path", "ca"):
            if key in opts and opts[key]:
                opts[key] = str((base / str(opts[key])).resolve())
        needs = {
            "splunk": ["url"],
            "elastic": ["url"],
            "wazuh": ["url"],
            "import": ["siem", "export"],
            "inventory": ["path"],
            "catalog": ["path"] if opts.get("path") else ["siem", "export"],
        }
        missing = [k for k in needs[kind] if not opts.get(k)]
        if missing:
            raise ConfigError(f"source '{name}': missing {', '.join(missing)}")
        if "env_prefix" in opts and not re.fullmatch(r"[A-Z][A-Z0-9_]*", str(opts["env_prefix"])):
            raise ConfigError(f"source '{name}': env_prefix must be upper case letters, digits and underscores")
        if any(k.lower() in ("token", "password", "api_key", "apikey", "secret") for k in opts):
            raise ConfigError(f"source '{name}': credentials go in environment variables, not in the config file")
        cfg.sources.append(Source(name, kind, opts))
    if not cfg.sources:
        raise ConfigError("the configuration has no [[source]]")
    return cfg


def _now() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


class Workspace:
    """Inventories, history and state on disk, plus the current scored result in memory."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.dir = cfg.data_dir
        (self.dir / "inventories").mkdir(parents=True, exist_ok=True)
        (self.dir / "history").mkdir(parents=True, exist_ok=True)
        (self.dir / "exports").mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.refreshing = False
        self.results: dict[str, Coverage] = {}
        self.rules: list[Rule] = []
        self.catalog: list[Rule] | None = None
        self.status: dict[str, Any] = self._read_json(self.dir / "status.json") or {"sources": {}, "updated": None}
        self.next_refresh: str | None = None

    @staticmethod
    def _read_json(path: Path) -> Any:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    # ------------------------------------------------------------------ refresh

    def _inventory_for(self, src: Source) -> Path:
        if src.type == "inventory" or (src.type == "catalog" and src.options.get("path")):
            return Path(src.options["path"])
        out = self.dir / "inventories" / f"{src.slug}.csv"
        previous = {}  # the last inventory of this source keeps its manual tested/tuned/owner columns
        if out.is_file():
            with open(out, newline="", encoding="utf-8") as fh:
                previous = {r["rule_id"]: r for r in csv.DictReader(fh) if r.get("rule_id")}
        if src.type in ("import", "catalog"):
            export, active = src.options["export"], src.options.get("data_sources")
        else:
            o = src.options
            http = connectors.Http(verify=not o.get("insecure", False), ca=o.get("ca"))
            raw = self.dir / "exports" / src.slug
            days = int(o.get("days", 7))
            prefix = str(o.get("env_prefix") or src.type.upper())
            if src.type == "splunk":
                export, active = connectors.pull_splunk(o["url"], raw, days=days, http=http, env_prefix=prefix)
            elif src.type == "elastic":
                export, active = connectors.pull_elastic(
                    o["url"],
                    raw,
                    es_url=o.get("es_url"),
                    days=days,
                    indices=o.get("indices", "logs-*,*beat-*"),
                    http=http,
                    env_prefix=prefix,
                )
            else:
                export, active = connectors.pull_wazuh(
                    o["url"], raw, indexer_url=o.get("indexer_url"), days=days, http=http, env_prefix=prefix
                )
        mapped, _unmapped, _warnings = importers.run_import(src.options.get("siem", src.type), export, active)
        rows = importers.to_rows(mapped, previous)
        for row in rows:  # one source name per inventory, so the UI can filter by it
            row["source"] = src.name
        importers.write_csv(rows, out)
        return out

    def refresh(self) -> dict[str, Any]:
        """Pull or import every source, score, and append a snapshot to the history."""
        with self.lock:
            if self.refreshing:
                return {"started": False, "reason": "a refresh is already running"}
            self.refreshing = True
        try:
            statuses: dict[str, Any] = {}
            rules: list[Rule] = []
            catalog: list[Rule] = []
            seen: set[str] = set()
            for src in self.cfg.sources:
                started = _now()
                try:
                    path = self._inventory_for(src)
                    loaded = load_rules(path)
                    if src.type == "catalog":  # available rules: suggestions only, never coverage
                        catalog.extend(loaded)
                        statuses[src.name] = {"ok": True, "type": src.type, "at": started, "rules": len(loaded)}
                        continue
                    for r in loaded:
                        r.source = src.name if src.type != "inventory" or not r.source else r.source
                        if r.rule_id in seen:
                            r.rule_id = f"{src.name}:{r.rule_id}"
                        seen.add(r.rule_id)
                    rules.extend(loaded)
                    dead = sum(r.enabled and not r.data_available for r in loaded)
                    statuses[src.name] = {
                        "ok": True,
                        "type": src.type,
                        "at": started,
                        "rules": len(loaded),
                        "dead": dead,
                    }
                except (connectors.ConnectorError, importers.ExportError, RuleError, OSError) as exc:
                    prev = self.status.get("sources", {}).get(src.name, {})
                    statuses[src.name] = {
                        "ok": False,
                        "type": src.type,
                        "at": started,
                        "error": str(exc),
                        "rules": prev.get("rules"),
                        "last_ok": prev.get("at") if prev.get("ok") else prev.get("last_ok"),
                    }
                    fallback = self.dir / "inventories" / f"{src.slug}.csv"
                    if fallback.is_file() and src.type == "catalog":
                        catalog.extend(load_rules(fallback))
                        statuses[src.name]["stale"] = True
                    elif fallback.is_file():  # keep the source in the picture with its last good inventory
                        loaded = load_rules(fallback)
                        for r in loaded:
                            r.source = src.name
                            if r.rule_id in seen:
                                r.rule_id = f"{src.name}:{r.rule_id}"
                            seen.add(r.rule_id)
                        rules.extend(loaded)
                        statuses[src.name]["stale"] = True
            if not rules:
                raise RuleError("no source produced rules")
            packages = {n: frameworks.load(n, self.cfg.frameworks_dir) for n in ("attack", "atlas")}
            cat = catalog if any(s.type == "catalog" for s in self.cfg.sources) else None
            results = {n: score(rules, p, cat) for n, p in packages.items()}
            stamp = dt.datetime.now().strftime(STAMP)
            payload: dict[str, Any] = {"generator": f"mitre-coverage-kit {__version__}", "taken_at": _now()}
            payload.update({n: c.to_dict() for n, c in results.items()})
            (self.dir / "history" / f"coverage-{stamp}.json").write_text(
                json.dumps(payload, ensure_ascii=False), encoding="utf-8"
            )
            with self.lock:
                self.results, self.rules, self.catalog = results, rules, cat
                self.status = {"sources": statuses, "updated": _now()}
            (self.dir / "status.json").write_text(json.dumps(self.status, indent=1), encoding="utf-8")
            return {"started": True, "ok": all(s["ok"] for s in statuses.values())}
        finally:
            with self.lock:
                self.refreshing = False

    def load_latest(self) -> bool:
        """Rebuild the in-memory result from the inventories on disk, without touching the SIEMs."""
        rules: list[Rule] = []
        catalog: list[Rule] = []
        seen: set[str] = set()
        for src in self.cfg.sources:
            own = src.type == "inventory" or (src.type == "catalog" and src.options.get("path"))
            path = Path(src.options["path"]) if own else self.dir / "inventories" / f"{src.slug}.csv"
            if not path.is_file():
                continue
            if src.type == "catalog":
                catalog.extend(load_rules(path))
                continue
            for r in load_rules(path):
                r.source = r.source if src.type == "inventory" and r.source else src.name
                if r.rule_id in seen:
                    r.rule_id = f"{src.name}:{r.rule_id}"
                seen.add(r.rule_id)
                rules.append(r)
        if not rules:
            return False
        packages = {n: frameworks.load(n, self.cfg.frameworks_dir) for n in ("attack", "atlas")}
        cat = catalog if any(s.type == "catalog" for s in self.cfg.sources) else None
        with self.lock:
            self.rules, self.catalog = rules, cat
            self.results = {n: score(rules, p, cat) for n, p in packages.items()}
        return True

    # ------------------------------------------------------------------ views

    def history(self) -> list[dict[str, Any]]:
        out = []
        for f in sorted((self.dir / "history").glob("coverage-*.json")):
            data = self._read_json(f)
            if not data or "attack" not in data:
                continue
            entry = {"id": f.stem.removeprefix("coverage-"), "taken_at": data.get("taken_at")}
            for fw in ("attack", "atlas"):
                if fw in data:
                    t = data[fw]["totals"]
                    entry[fw] = {
                        "percent": t["percent"],
                        "covered": t["distinct_covered"],
                        "by_level": t["by_level"],
                        "dead": len(data[fw].get("dead_rules", [])),
                    }
            out.append(entry)
        return out

    def snapshot(self, snap_id: str) -> dict[str, Any] | None:
        if not re.fullmatch(r"[0-9T-]+", snap_id):
            return None
        return self._read_json(self.dir / "history" / f"coverage-{snap_id}.json")

    def state(self) -> dict[str, Any]:
        with self.lock:
            results, rules, status, refreshing = self.results, self.rules, self.status, self.refreshing
        hist = self.history()
        change = None
        if len(hist) >= 2:
            a, b = self.snapshot(hist[-2]["id"]), self.snapshot(hist[-1]["id"])
            if a and b:
                change = {"from": hist[-2]["id"], "to": hist[-1]["id"], **diff(a, b)}
        rule_rows = []
        level_names = {0: "None", 1: "Low", 2: "Medium", 3: "High"}
        for r in rules:
            q = rule_quality(r)
            state = "disabled" if not r.enabled else "dead" if not r.data_available else level_names[q].lower()
            rule_rows.append(
                {
                    "id": r.rule_id,
                    "name": r.name,
                    "source": r.source,
                    "techniques": r.valid_techniques,
                    "enabled": r.enabled,
                    "data": r.data_available,
                    "tested": r.tested,
                    "tuned": r.tuned,
                    "owner": r.owner,
                    "level": q,
                    "state": state,
                    "data_sources": r.data_sources,
                    "missing": r.missing_data,
                }
            )
        return {
            "title": self.cfg.title,
            "version": __version__,
            "updated": status.get("updated"),
            "refreshing": refreshing,
            "next_refresh": self.next_refresh,
            "refresh_hours": self.cfg.refresh_hours,
            "sources": [
                {"name": s.name, "type": s.type, **status.get("sources", {}).get(s.name, {})} for s in self.cfg.sources
            ],
            "coverage": {n: c.to_dict() for n, c in results.items()},
            "rules": rule_rows,
            "history": hist,
            "change": change,
        }


# ---------------------------------------------------------------------- HTTP


def _app_html() -> str:
    return resources.files("coveragekit").joinpath("web/app.html").read_text(encoding="utf-8")


def make_handler(ws: Workspace, allowed_hosts: set[str]):
    class Handler(BaseHTTPRequestHandler):
        server_version = f"coveragekit/{__version__}"

        def log_message(self, fmt: str, *args: Any) -> None:  # quiet by default
            pass

        def _send(
            self, code: int, body: bytes | str, ctype: str = "application/json", extra: dict[str, str] | None = None
        ) -> None:
            raw = body.encode("utf-8") if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", f"{ctype}; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
            )
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(raw)

        def _json(self, code: int, obj: Any) -> None:
            self._send(code, json.dumps(obj, ensure_ascii=False))

        def _host_ok(self) -> bool:
            # Guards against DNS rebinding: a page on another site cannot reach the API through a hostname it controls.
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]").lower()
            return host in allowed_hosts

        def do_GET(self) -> None:  # noqa: N802
            if not self._host_ok():
                return self._json(HTTPStatus.FORBIDDEN, {"error": "host not allowed"})
            url = urlsplit(self.path)
            q = parse_qs(url.query)
            try:
                if url.path in ("/", "/index.html"):
                    return self._send(200, _app_html(), "text/html")
                if url.path == "/api/state":
                    return self._json(200, ws.state())
                if url.path == "/api/diff":
                    a, b = ws.snapshot(q.get("from", [""])[0]), ws.snapshot(q.get("to", [""])[0])
                    if not (a and b):
                        return self._json(404, {"error": "snapshot not found"})
                    return self._json(200, diff(a, b))
                if url.path == "/report.html":
                    if not ws.results:
                        return self._json(409, {"error": "no data yet"})
                    return self._send(200, render_html(ws.results, ws.rules, title=ws.cfg.title), "text/html")
                if url.path == "/attack-layer.json":
                    if "attack" not in ws.results:
                        return self._json(409, {"error": "no data yet"})
                    layer = json.dumps(build_layer(ws.results["attack"], name=ws.cfg.title), indent=1)
                    return self._send(
                        200,
                        layer,
                        "application/json",
                        {"Content-Disposition": 'attachment; filename="attack-layer.json"'},
                    )
                if url.path.startswith("/export/"):
                    return self._export(url.path.removeprefix("/export/"), q)
                if url.path == "/healthz":
                    return self._json(200, {"ok": True})
                return self._json(404, {"error": "not found"})
            except Exception:  # noqa: BLE001  a bug must not take the server down
                traceback.print_exc()
                return self._json(500, {"error": "internal error"})

        def _export(self, name: str, q: dict[str, list[str]]) -> None:
            from .export import CONTENT_TYPES, ExportFailed, export

            files = {
                "report.pdf": ("pdf", "techniques"),
                "coverage.xlsx": ("xlsx", "techniques"),
                "techniques.csv": ("csv", "techniques"),
                "rules.csv": ("csv", "rules"),
                "recommendations.csv": ("csv", "recommendations"),
                "summary.md": ("md", "techniques"),
                "coverage.json": ("json", "techniques"),
                "report.html": ("html", "techniques"),
            }
            if name not in files:
                return self._json(404, {"error": "unknown export"})
            if not ws.results:
                return self._json(409, {"error": "no data yet"})
            fmt, table = files[name]
            try:
                data = export(ws.results, ws.rules, fmt, ws.cfg.title, table)
            except ExportFailed as exc:
                return self._json(501, {"error": str(exc)})
            stamp = dt.date.today().isoformat()
            slug = re.sub(r"[^a-z0-9]+", "-", ws.cfg.title.lower()).strip("-") or "coverage"
            stem, ext = name.rsplit(".", 1)
            filename = f"{slug}-{stem}-{stamp}.{ext}"
            ctype = CONTENT_TYPES[fmt]
            if fmt in ("pdf", "xlsx"):
                self.send_response(200)
                for k, v in (
                    ("Content-Type", ctype),
                    ("Content-Length", str(len(data))),
                    ("Cache-Control", "no-store"),
                    ("X-Content-Type-Options", "nosniff"),
                    ("Content-Disposition", f'attachment; filename="{filename}"'),
                ):
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)
                return None
            return self._send(200, data, ctype, {"Content-Disposition": f'attachment; filename="{filename}"'})

        def do_POST(self) -> None:  # noqa: N802
            if not self._host_ok():
                return self._json(HTTPStatus.FORBIDDEN, {"error": "host not allowed"})
            # A cross-site form cannot set custom headers, so this blocks CSRF without a session.
            if self.headers.get("X-Coveragekit") != "1":
                return self._json(HTTPStatus.FORBIDDEN, {"error": "missing X-Coveragekit header"})
            if urlsplit(self.path).path == "/api/refresh":
                if ws.refreshing:
                    return self._json(409, {"error": "a refresh is already running"})
                threading.Thread(target=_safe_refresh, args=(ws,), daemon=True).start()
                return self._json(202, {"started": True})
            return self._json(404, {"error": "not found"})

    return Handler


def _safe_refresh(ws: Workspace) -> None:
    try:
        ws.refresh()
    except Exception:  # noqa: BLE001
        traceback.print_exc()


def _schedule(ws: Workspace, stop: threading.Event) -> None:
    hours = ws.cfg.refresh_hours
    while not stop.is_set():
        due = dt.datetime.now().astimezone() + dt.timedelta(hours=hours)
        ws.next_refresh = due.isoformat(timespec="seconds")
        if stop.wait(hours * 3600):
            break
        _safe_refresh(ws)


def serve(cfg: Config, *, refresh_on_start: bool = True, ready: threading.Event | None = None) -> None:
    ws = Workspace(cfg)
    if not ws.load_latest() or refresh_on_start:
        print("refreshing all sources...")
        _safe_refresh(ws)
    allowed = (
        {"127.0.0.1", "localhost", "::1"}
        if cfg.host in ("127.0.0.1", "localhost", "::1")
        else {cfg.host, "localhost", "127.0.0.1"}
    )
    httpd = ThreadingHTTPServer((cfg.host, cfg.port), make_handler(ws, allowed))
    stop = threading.Event()
    if cfg.refresh_hours > 0:
        threading.Thread(target=_schedule, args=(ws, stop), daemon=True).start()
    print(f"coveragekit {__version__} serving {cfg.title} on http://{cfg.host}:{httpd.server_port}")
    if ready is not None:
        ready.port = httpd.server_port  # type: ignore[attr-defined]
        ready.httpd = httpd  # type: ignore[attr-defined]
        ready.set()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        httpd.server_close()

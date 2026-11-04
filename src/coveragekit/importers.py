"""Importers: turn a SIEM's native rule export into the coveragekit rule inventory.

Every importer returns :class:`ImportedRule` objects. Each one carries the ATT&CK/ATLAS ids the SIEM already
stores on the rule, whether the rule is enabled, and the data sources the rule reads (indexes, sourcetypes,
data models, tables, log sources or groups). ``data_available`` is then decided by comparing those
requirements with a list of sources that received events recently (``--data-sources``).

Supported exports:

* ``splunk``   Splunk ES correlation searches: REST JSON (``saved/searches``) or a CSV from ``| rest``.
* ``elastic``  Elastic Security detection rules: ``_find`` JSON or the ``_export`` NDJSON file.
* ``wazuh``    Wazuh rules: ``GET /rules`` API JSON, or rule XML files / a directory of them.
* ``sigma``    Sigma rules: a YAML file or a directory of them.
* ``sentinel`` Microsoft Sentinel analytics rules: ARM template export or REST ``alertRules`` JSON.
"""

from __future__ import annotations

import csv
import io
import json
import re
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import yaml

from .rules import COLUMNS, TECHNIQUE_RE, TRUE_VALUES


class ExportError(ValueError):
    """Raised when an export cannot be read."""


@dataclass
class ImportedRule:
    rule_id: str
    name: str
    techniques: list[str]
    enabled: bool
    requires: list[tuple[str, str]] = field(default_factory=list)
    match: str = "all"  # "all": every requirement needs data; "any": one is enough
    source: str = ""
    data_available: bool = True
    checked: bool = False


# --------------------------------------------------------------------------- helpers


def _techniques(values: Iterable[Any]) -> list[str]:
    out: list[str] = []
    for value in values:
        tid = str(value or "").strip().upper()
        if TECHNIQUE_RE.match(tid) and tid not in out:
            out.append(tid)
    return out


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in TRUE_VALUES


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise ExportError(f"cannot read {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise ExportError(f"{path} is not valid UTF-8 text") from exc


def _load_json(path: Path) -> Any:
    text = _read_text(path)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # NDJSON (Elastic _export): one object per line.
        rows = []
        for n, line in enumerate(text.splitlines(), 1):
            if line.strip():
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise ExportError(f"{path}: line {n} is not valid JSON") from exc
        return rows


def _files(path: Path, suffixes: tuple[str, ...]) -> list[Path]:
    if path.is_dir():
        found = sorted(p for p in path.rglob("*") if p.suffix.lower() in suffixes and p.is_file())
        if not found:
            raise ExportError(f"no {'/'.join(suffixes)} files under {path}")
        return found
    if path.is_file():
        return [path]
    raise ExportError(f"export not found: {path}")


# --------------------------------------------------------------------------- Splunk ES

_SPL_DM = re.compile(r"datamodel\s*[=:]\s*\"?([A-Za-z_][\w]*)", re.I)
_SPL_DM_CMD = re.compile(r"\|\s*datamodel\s+\"?([A-Za-z_][\w]*)", re.I)
_SPL_INDEX = re.compile(r"(?<![\w.])index\s*=\s*(?:\"([^\"]+)\"|([\w\-*]+))", re.I)
_SPL_ST = re.compile(r"(?<![\w.])sourcetype\s*=\s*(?:\"([^\"]+)\"|([\w\-*:/.]+))", re.I)


def spl_requirements(search: str) -> list[tuple[str, str]]:
    reqs: list[tuple[str, str]] = []
    patterns = (("datamodel", _SPL_DM), ("datamodel", _SPL_DM_CMD), ("index", _SPL_INDEX), ("sourcetype", _SPL_ST))
    for kind, pattern in patterns:
        for found in pattern.findall(search or ""):
            value = found if isinstance(found, str) else next(v for v in found if v)
            item = (kind, value)
            if item not in reqs:
                reqs.append(item)
    return reqs


def _splunk_rows(path: Path) -> list[dict[str, Any]]:
    if path.suffix.lower() == ".csv":
        return list(csv.DictReader(io.StringIO(_read_text(path))))
    data = _load_json(path)
    if isinstance(data, dict) and isinstance(data.get("entry"), list):  # REST output_mode=json
        return [{"title": e.get("name", ""), **(e.get("content") or {})} for e in data["entry"]]
    if isinstance(data, dict) and isinstance(data.get("results"), list):  # search export JSON
        return data["results"]
    if isinstance(data, list):
        return [r.get("result", r) for r in data if isinstance(r, dict)]
    raise ExportError("unrecognised Splunk export (expected REST JSON, search results JSON or CSV)")


def import_splunk(path: Path) -> list[ImportedRule]:
    rows = _splunk_rows(path)
    has_flag = any(row.get("action.correlationsearch.enabled") not in (None, "") for row in rows)
    rules = []
    for row in rows:
        if has_flag and not _truthy(row.get("action.correlationsearch.enabled") or False):
            continue  # a plain saved search or report, not a correlation search
        raw = row.get("action.correlationsearch.annotations") or "{}"
        try:
            annotations = json.loads(raw) if isinstance(raw, str) else raw
        except json.JSONDecodeError:
            annotations = {}
        ids: list[Any] = []
        if isinstance(annotations, dict):
            for key in ("mitre_attack", "mitre_atlas"):
                value = annotations.get(key) or []
                ids += [value] if isinstance(value, str) else list(value)
        search = row.get("search") or row.get("qualifiedSearch") or ""
        rules.append(
            ImportedRule(
                rule_id=str(row.get("title") or row.get("name") or "").strip(),
                name=str(row.get("title") or "").strip(),
                techniques=_techniques(ids),
                enabled=not _truthy(row.get("disabled", False)),
                requires=spl_requirements(search),
                source="Splunk ES",
            )
        )
    return rules


# --------------------------------------------------------------------------- Elastic Security

_ESQL_FROM = re.compile(r"^\s*from\s+([^\s|]+)", re.I)


def import_elastic(path: Path) -> list[ImportedRule]:
    data = _load_json(path)
    items = data.get("data") if isinstance(data, dict) else data
    if not isinstance(items, list):
        raise ExportError("unrecognised Elastic export (expected _find JSON or _export NDJSON)")
    rules = []
    for item in items:
        if not isinstance(item, dict) or "exported_count" in item or "name" not in item:
            continue  # NDJSON export summary line, exceptions lists, etc.
        ids: list[str] = []
        for threat in item.get("threat") or []:
            if not str(threat.get("framework", "")).upper().startswith("MITRE"):
                continue
            for tech in threat.get("technique") or []:
                ids.append(tech.get("id", ""))
                ids.extend(sub.get("id", "") for sub in tech.get("subtechnique") or [])
        patterns = list(item.get("index") or [])
        if not patterns and item.get("type") == "esql":
            m = _ESQL_FROM.match(item.get("query") or "")
            if m:
                patterns = [p.strip() for p in m.group(1).split(",") if p.strip()]
        rules.append(
            ImportedRule(
                rule_id=str(item.get("rule_id") or item.get("id") or "").strip(),
                name=str(item.get("name") or "").strip(),
                techniques=_techniques(ids),
                enabled=bool(item.get("enabled", False)),
                requires=[("index", p) for p in patterns],
                match="any",
                source="Elastic Security",
            )
        )
    return rules


# --------------------------------------------------------------------------- Wazuh


def _wazuh_mitre(value: Any) -> list[str]:
    if isinstance(value, dict):
        value = value.get("id") or value.get("technique") or []
    if isinstance(value, str):
        value = [value]
    return _techniques(value or [])


def _wazuh_xml(path: Path) -> list[ImportedRule]:
    text = _read_text(path)
    text = re.sub(r"<\?xml[^>]*\?>", "", text)
    try:
        root = ET.fromstring(f"<root>{text}</root>")
    except ET.ParseError as exc:
        raise ExportError(f"{path}: invalid rule XML ({exc})") from exc
    rules = []
    for group in root.iter("group"):
        parent = [g.strip() for g in (group.get("name") or "").split(",") if g.strip()]
        for rule in group.findall("rule"):
            groups = list(parent)
            for g in rule.findall("group"):
                groups += [x.strip() for x in (g.text or "").split(",") if x.strip()]
            ids = [m.text for m in rule.findall("./mitre/id")]
            level = int(rule.get("level") or 0)
            rules.append(
                ImportedRule(
                    rule_id=str(rule.get("id") or "").strip(),
                    name=(rule.findtext("description") or "").strip(),
                    techniques=_techniques(ids),
                    enabled=level > 0,  # level 0 rules never raise an alert
                    requires=[("group", g) for g in dict.fromkeys(groups)],
                    match="any",
                    source="Wazuh",
                )
            )
    return rules


def import_wazuh(path: Path) -> list[ImportedRule]:
    if path.is_dir() or path.suffix.lower() == ".xml":
        return [r for f in _files(path, (".xml",)) for r in _wazuh_xml(f)]
    data = _load_json(path)
    if isinstance(data, dict):
        data = (data.get("data") or {}).get("affected_items", data.get("affected_items"))
    if not isinstance(data, list):
        raise ExportError("unrecognised Wazuh export (expected GET /rules JSON or rule XML)")
    rules = []
    for item in data:
        level = int(item.get("level") or 0)
        rules.append(
            ImportedRule(
                rule_id=str(item.get("id", "")).strip(),
                name=str(item.get("description") or "").strip(),
                techniques=_wazuh_mitre(item.get("mitre")),
                enabled=str(item.get("status", "enabled")).lower() == "enabled" and level > 0,
                requires=[("group", g) for g in item.get("groups") or []],
                match="any",
                source="Wazuh",
            )
        )
    return rules


# --------------------------------------------------------------------------- Sigma

_SIGMA_TAG = re.compile(r"^(?:attack|atlas)\.((?:aml\.)?t\d{4}(?:\.\d{3})?)$", re.I)


def import_sigma(path: Path) -> list[ImportedRule]:
    rules = []
    for f in _files(path, (".yml", ".yaml")):
        try:
            docs = [d for d in yaml.safe_load_all(_read_text(f)) if isinstance(d, dict)]
        except yaml.YAMLError as exc:
            raise ExportError(f"{f}: invalid YAML ({exc})") from exc
        for doc in docs:
            if "detection" not in doc or "title" not in doc:
                continue
            tags = [m.group(1) for t in doc.get("tags") or [] if (m := _SIGMA_TAG.match(str(t)))]
            ls = doc.get("logsource") or {}
            product = ls.get("product") or "*"
            kind = ls.get("category") or ls.get("service") or "*"
            status = str(doc.get("status") or "").lower()
            rules.append(
                ImportedRule(
                    rule_id=str(doc.get("id") or f.stem).strip(),
                    name=str(doc.get("title")).strip(),
                    techniques=_techniques(tags),
                    enabled=status not in {"deprecated", "unsupported"},
                    requires=[("logsource", f"{product}/{kind}".lower())],
                    source="Sigma",
                )
            )
    return rules


# --------------------------------------------------------------------------- Microsoft Sentinel

_KQL_LET = re.compile(r"\blet\s+([A-Za-z_]\w*)\s*=", re.I)
_KQL_TABLE = re.compile(
    r"(?:^|[;(,=]|\bunion\b(?:\s+\w+\s*=\s*\w+)*)\s*([A-Z][A-Za-z0-9_]+)\s*(?=\||\)|,|$)", re.M
)
_KQL_WORDS = {"True", "False"}


def kql_tables(query: str) -> list[str]:
    text = re.sub(r"//[^\n]*", "", query or "")
    lets = set(_KQL_LET.findall(text))
    out: list[str] = []
    for name in _KQL_TABLE.findall(text):
        if name not in lets and name not in _KQL_WORDS and name not in out:
            out.append(name)
    return out


def import_sentinel(path: Path) -> list[ImportedRule]:
    data = _load_json(path)
    if isinstance(data, dict):
        data = data.get("resources") or data.get("value") or []
    if not isinstance(data, list):
        raise ExportError("unrecognised Sentinel export (expected ARM template or alertRules JSON)")
    rules = []
    for item in data:
        props = item.get("properties") or {}
        if "query" not in props:
            continue  # Fusion, ML behaviour analytics and similar rules have no query
        name = str(item.get("name") or "")
        display = str(props.get("displayName") or "").strip()
        rule_id = display if not name or name.startswith("[") else name.rsplit("/", 1)[-1]
        rules.append(
            ImportedRule(
                rule_id=rule_id,
                name=display,
                techniques=_techniques((props.get("techniques") or []) + (props.get("subTechniques") or [])),
                enabled=bool(props.get("enabled", False)),
                requires=[("table", t) for t in kql_tables(props.get("query") or "")],
                source="Microsoft Sentinel",
            )
        )
    return rules


IMPORTERS = {
    "splunk": import_splunk,
    "elastic": import_elastic,
    "wazuh": import_wazuh,
    "sigma": import_sigma,
    "sentinel": import_sentinel,
}

# --------------------------------------------------------------------------- data availability

DATA_COLUMNS = ("index", "sourcetype", "datamodel", "table", "group", "logsource")


_DS_BACKING = re.compile(r"^\.ds-(.+)-\d{4}\.\d{2}\.\d{2}-\d{6}$")


def _normalise_source(value: str) -> str:
    """Elastic data stream backing indices (.ds-<stream>-<date>-<gen>) count as the stream itself."""
    m = _DS_BACKING.match(value)
    return m.group(1) if m else value


def load_data_sources(path: str | Path) -> list[tuple[str | None, str]]:
    """Read the sources that received events recently.

    Accepts a CSV whose header uses any of :data:`DATA_COLUMNS` (for example the output of
    ``| tstats count where index=* by index sourcetype``), or plain text with one source per line,
    optionally prefixed with its kind (``datamodel:Endpoint``, ``table:SecurityEvent``). Bare values
    match any kind. ``#`` starts a comment.
    """
    text = _read_text(Path(path))
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    if not lines:
        return []
    header = [h.strip().lower() for h in next(csv.reader([lines[0]]))]
    tokens: list[tuple[str | None, str]] = []
    if any(h in DATA_COLUMNS for h in header):
        for row in csv.DictReader(io.StringIO("\n".join(lines))):
            for key, value in row.items():
                kind = (key or "").strip().lower()
                if kind in DATA_COLUMNS and value and value.strip():
                    tokens.append((kind, value.strip()))
        return tokens
    for line in lines:
        value = _normalise_source(line.strip())
        kind, sep, rest = value.partition(":")
        if sep and kind.lower() in DATA_COLUMNS:
            tokens.append((kind.lower(), rest.strip()))
        else:
            tokens.append((None, value))
    return tokens


def _satisfied(req: tuple[str, str], active: list[tuple[str | None, str]]) -> bool:
    kind, value = req[0], req[1].lower()
    for akind, avalue in active:
        if akind not in (None, kind):
            continue
        a = avalue.lower()
        if fnmatchcase(a, value) or fnmatchcase(value, a):
            return True
    return False


def apply_data_sources(rules: list[ImportedRule], active: list[tuple[str | None, str]]) -> None:
    for rule in rules:
        if not rule.requires:
            rule.data_available, rule.checked = True, False
            continue
        hits = [_satisfied(r, active) for r in rule.requires]
        rule.data_available = all(hits) if rule.match == "all" else any(hits)
        rule.checked = True


# --------------------------------------------------------------------------- output


def to_rows(rules: list[ImportedRule], keep: dict[str, dict[str, str]] | None = None) -> list[dict[str, str]]:
    """Inventory rows. ``keep`` (rows of a previous inventory by rule_id) preserves manual columns."""
    keep = keep or {}
    rows = []
    for r in rules:
        prev = keep.get(r.rule_id, {})
        rows.append(
            {
                "rule_id": r.rule_id,
                "name": r.name,
                "techniques": ";".join(r.techniques),
                "enabled": str(r.enabled).lower(),
                "data_available": str(r.data_available).lower(),
                "tested": prev.get("tested") or "false",
                "tuned": prev.get("tuned") or "false",
                "owner": prev.get("owner") or "",
                "source": r.source,
            }
        )
    return rows


def write_csv(rows: list[dict[str, str]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(COLUMNS))
        writer.writeheader()
        writer.writerows(rows)


def run_import(
    siem: str, export: str | Path, data_sources: str | Path | None = None
) -> tuple[list[ImportedRule], list[ImportedRule], list[str]]:
    """Return (mapped rules, rules without a technique id, warnings)."""
    if siem not in IMPORTERS:
        raise ExportError(f"unknown SIEM '{siem}' (choose from {', '.join(IMPORTERS)})")
    imported = IMPORTERS[siem](Path(export))
    warnings: list[str] = []
    seen: set[str] = set()
    unique: list[ImportedRule] = []
    for rule in imported:
        if not rule.rule_id:
            warnings.append(f"skipped a rule without an id: '{rule.name}'")
            continue
        if rule.rule_id in seen:
            warnings.append(f"duplicate rule id '{rule.rule_id}': kept the first one")
            continue
        seen.add(rule.rule_id)
        unique.append(rule)
    if data_sources:
        apply_data_sources(unique, load_data_sources(data_sources))
        unchecked = [r for r in unique if not r.checked and r.techniques]
        if unchecked:
            warnings.append(
                f"{len(unchecked)} rules name no data source the importer can read; assumed to have data"
            )
    else:
        warnings.append("data availability not checked: every rule is assumed to have data (use --data-sources)")
    mapped = [r for r in unique if r.techniques]
    unmapped = [r for r in unique if not r.techniques]
    if not mapped:
        raise ExportError("no rule in the export has an ATT&CK or ATLAS technique id")
    return mapped, unmapped, warnings

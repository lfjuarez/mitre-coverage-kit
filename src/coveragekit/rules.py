"""Rule inventory loading and validation (CSV or JSON)."""

from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

TECHNIQUE_RE = re.compile(r"^(T\d{4}(\.\d{3})?|AML\.T\d{4}(\.\d{3})?)$")
TRUE_VALUES = {"true", "yes", "1", "y"}
FALSE_VALUES = {"false", "no", "0", "n"}
COLUMNS = (
    "rule_id",
    "name",
    "techniques",
    "enabled",
    "data_available",
    "tested",
    "tuned",
    "owner",
    "source",
    "data_sources",
    "missing_data",
)
REQUIRED = ("rule_id", "techniques", "enabled", "data_available")


class RuleError(ValueError):
    """Raised when the inventory cannot be used."""


@dataclass
class Rule:
    rule_id: str
    name: str
    techniques: list[str]
    enabled: bool
    data_available: bool
    tested: bool = False
    tuned: bool = False
    owner: str = ""
    source: str = ""
    invalid_techniques: list[str] = field(default_factory=list)
    data_sources: list[str] = field(default_factory=list)  # what the rule reads, as kind:value (optional)
    missing_data: list[str] = field(default_factory=list)  # the subset that was not found when the import checked

    @property
    def valid_techniques(self) -> list[str]:
        return [t for t in self.techniques if t not in self.invalid_techniques]


def parse_bool(value: Any, *, field_name: str, row: str) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in TRUE_VALUES:
        return True
    if text in FALSE_VALUES:
        return False
    raise RuleError(f"{row}: invalid boolean '{value}' in '{field_name}' (use true/false/yes/no/1/0)")


def _split_techniques(value: Any) -> list[str]:
    if isinstance(value, list):
        items = [str(v) for v in value]
    else:
        items = str(value or "").split(";")
    seen: list[str] = []
    for item in items:
        item = item.strip().upper()
        if item and item not in seen:
            seen.append(item)
    return seen


def _build(raw: dict[str, Any], index: int) -> Rule:
    rule_id = str(raw.get("rule_id") or "").strip()
    row = f"row {index}" + (f" ({rule_id})" if rule_id else "")
    if not rule_id:
        raise RuleError(f"{row}: missing rule_id")
    for column in REQUIRED:
        if raw.get(column) in (None, ""):
            raise RuleError(f"{row}: missing value for '{column}'")
    techniques = _split_techniques(raw["techniques"])
    invalid = [t for t in techniques if not TECHNIQUE_RE.match(t)]
    if not [t for t in techniques if t not in invalid]:
        raise RuleError(f"{row}: needs at least one technique id such as T1059.001 or AML.T0051")
    flags = {
        name: parse_bool(raw.get(name, False) or False, field_name=name, row=row)
        for name in ("enabled", "data_available", "tested", "tuned")
    }
    return Rule(
        rule_id=rule_id,
        name=str(raw.get("name") or "").strip(),
        techniques=techniques,
        owner=str(raw.get("owner") or "").strip(),
        source=str(raw.get("source") or "").strip(),
        invalid_techniques=invalid,
        data_sources=[d.strip() for d in str(raw.get("data_sources") or "").split(";") if d.strip()],
        missing_data=[d.strip() for d in str(raw.get("missing_data") or "").split(";") if d.strip()],
        **flags,
    )


def _read_rows(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise RuleError(f"rule inventory not found: {path}")
    suffix = path.suffix.lower()
    try:
        if suffix == ".json":
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, list) or not all(isinstance(r, dict) for r in data):
                raise RuleError("JSON inventory must be a list of rule objects")
            return data
        if suffix == ".csv":
            with open(path, newline="", encoding="utf-8-sig") as fh:
                reader = csv.DictReader(fh)
                missing = [c for c in REQUIRED if c not in (reader.fieldnames or [])]
                if missing:
                    raise RuleError(f"CSV is missing required columns: {', '.join(missing)}")
                return list(reader)
    except json.JSONDecodeError as exc:
        raise RuleError(f"invalid JSON in {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise RuleError(f"{path} is not valid UTF-8 text") from exc
    raise RuleError(f"unsupported inventory format '{path.suffix}' (use .csv or .json)")


def build_rules(rows: list[dict[str, Any]]) -> list[Rule]:
    """Validate raw rows and return rules. Raises :class:`RuleError` on the first problem."""
    rules: list[Rule] = []
    seen: set[str] = set()
    for index, raw in enumerate(rows, start=1):
        rule = _build(raw, index)
        if rule.rule_id in seen:
            raise RuleError(f"row {index}: duplicate rule_id '{rule.rule_id}'")
        seen.add(rule.rule_id)
        rules.append(rule)
    if not rules:
        raise RuleError("the inventory contains no rules")
    return rules


def load_rules(path: str | Path) -> list[Rule]:
    return build_rules(_read_rows(Path(path)))


def unknown_technique_warnings(rules: list[Rule], known: set[str]) -> list[str]:
    """Warnings for well-formed technique ids that are not in the loaded frameworks.

    Sub-technique ids are checked against their parent technique.
    """
    from .frameworks import parent_id

    warnings: list[str] = []
    for rule in rules:
        for tid in rule.valid_techniques:
            if parent_id(tid) not in known:
                warnings.append(f"{rule.rule_id}: technique {tid} is not in the loaded frameworks")
    for rule in rules:
        for tid in rule.invalid_techniques:
            warnings.append(f"{rule.rule_id}: '{tid}' is not a valid technique id and was ignored")
    return warnings


def merge_inventories(paths: str | Path | list[str | Path]) -> list[Rule]:
    """Load one or several inventories (for example one per SIEM) into a single list.

    A rule id that repeats across files is qualified with its source (or file name) so both rules count.
    """
    if isinstance(paths, (str, Path)):
        paths = [paths]
    merged: list[Rule] = []
    seen: set[str] = set()
    for path in paths:
        for rule in load_rules(path):
            if not rule.source and len(paths) > 1:
                rule.source = Path(path).stem
            if rule.rule_id in seen:
                rule.rule_id = f"{rule.source or Path(path).stem}:{rule.rule_id}"
                if rule.rule_id in seen:
                    raise RuleError(f"{path}: duplicate rule_id '{rule.rule_id}'")
            seen.add(rule.rule_id)
            merged.append(rule)
    return merged

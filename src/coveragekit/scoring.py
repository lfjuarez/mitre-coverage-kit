"""Coverage scoring: per-technique level 0..3, per-tactic statistics, dead rules."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .frameworks import cell_count, parent_id, technique_ids
from .rules import Rule

LEVEL_NAMES = {0: "None", 1: "Low", 2: "Medium", 3: "High"}


def rule_quality(rule: Rule) -> int:
    """0 when the rule cannot fire, otherwise 1 (Low), 2 (tested) or 3 (tested and tuned)."""
    if not (rule.enabled and rule.data_available):
        return 0
    if rule.tested and rule.tuned:
        return 3
    if rule.tested:
        return 2
    return 1


@dataclass
class Coverage:
    framework: str
    version: str
    cells: list[dict[str, Any]] = field(default_factory=list)
    tactics: list[dict[str, Any]] = field(default_factory=list)
    totals: dict[str, Any] = field(default_factory=dict)
    dead_rules: list[dict[str, str]] = field(default_factory=list)
    sources: list[dict[str, Any]] = field(default_factory=list)
    unmapped_rules: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "framework": self.framework,
            "version": self.version,
            "totals": self.totals,
            "tactics": self.tactics,
            "cells": self.cells,
            "dead_rules": self.dead_rules,
            "sources": self.sources,
            "unmapped_rules": self.unmapped_rules,
        }


def technique_levels(rules: list[Rule]) -> tuple[dict[str, int], dict[str, list[str]]]:
    """Level and referencing rule ids per parent technique id (max over rules, roll-up)."""
    levels: dict[str, int] = {}
    refs: dict[str, list[str]] = {}
    for rule in rules:
        quality = rule_quality(rule)
        for tid in {parent_id(t) for t in rule.valid_techniques}:
            levels[tid] = max(levels.get(tid, 0), quality)
            refs.setdefault(tid, []).append(rule.rule_id)
    return levels, refs


def source_breakdown(rules: list[Rule], known: set[str]) -> list[dict[str, Any]]:
    """Per source (SIEM), techniques covered and techniques that only that source covers.

    Empty when the inventory has a single source, so single-SIEM reports stay unchanged.
    """
    groups: dict[str, list[Rule]] = {}
    for rule in rules:
        groups.setdefault(rule.source or "unspecified", []).append(rule)
    if len(groups) < 2:
        return []
    covered = {
        name: {tid for tid, lv in technique_levels(group)[0].items() if lv > 0 and tid in known}
        for name, group in groups.items()
    }
    out = []
    for name, techs in covered.items():
        others = set().union(*(t for n, t in covered.items() if n != name))
        out.append(
            {"source": name, "rules": len(groups[name]), "covered": len(techs), "only_here": len(techs - others)}
        )
    return sorted(out, key=lambda x: -x["covered"])


def score(rules: list[Rule], package: dict[str, Any]) -> Coverage:
    """Score ``rules`` against one framework map (``attack`` or ``atlas``)."""
    framework = package["framework"]
    levels, refs = technique_levels(rules)
    known = technique_ids(package)

    cells: list[dict[str, Any]] = []
    tactic_stats: list[dict[str, Any]] = []
    for tactic in package["tactics"]:
        tactic_levels: list[int] = []
        for tid, name in tactic["techniques"]:
            level = levels.get(tid, 0)
            tactic_levels.append(level)
            cells.append(
                {
                    "framework": framework,
                    "tactic": tactic["name"],
                    "tactic_id": tactic["id"],
                    "id": tid,
                    "name": name,
                    "level": level,
                    "rules": sorted(refs.get(tid, [])),
                }
            )
        total = len(tactic_levels)
        covered = sum(1 for lv in tactic_levels if lv > 0)
        tactic_stats.append(
            {
                "tactic": tactic["name"],
                "tactic_id": tactic["id"],
                "techniques": total,
                "covered": covered,
                "percent": round(100 * covered / total, 1) if total else 0.0,
                "mean_level": round(sum(tactic_levels) / total, 2) if total else 0.0,
            }
        )

    distinct_levels = {tid: levels.get(tid, 0) for tid in known}
    distinct_covered = sum(1 for lv in distinct_levels.values() if lv > 0)
    cell_total = cell_count(package)
    cell_covered = sum(1 for c in cells if c["level"] > 0)
    totals = {
        "tactics": len(package["tactics"]),
        "cells": cell_total,
        "cells_covered": cell_covered,
        "distinct_techniques": len(known),
        "distinct_covered": distinct_covered,
        "percent": round(100 * distinct_covered / len(known), 1) if known else 0.0,
        "by_level": {
            LEVEL_NAMES[n]: sum(1 for lv in distinct_levels.values() if lv == n) for n in range(4)
        },
    }

    # Rules are attributed to the framework their ids belong to.
    prefix = "AML." if framework == "atlas" else "T"
    own = [r for r in rules if any(t.startswith(prefix) for t in r.valid_techniques)]
    dead = [
        {"rule_id": r.rule_id, "name": r.name, "reason": "enabled but no data available"}
        for r in own
        if r.enabled and not r.data_available
    ]
    unmapped = [
        {
            "rule_id": r.rule_id,
            "name": r.name,
            "reason": "no technique in the matrix: " + ", ".join(r.valid_techniques),
        }
        for r in own
        if not any(parent_id(t) in known for t in r.valid_techniques)
    ]
    return Coverage(
        sources=source_breakdown(own, known),
        framework=framework,
        version=package["version"],
        cells=cells,
        tactics=tactic_stats,
        totals=totals,
        dead_rules=dead,
        unmapped_rules=unmapped,
    )

"""Statistics and recommendations derived from a scored inventory.

Everything here is a plain rule over the numbers, so a SOC can explain each recommendation to an auditor.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from .frameworks import parent_id
from .rules import Rule

PRE_COMPROMISE = ("Reconnaissance", "Resource Development")
WEAK_PERCENT = 20.0
ATOMIC = "https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/"
MAX_ITEMS = 8


def _item(text: str, link: str | None = None) -> dict[str, str]:
    return {"text": text, "link": link} if link else {"text": text}


def analyze(
    rules: list[Rule],
    cells: list[dict[str, Any]],
    tactics: list[dict[str, Any]],
    dead_rules: list[dict[str, str]],
    unmapped_rules: list[dict[str, str]],
    framework: str,
    version: str,
) -> dict[str, Any]:
    """Statistics and recommendations for one framework. ``rules`` are the rules attributed to it."""
    level: dict[str, int] = {}
    rules_of: dict[str, set[str]] = {}
    name_of: dict[str, str] = {}
    for c in cells:
        level[c["id"]] = max(level.get(c["id"], 0), c["level"])
        rules_of.setdefault(c["id"], set()).update(c["rules"])
        name_of[c["id"]] = c["name"]
    by_id = {r.rule_id: r for r in rules}
    label = "ATT&CK Enterprise" if framework == "attack" else "ATLAS"

    def techniques(rule: Rule) -> list[str]:
        return sorted({parent_id(t) for t in rule.valid_techniques if parent_id(t) in level})

    dead = [by_id[d["rule_id"]] for d in dead_rules if d["rule_id"] in by_id]
    recoverable: dict[str, set[str]] = {}
    for r in dead:
        for tid in techniques(r):
            if level[tid] == 0:
                recoverable.setdefault(tid, set()).add(r.rule_id)
    recoverable_list = [{"id": t, "name": name_of[t], "rules": sorted(rs)} for t, rs in sorted(recoverable.items())]
    # Sources the import found missing; for rules that were never checked, everything they read.
    needs = {r.rule_id: (r.missing_data or r.data_sources) for r in dead}
    dead_by_source = Counter(src for srcs in needs.values() for src in srcs)
    dead_by_source_list = [
        {"source": src, "rules": sorted(rid for rid, srcs in needs.items() if src in srcs)}
        for src, _ in dead_by_source.most_common()
    ]

    fragile = sorted(
        (
            {"id": t, "name": name_of[t], "level": lv, "rule": next(iter(rules_of[t]))}
            for t, lv in level.items()
            if lv > 0 and len(rules_of[t]) == 1
        ),
        key=lambda x: (-x["level"], x["id"]),
    )
    live = [r for r in rules if r.enabled and r.data_available]
    untested = [r for r in live if not r.tested]
    untuned = [r for r in live if r.tested and not r.tuned]
    low = sum(1 for lv in level.values() if lv == 1)
    medium = sum(1 for lv in level.values() if lv == 2)

    weak = []
    for t in sorted(tactics, key=lambda x: x["percent"]):
        if t["tactic"] in PRE_COMPROMISE or t["percent"] >= WEAK_PERCENT or len(weak) == 3:
            continue
        uncovered = [
            {"id": c["id"], "name": c["name"]} for c in cells if c["tactic"] == t["tactic"] and c["level"] == 0
        ]
        weak.append({**t, "uncovered": uncovered})
    pre = [t["tactic"] for t in tactics if t["tactic"] in PRE_COMPROMISE]

    recs: list[dict[str, Any]] = []
    if dead:
        n = len(recoverable_list)
        impact = (
            f"Recovers {n} technique{'s' if n != 1 else ''} without writing a rule."
            if n
            else "No technique is lost yet, but these rules will never fire."
        )
        items = [
            _item(f"{src['source']}: needed by {len(src['rules'])} dead rule{'s' if len(src['rules']) != 1 else ''}")
            for src in dead_by_source_list[:4]
        ]
        items += [
            _item(f"{r.rule_id} {r.name} · {';'.join(r.valid_techniques)}" + (f" · {r.source}" if r.source else ""))
            for r in dead[:MAX_ITEMS]
        ]
        recs.append(
            {
                "key": "restore-data",
                "title": "Restore the data behind the dead rules",
                "impact": impact,
                "body": f"{len(dead)} enabled rule{'s' if len(dead) != 1 else ''} read a source that is not arriving. "
                "They count as coverage in the SIEM and never fire. "
                "Fixing ingestion is the cheapest gain in this inventory.",
                "items": items,
            }
        )
    if untested:
        picks = [r for r in untested if any(level[t] == 1 for t in techniques(r))][:MAX_ITEMS]
        items = []
        for r in picks:
            ids = techniques(r)
            link = ATOMIC + ids[0] if framework == "attack" and ids else None
            items.append(_item(f"{r.rule_id} {r.name} · {', '.join(ids)}", link))
        recs.append(
            {
                "key": "test-rules",
                "title": "Test the rules nobody has run",
                "impact": f"{low} technique{'s' if low != 1 else ''} move from Low to Medium.",
                "body": f"{len(untested)} enabled rule{'s have' if len(untested) != 1 else ' has'} data but "
                "were never exercised. Run the Atomic Red Team test for each technique "
                "and record the result in the tested column.",
                "items": items,
            }
        )
    if weak:
        items = []
        for t in weak:
            names = ", ".join(f"{u['id']} {u['name']}" for u in t["uncovered"][:3])
            more = len(t["uncovered"]) - 3
            items.append(
                _item(
                    f"{t['tactic']} {t['covered']}/{t['techniques']} · uncovered: {names}"
                    + (f" and {more} more" if more > 0 else "")
                )
            )
        recs.append(
            {
                "key": "close-gaps",
                "title": "Close the gaps where the attacker operates",
                "impact": f"{', '.join(t['tactic'] for t in weak)} below {WEAK_PERCENT:.0f}%.",
                "body": "These tactics sit after initial access, where a missed technique means a longer dwell time. "
                "Start with techniques your current data sources can already see.",
                "items": items,
            }
        )
    if fragile:
        level_names = {1: "Low", 2: "Medium", 3: "High"}
        recs.append(
            {
                "key": "add-redundancy",
                "title": "Add a second rule where one carries the technique",
                "impact": f"{len(fragile)} technique{'s depend' if len(fragile) != 1 else ' depends'} "
                "on a single rule.",
                "body": "If that rule breaks, is tuned too far or its source changes, "
                "the technique goes dark with no warning. "
                "Prioritise the ones at High, which are the ones the SOC relies on.",
                "items": [
                    _item(f"{f['id']} {f['name']} · {level_names[f['level']]} · only {f['rule']}")
                    for f in fragile[:MAX_ITEMS]
                ],
            }
        )
    if untuned:
        recs.append(
            {
                "key": "tune-rules",
                "title": "Tune the tested rules",
                "impact": f"{len(untuned)} rule{'s are' if len(untuned) != 1 else ' is'} tested but not tuned; "
                f"{medium} technique{'s' if medium != 1 else ''} could reach High.",
                "body": "Tuning means reviewing false positives after the test "
                "and adjusting thresholds and allow-lists. "
                "Record it in the tuned column.",
                "items": [],
            }
        )
    if unmapped_rules:
        recs.append(
            {
                "key": "remap-retired",
                "title": "Remap rules that point at retired techniques",
                "impact": f"{len(unmapped_rules)} rule{'s' if len(unmapped_rules) != 1 else ''} "
                f"reference ids that are not in {label} v{version}.",
                "body": "MITRE retires and splits techniques between releases. "
                "A rule tagged with an old id silently stops counting "
                "as coverage. Map it to the current technique and update the SIEM annotation.",
                "items": [_item(f"{u['rule_id']} {u['name']} · {u['reason']}") for u in unmapped_rules[:MAX_ITEMS]],
            }
        )
    if pre:
        recs.append(
            {
                "key": "pre-compromise",
                "title": "Leave pre-compromise tactics for last",
                "impact": f"{' and '.join(pre)} are expected to be low.",
                "body": "They happen outside your network, before the first alert. A SIEM rarely sees them; "
                "threat intelligence covers them better than detection rules. "
                "They are marked in the chart so they do not distort the average.",
                "items": [],
            }
        )

    return {
        "fragile": fragile,
        "recoverable": recoverable_list,
        "dead_by_source": dead_by_source_list,
        "untested_rules": len(untested),
        "low_techniques": low,
        "untuned_rules": len(untuned),
        "medium_techniques": medium,
        "weak_tactics": weak,
        "pre_compromise": pre,
        "recommendations": recs,
    }

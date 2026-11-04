"""Compare two coverage.json files: what improved, what regressed, which rules died or came back."""

from __future__ import annotations

from typing import Any

from .scoring import LEVEL_NAMES


def _levels(fw: dict[str, Any]) -> tuple[dict[str, int], dict[str, str]]:
    level: dict[str, int] = {}
    name: dict[str, str] = {}
    for c in fw["cells"]:
        level[c["id"]] = max(level.get(c["id"], 0), c["level"])
        name[c["id"]] = c["name"]
    return level, name


def diff(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Per framework present in both files: technique level changes, tactic deltas and dead rule changes."""
    out: dict[str, Any] = {"generator": after.get("generator", ""), "frameworks": {}}
    for fw in (k for k in after if k != "generator" and k in before and isinstance(after[k], dict)):
        b, a = before[fw], after[fw]
        lb, nb = _levels(b)
        la, na = _levels(a)
        names = {**nb, **na}
        changes = []
        for tid in sorted(set(lb) | set(la)):
            x, y = lb.get(tid, 0), la.get(tid, 0)
            if x != y:
                changes.append({"id": tid, "name": names[tid], "before": x, "after": y})
        dead_b = {d["rule_id"]: d for d in b.get("dead_rules", [])}
        dead_a = {d["rule_id"]: d for d in a.get("dead_rules", [])}
        tb = {t["tactic"]: t for t in b["tactics"]}
        tactics = []
        for t in a["tactics"]:
            prev = tb.get(t["tactic"], {}).get("percent", 0.0)
            if prev != t["percent"]:
                tactics.append(
                    {
                        "tactic": t["tactic"],
                        "before": prev,
                        "after": t["percent"],
                        "delta": round(t["percent"] - prev, 1),
                    }
                )
        out["frameworks"][fw] = {
            "version_before": b.get("version"),
            "version_after": a.get("version"),
            "covered_before": b["totals"]["distinct_covered"],
            "covered_after": a["totals"]["distinct_covered"],
            "percent_before": b["totals"]["percent"],
            "percent_after": a["totals"]["percent"],
            "improved": [c for c in changes if c["after"] > c["before"]],
            "regressed": [c for c in changes if c["after"] < c["before"]],
            "tactics": tactics,
            "new_dead_rules": [dead_a[r] for r in sorted(set(dead_a) - set(dead_b))],
            "resolved_dead_rules": [dead_b[r] for r in sorted(set(dead_b) - set(dead_a))],
        }
    return out


def format_diff(d: dict[str, Any]) -> str:
    lines: list[str] = []
    for fw, x in d["frameworks"].items():
        label = "ATT&CK Enterprise" if fw == "attack" else "ATLAS" if fw == "atlas" else fw
        arrow = f"{x['covered_before']} -> {x['covered_after']} techniques "
        arrow += f"({x['percent_before']}% -> {x['percent_after']}%)"
        versions = (
            "" if x["version_before"] == x["version_after"] else f"  [v{x['version_before']} -> v{x['version_after']}]"
        )
        lines.append(f"{label}: {arrow}{versions}")
        for key, title, sign in (("improved", "improved", "+"), ("regressed", "regressed", "-")):
            if x[key]:
                lines.append(f"  {title} ({len(x[key])}):")
                for c in x[key]:
                    lines.append(
                        f"    {sign} {c['id']} {c['name']}: {LEVEL_NAMES[c['before']]} -> {LEVEL_NAMES[c['after']]}"
                    )
        if x["tactics"]:
            lines.append("  tactics:")
            for t in x["tactics"]:
                lines.append(f"    {t['tactic']}: {t['before']}% -> {t['after']}% ({t['delta']:+.1f})")
        if x["new_dead_rules"]:
            lines.append(
                f"  new dead rules ({len(x['new_dead_rules'])}): "
                + ", ".join(r["rule_id"] for r in x["new_dead_rules"])
            )
        if x["resolved_dead_rules"]:
            lines.append(
                f"  dead rules resolved ({len(x['resolved_dead_rules'])}): "
                + ", ".join(r["rule_id"] for r in x["resolved_dead_rules"])
            )
        if not (x["improved"] or x["regressed"] or x["tactics"] or x["new_dead_rules"] or x["resolved_dead_rules"]):
            lines.append("  no change")
    return "\n".join(lines) if lines else "the two files share no framework"

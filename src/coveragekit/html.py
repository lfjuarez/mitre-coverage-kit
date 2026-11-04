"""Self-contained HTML report: key figures, coverage by tactic, recommendations and tables."""

# ruff: noqa: E501  (HTML and CSS templates read better on one line each)

from __future__ import annotations

import datetime as dt
from html import escape as E
from typing import Any

from . import __version__
from .analysis import PRE_COMPROMISE
from .rules import Rule
from .scoring import LEVEL_NAMES, Coverage

LEVEL_FILL = {0: "#f0efec", 1: "#9ec5f4", 2: "#3987e5", 3: "#184f95"}
LABEL = {"attack": "MITRE ATT&CK Enterprise", "atlas": "MITRE ATLAS"}
SHORT = {"attack": "ATT&CK", "atlas": "ATLAS"}
TONE = {"restore-data": "amber", "remap-retired": "amber", "tune-rules": "green", "pre-compromise": "grey"}

CSS = """
:root{--bg:#fcfcfb;--ink:#0b0b0b;--ink2:#52514e;--muted:#898781;--line:#e1e0d9;--bar:#2a78d6;--card:#fff;--amber:#b8690f;--green:#2f7d4f}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 "Avenir Next","Segoe UI","Helvetica Neue",Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased}
.page{max-width:1100px;margin:0 auto;padding:48px 24px 64px}
header{display:flex;justify-content:space-between;align-items:flex-end;gap:24px;border-bottom:1px solid var(--line);padding-bottom:20px;margin-bottom:28px}
h1{font-size:30px;margin:0 0 4px;letter-spacing:-.01em}.sub{color:var(--ink2);margin:0}.meta{color:var(--muted);font-size:13px;text-align:right;line-height:1.6;white-space:nowrap}
h2{font-size:19px;margin:40px 0 14px;letter-spacing:-.01em}h2 small{font-weight:400;color:var(--muted);font-size:14px;margin-left:10px}
.kpis{display:grid;grid-template-columns:repeat(5,1fr);gap:14px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px}
.kpi .v{font-size:34px;font-weight:600;letter-spacing:-.02em;line-height:1.1}.kpi .l{color:var(--ink2);margin-top:4px;font-weight:500}.kpi .s{color:var(--muted);font-size:13px;margin-top:2px}
.levels{display:flex;height:14px;border-radius:4px;overflow:hidden;margin:18px 0 8px}.levels i{display:block;height:100%}
.legend{display:flex;gap:22px;color:var(--ink2);font-size:13px}.legend i,.lv{display:inline-block;width:12px;height:12px;border-radius:3px;margin-right:6px;vertical-align:-1px;border:1px solid rgba(0,0,0,.06)}
.trow{display:grid;grid-template-columns:270px 1fr 110px;align-items:center;min-height:28px}.tl{color:var(--ink2);font-size:14px;white-space:nowrap}
.cells{display:flex;flex-wrap:wrap;gap:3px}.cells i{display:block;width:14px;height:14px;border-radius:3px;border:1px solid rgba(0,0,0,.05)}
.tn{text-align:right;color:var(--ink2);font-size:13px}.tn b{color:var(--ink);font-size:14px}
.tag{font-size:11px;color:var(--muted);border:1px solid var(--line);border-radius:10px;padding:1px 7px;margin-left:6px;vertical-align:1px}
.recs{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.rec{display:flex;gap:14px;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px 20px 14px}
.rec .n{flex:none;width:28px;height:28px;border-radius:14px;background:var(--bar);color:#fff;font-weight:600;display:flex;align-items:center;justify-content:center;font-size:14px}
.rec.amber .n{background:var(--amber)}.rec.green .n{background:var(--green)}.rec.grey .n{background:var(--muted)}
.rec h3{margin:2px 0 4px;font-size:16px}.impact{margin:0 0 6px;font-weight:600;color:var(--ink)}.rec p{margin:0 0 8px;color:var(--ink2);font-size:14px}
.rec ul{margin:4px 0 0;padding-left:18px;color:var(--ink2);font-size:13px}.rec li{margin:2px 0}
code{font:12.5px "SF Mono",Menlo,Consolas,monospace;background:#f1f0ed;padding:1px 5px;border-radius:4px;color:var(--ink);white-space:nowrap}.muted{color:var(--muted)}a{color:var(--bar);text-decoration:none}
table{width:100%;border-collapse:collapse;font-size:14px}th{text-align:left;color:var(--muted);font-weight:500;font-size:12.5px;letter-spacing:.04em;text-transform:uppercase;border-bottom:1px solid var(--line);padding:8px 10px}
td{padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}td:first-child,th:first-child{padding-left:0}.num td:not(:first-child),.num th:not(:first-child){text-align:right}
.two{display:grid;grid-template-columns:2fr 3fr;gap:40px}tr.off td{color:var(--muted)}
input.q{width:100%;font:inherit;padding:8px 12px;border:1px solid var(--line);border-radius:8px;margin:0 0 10px;background:var(--card)}
footer{margin-top:48px;border-top:1px solid var(--line);padding-top:16px;color:var(--muted);font-size:13px}
@media (max-width:900px){.kpis{grid-template-columns:repeat(2,1fr)}.recs,.two{grid-template-columns:1fr}.trow{grid-template-columns:160px 1fr 90px}.tl{white-space:normal}}
@media print{input.q{display:none}.rec,.kpi{break-inside:avoid}}
"""

JS = """
document.getElementById('q').addEventListener('input',function(e){var q=e.target.value.toLowerCase();
document.querySelectorAll('#techs tbody tr').forEach(function(r){r.hidden=!!q&&r.textContent.toLowerCase().indexOf(q)<0})});
"""


def _kpi(value: Any, label: str, sub: str = "", tone: str = "") -> str:
    style = f' style="color:var(--{tone})"' if tone else ""
    return f'<div class="kpi"><div class="v"{style}>{E(str(value))}</div><div class="l">{E(label)}</div><div class="s">{E(sub)}</div></div>'


def _tactic_rows(cov: Coverage) -> str:
    out = []
    for t in cov.tactics:
        cells = sorted((c for c in cov.cells if c["tactic_id"] == t["tactic_id"]), key=lambda c: -c["level"])
        squares = []
        for c in cells:
            title = f"{c['id']} {c['name']} · {LEVEL_NAMES[c['level']]}" + (f" · {', '.join(c['rules'])}" if c["rules"] else "")
            squares.append(f'<i style="background:{LEVEL_FILL[c["level"]]}" title="{E(title)}"></i>')
        tag = ' <span class="tag">pre-compromise</span>' if t["tactic"] in PRE_COMPROMISE else ""
        out.append(
            f'<div class="trow"><div class="tl">{E(t["tactic"])}{tag}</div><div class="cells">{"".join(squares)}</div>'
            f'<div class="tn"><b>{t["percent"]:.0f}%</b> · {t["covered"]}/{t["techniques"]}</div></div>'
        )
    return "".join(out)


def _recs(cov: Coverage) -> str:
    out = []
    for n, rec in enumerate(cov.analysis.get("recommendations", []), 1):
        items = ""
        if rec["items"]:
            lis = []
            for item in rec["items"]:
                text = E(item["text"])
                if item.get("link"):
                    text += f' <a href="{E(item["link"])}">Atomic test</a>'
                lis.append(f"<li>{text}</li>")
            items = f"<ul>{''.join(lis)}</ul>"
        out.append(
            f'<div class="rec {TONE.get(rec["key"], "")}"><div class="n">{n}</div><div class="rb"><h3>{E(rec["title"])}</h3>'
            f'<p class="impact">{E(rec["impact"])}</p><p>{E(rec["body"])}</p>{items}</div></div>'
        )
    return "".join(out)


def _table(headers: list[str], rows: list[str], cls: str = "", attrs: str = "") -> str:
    head = "".join(f"<th>{E(h)}</th>" for h in headers)
    return f'<table class="{cls}"{attrs}><thead><tr>{head}</tr></thead><tbody>{"".join(rows)}</tbody></table>'


def render_html(results: dict[str, Coverage], rules: list[Rule], title: str = "Detection coverage report") -> str:
    """Render the report for the scored frameworks (``attack`` first when present)."""
    order = [k for k in ("attack", "atlas") if k in results] + [k for k in results if k not in ("attack", "atlas")]
    primary = results[order[0]]
    tot = primary.totals
    sources = sorted({r.source for r in rules if r.source})
    by_id = {r.rule_id: r for r in rules}

    dead: dict[str, dict[str, str]] = {}
    for k in order:
        for d in results[k].dead_rules:
            dead.setdefault(d["rule_id"], d)
    recover_by = {k: len(results[k].analysis.get("recoverable", [])) for k in order}
    recover = sum(recover_by.values())
    recover_sub = f"recover {recover} technique{'s' if recover != 1 else ''}"
    if sum(1 for v in recover_by.values() if v) > 1:
        recover_sub += " (" + ", ".join(f"{v} {SHORT.get(k, k)}" for k, v in recover_by.items() if v) + ")"
    fragile = len(primary.analysis.get("fragile", []))

    frameworks = " and ".join(f"{LABEL.get(k, k)} v{results[k].version}" for k in order)
    kpis = [
        _kpi(f"{tot['percent']:.0f}%", f"{SHORT.get(order[0], order[0])} techniques covered",
             f"{tot['distinct_covered']} of {tot['distinct_techniques']}"),
        _kpi(tot["by_level"]["High"], "techniques at High", f"{tot['by_level']['Medium']} Medium · {tot['by_level']['Low']} Low"),
        _kpi(len(dead), "dead rules", recover_sub, "amber" if dead else ""),
        _kpi(fragile, "fragile techniques", "depend on a single rule", "amber" if fragile else ""),
    ]
    if len(order) > 1:
        second = results[order[1]]
        kpis.append(_kpi(f"{second.totals['percent']:.0f}%", f"{SHORT.get(order[1], order[1])} techniques covered",
                         f"{second.totals['distinct_covered']} of {second.totals['distinct_techniques']} · {len(second.dead_rules)} dead rules"))
    else:
        kpis.append(_kpi(len(rules), "rules", f"{len(sources)} source{'s' if len(sources) != 1 else ''}"))

    level_bar = "".join(
        f'<i style="background:{LEVEL_FILL[n]};width:{100 * tot["by_level"][LEVEL_NAMES[n]] / max(tot["distinct_techniques"], 1):.2f}%"></i>'
        for n in (3, 2, 1, 0))
    legend = "".join(f'<span><i style="background:{LEVEL_FILL[n]}"></i>{LEVEL_NAMES[n]} ({tot["by_level"][LEVEL_NAMES[n]]})</span>' for n in range(4))

    body: list[str] = []
    for k in order:  # each framework: its chart, then what to do about it
        cov = results[k]
        body.append(f'<h2>Coverage by tactic <small>{E(LABEL.get(k, k))} v{E(cov.version)} · one cell per technique, sorted by level · hover for the technique and its rules</small></h2>{_tactic_rows(cov)}')
        if cov.analysis.get("recommendations") and any(c["rules"] for c in cov.cells):
            body.append(f'<h2>Recommendations <small>{E(LABEL.get(k, k))} · computed from the inventory, ordered by effort</small></h2><div class="recs">{_recs(cov)}</div>')

    side: list[str] = []
    if primary.sources:
        rows = [f"<tr><td>{E(s['source'])}</td><td>{s['rules']}</td><td>{s['covered']}</td><td>{s['only_here']}</td></tr>" for s in primary.sources]
        side.append(f'<div><h2>Coverage by source <small>techniques covered, and covered only there</small></h2>{_table(["Source", "Rules", "Techniques", "Only here"], rows, "num")}</div>')
    if dead:
        rows = []
        for rid, d in dead.items():
            r = by_id.get(rid)
            techs = ";".join(r.valid_techniques) if r else ""
            src = r.source if r else ""
            rows.append(f"<tr><td><code>{E(rid)}</code></td><td>{E(d['name'])}</td><td>{E(techs)}</td><td>{E(src)}</td><td>{E(d['reason'])}</td></tr>")
        side.append(f'<div><h2>Dead rules <small>enabled, no data</small></h2>{_table(["Rule", "Name", "Techniques", "Source", "Reason"], rows)}</div>')
    if side:
        body.append(f'<div class="two">{"".join(side)}</div>' if len(side) == 2 else side[0])

    detail: dict[tuple[str, str], dict[str, Any]] = {}
    for k in order:
        for c in results[k].cells:
            d = detail.setdefault((k, c["id"]), {"id": c["id"], "name": c["name"], "tactics": [], "level": 0, "rules": set(), "fw": k})
            d["tactics"].append(c["tactic"])
            d["level"] = max(d["level"], c["level"])
            d["rules"].update(c["rules"])
    rows = []
    for d in sorted(detail.values(), key=lambda x: (-x["level"], x["fw"] != order[0], x["id"])):
        cls = ' class="off"' if d["level"] == 0 else ""
        rows.append(
            f'<tr{cls}><td>{E(d["id"])}</td><td>{E(d["name"])}</td><td>{E(", ".join(dict.fromkeys(d["tactics"])))}</td>'
            f'<td><span class="lv" style="background:{LEVEL_FILL[d["level"]]}"></span>{LEVEL_NAMES[d["level"]]}</td><td>{E(", ".join(sorted(d["rules"])))}</td></tr>'
        )
    covered = sum(1 for d in detail.values() if d["level"] > 0)
    body.append(
        f'<h2>Technique detail <small>{covered} covered of {len(detail)} techniques · type to filter</small></h2>'
        f'<input class="q" id="q" type="search" placeholder="Filter by technique, tactic, level or rule">'
        + _table(["ID", "Technique", "Tactics", "Level", "Rules"], rows, attrs=' id="techs"')
    )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{E(title)}</title><style>{CSS}</style></head>
<body><div class="page">
<header><div><h1>{E(title)}</h1><p class="sub">{E(frameworks)} · {len(rules)} rule{'s' if len(rules) != 1 else ''} from {len(sources)} source{'s' if len(sources) != 1 else ''}</p></div>
<div class="meta">{dt.date.today().isoformat()}<br>mitre-coverage-kit {E(__version__)}</div></header>
<div class="kpis">{"".join(kpis)}</div>
<div class="levels">{level_bar}</div><div class="legend">{legend}</div>
{"".join(body)}
<footer>Levels: 0 no rule or no data · 1 enabled with data · 2 tested · 3 tested and tuned. A technique takes the best level across its rules; sub-techniques roll up to their parent. Coverage means at least one way of performing the technique is detected, not every variant. Generated by mitre-coverage-kit.</footer>
</div><script>{JS}</script></body></html>
"""

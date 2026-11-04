# ruff: noqa: E501  (OOXML templates read better on one line each)
"""Shareable exports: PDF, Excel, CSV, Markdown and JSON, all from the scored results, without dependencies.

* PDF: the HTML report printed by a local Chrome, Chromium or Edge in headless mode. Without a browser the
  caller gets :class:`ExportFailed`, and the HTML report can still be printed from any browser.
* Excel: a minimal .xlsx written with ``zipfile`` (summary, techniques, rules, recommendations).
* CSV: one table per file (techniques, rules or recommendations).
* Markdown: a short summary for a ticket, a pull request or a chat message.
"""

from __future__ import annotations

import csv
import datetime as dt
import io
import json
import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from . import __version__
from .html import render_html
from .rules import Rule
from .scoring import LEVEL_NAMES, Coverage, rule_quality

LABEL = {"attack": "ATT&CK Enterprise", "atlas": "ATLAS"}
FORMATS = ("pdf", "xlsx", "csv", "md", "json", "html")
TABLES = ("techniques", "rules", "recommendations")


class ExportFailed(Exception):
    """The export cannot be produced in this environment (for example, no browser for the PDF)."""


def _order(results: dict[str, Coverage]) -> list[str]:
    return [k for k in ("attack", "atlas") if k in results] + [k for k in results if k not in ("attack", "atlas")]


# --------------------------------------------------------------------------- tables


def technique_rows(results: dict[str, Coverage], rules: list[Rule]) -> list[dict[str, Any]]:
    source_of = {r.rule_id: r.source for r in rules}
    rows: list[dict[str, Any]] = []
    for fw in _order(results):
        merged: dict[str, dict[str, Any]] = {}
        for c in results[fw].cells:
            d = merged.setdefault(
                c["id"], {"id": c["id"], "name": c["name"], "tactics": [], "level": 0, "rules": set()}
            )
            d["tactics"].append(c["tactic"])
            d["level"] = max(d["level"], c["level"])
            d["rules"].update(c["rules"])
        for d in sorted(merged.values(), key=lambda x: (-x["level"], x["id"])):
            rule_ids = sorted(d["rules"])
            rows.append(
                {
                    "framework": LABEL.get(fw, fw),
                    "technique_id": d["id"],
                    "technique": d["name"],
                    "tactics": ", ".join(dict.fromkeys(d["tactics"])),
                    "level": d["level"],
                    "level_name": LEVEL_NAMES[d["level"]],
                    "rule_count": len(rule_ids),
                    "single_rule": "yes" if d["level"] > 0 and len(rule_ids) == 1 else "",
                    "rules": ", ".join(rule_ids),
                    "sources": ", ".join(sorted({source_of.get(r, "") for r in rule_ids} - {""})),
                }
            )
    return rows


def rule_rows(rules: list[Rule]) -> list[dict[str, Any]]:
    rows = []
    for r in rules:
        q = rule_quality(r)
        state = "disabled" if not r.enabled else "dead" if not r.data_available else LEVEL_NAMES[q].lower()
        rows.append(
            {
                "rule_id": r.rule_id,
                "name": r.name,
                "source": r.source,
                "techniques": ";".join(r.valid_techniques),
                "state": state,
                "enabled": r.enabled,
                "data_available": r.data_available,
                "tested": r.tested,
                "tuned": r.tuned,
                "owner": r.owner,
                "data_sources": ";".join(r.data_sources),
                "missing_data": ";".join(r.missing_data),
            }
        )
    return rows


def recommendation_rows(results: dict[str, Coverage]) -> list[dict[str, Any]]:
    rows = []
    for fw in _order(results):
        for n, rec in enumerate(results[fw].analysis.get("recommendations", []), 1):
            rows.append(
                {
                    "framework": LABEL.get(fw, fw),
                    "order": n,
                    "recommendation": rec["title"],
                    "impact": rec["impact"],
                    "detail": rec["body"],
                    "examples": " | ".join(i["text"] for i in rec["items"]),
                }
            )
    return rows


def summary_rows(results: dict[str, Coverage], rules: list[Rule], title: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = [
        {"metric": "Report", "value": title},
        {"metric": "Generated", "value": dt.datetime.now().astimezone().isoformat(timespec="minutes")},
        {"metric": "Rules", "value": len(rules)},
        {"metric": "Sources", "value": ", ".join(sorted({r.source for r in rules if r.source}))},
    ]
    for fw in _order(results):
        c, t = results[fw], results[fw].totals
        label = LABEL.get(fw, fw)
        rows += [
            {"metric": f"{label} version", "value": c.version},
            {
                "metric": f"{label} techniques covered",
                "value": f"{t['distinct_covered']} of {t['distinct_techniques']} ({t['percent']}%)",
            },
            {
                "metric": f"{label} at High / Medium / Low",
                "value": f"{t['by_level']['High']} / {t['by_level']['Medium']} / {t['by_level']['Low']}",
            },
            {"metric": f"{label} dead rules", "value": len(c.dead_rules)},
            {"metric": f"{label} single-rule techniques", "value": len(c.analysis.get("fragile", []))},
        ]
    return rows


def table(results: dict[str, Coverage], rules: list[Rule], name: str) -> list[dict[str, Any]]:
    if name == "techniques":
        return technique_rows(results, rules)
    if name == "rules":
        return rule_rows(rules)
    if name == "recommendations":
        return recommendation_rows(results)
    raise ExportFailed(f"unknown table '{name}' (choose from {', '.join(TABLES)})")


# --------------------------------------------------------------------------- writers


def _safe_cell(value: Any) -> Any:
    """Neutralise spreadsheet formula injection: a rule name like '=HYPERLINK(...)' must stay text."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def to_csv(rows: list[dict[str, Any]]) -> str:
    buf = io.StringIO()
    if rows:
        w = csv.DictWriter(buf, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows({k: _safe_cell(v) for k, v in r.items()} for r in rows)
    return buf.getvalue()


def _col(n: int) -> str:
    s = ""
    n += 1
    while n:
        n, rem = divmod(n - 1, 26)
        s = chr(65 + rem) + s
    return s


def _sheet_xml(rows: list[dict[str, Any]]) -> str:
    headers = list(rows[0]) if rows else []
    widths = []
    for h in headers:
        longest = max([len(str(h))] + [len(str(r.get(h, ""))) for r in rows[:500]])
        widths.append(min(max(10, longest + 2), 70))
    cols = "".join(f'<col min="{i + 1}" max="{i + 1}" width="{w}" customWidth="1"/>' for i, w in enumerate(widths))
    out = [
        '<row r="1">'
        + "".join(
            f'<c r="{_col(i)}1" t="inlineStr" s="1"><is><t>{escape(str(h))}</t></is></c>' for i, h in enumerate(headers)
        )
        + "</row>"
    ]
    for n, r in enumerate(rows, 2):
        cells = []
        for i, h in enumerate(headers):
            v = r.get(h, "")
            ref = f"{_col(i)}{n}"
            if isinstance(v, bool):
                cells.append(f'<c r="{ref}" t="b"><v>{int(v)}</v></c>')
            elif isinstance(v, (int, float)):
                cells.append(f'<c r="{ref}"><v>{v}</v></c>')
            else:  # inline strings are never evaluated as formulas
                cells.append(f'<c r="{ref}" t="inlineStr"><is><t xml:space="preserve">{escape(str(v))}</t></is></c>')
        out.append(f'<row r="{n}">{"".join(cells)}</row>')
    last = f"{_col(max(len(headers) - 1, 0))}{max(len(rows) + 1, 1)}"
    pane = '<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>'
    auto = f'<autoFilter ref="A1:{last}"/>' if headers else ""
    data = "".join(out)
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f"{pane}<cols>{cols}</cols><sheetData>{data}</sheetData>{auto}</worksheet>"
    )


def to_xlsx(sheets: dict[str, list[dict[str, Any]]]) -> bytes:
    names = list(sheets)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(
            "[Content_Types].xml",
            (
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                '<Default Extension="xml" ContentType="application/xml"/>'
                '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
                '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
                + "".join(
                    f'<Override PartName="/xl/worksheets/sheet{i + 1}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
                    for i in range(len(names))
                )
                + "</Types>"
            ),
        )
        z.writestr(
            "_rels/.rels",
            (
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
                "</Relationships>"
            ),
        )
        z.writestr(
            "xl/workbook.xml",
            (
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'
                + "".join(
                    f'<sheet name="{escape(n[:31])}" sheetId="{i + 1}" r:id="rId{i + 1}"/>' for i, n in enumerate(names)
                )
                + "</sheets></workbook>"
            ),
        )
        z.writestr(
            "xl/_rels/workbook.xml.rels",
            (
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                + "".join(
                    f'<Relationship Id="rId{i + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{i + 1}.xml"/>'
                    for i in range(len(names))
                )
                + f'<Relationship Id="rId{len(names) + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
                "</Relationships>"
            ),
        )
        z.writestr(
            "xl/styles.xml",
            (
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font></fonts>'
                '<fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill>'
                '<fill><patternFill patternType="solid"><fgColor rgb="FF13213A"/><bgColor indexed="64"/></patternFill></fill></fills>'
                '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
                '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
                '<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
                '<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/></cellXfs>'
                "</styleSheet>"
            ),
        )
        for i, n in enumerate(names):
            z.writestr(f"xl/worksheets/sheet{i + 1}.xml", _sheet_xml(sheets[n]))
    return buf.getvalue()


def workbook(results: dict[str, Coverage], rules: list[Rule], title: str) -> bytes:
    return to_xlsx(
        {
            "Summary": summary_rows(results, rules, title),
            "Techniques": technique_rows(results, rules),
            "Rules": rule_rows(rules),
            "Recommendations": recommendation_rows(results),
        }
    )


def to_markdown(results: dict[str, Coverage], rules: list[Rule], title: str) -> str:
    lines = [
        f"# {title}",
        "",
        f"_{dt.date.today().isoformat()} · mitre-coverage-kit {__version__} · {len(rules)} rules_",
        "",
    ]
    for fw in _order(results):
        c, t = results[fw], results[fw].totals
        label = LABEL.get(fw, fw)
        lines += [
            f"## {label} v{c.version}",
            "",
            f"**{t['percent']:.0f}% of techniques covered** ({t['distinct_covered']} of {t['distinct_techniques']}). "
            f"High {t['by_level']['High']} · Medium {t['by_level']['Medium']} · Low {t['by_level']['Low']} · "
            f"dead rules {len(c.dead_rules)} · single-rule techniques {len(c.analysis.get('fragile', []))}.",
            "",
            "| Tactic | Covered | % |",
            "|---|---:|---:|",
        ]
        lines += [f"| {x['tactic']} | {x['covered']}/{x['techniques']} | {x['percent']:.0f}% |" for x in c.tactics]
        recs = c.analysis.get("recommendations", [])
        if recs:
            lines += ["", "**Next actions**", ""]
            lines += [f"{n}. **{r['title']}**: {r['impact']}" for n, r in enumerate(recs, 1)]
        if c.dead_rules:
            lines += ["", "**Dead rules** (enabled, no data)", ""]
            lines += [f"- `{d['rule_id']}` {d['name']}" for d in c.dead_rules[:20]]
            if len(c.dead_rules) > 20:
                lines.append(f"- and {len(c.dead_rules) - 20} more")
        lines.append("")
    return "\n".join(lines)


def to_json(results: dict[str, Coverage]) -> str:
    payload: dict[str, Any] = {"generator": f"mitre-coverage-kit {__version__}"}
    payload.update({n: c.to_dict() for n, c in results.items()})
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


# --------------------------------------------------------------------------- PDF

_BROWSERS = (
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
)


def find_browser() -> str | None:
    env = os.environ.get("COVERAGEKIT_CHROME")
    if env and Path(env).exists():
        return env
    for name in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "msedge", "microsoft-edge"):
        found = shutil.which(name)
        if found:
            return found
    return next((p for p in _BROWSERS if Path(p).exists()), None)


def html_to_pdf(page: str, browser: str | None = None, timeout: int = 120) -> bytes:
    browser = browser or find_browser()
    if not browser:
        raise ExportFailed(
            "no Chrome, Chromium or Edge found for the PDF; set COVERAGEKIT_CHROME, "
            "or open the HTML report and print it to PDF from any browser"
        )
    with tempfile.TemporaryDirectory(prefix="coveragekit-pdf-") as tmp:
        src, out = Path(tmp) / "report.html", Path(tmp) / "report.pdf"
        src.write_text(page, encoding="utf-8")
        cmd = [
            browser,
            "--headless=new",
            "--disable-gpu",
            "--no-pdf-header-footer",
            f"--user-data-dir={tmp}/profile",
            f"--print-to-pdf={out}",
            src.as_uri(),
        ]
        try:
            subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ExportFailed(f"the browser could not print the PDF: {exc}") from exc
        if not out.is_file() or out.stat().st_size == 0:
            raise ExportFailed("the browser did not produce a PDF")
        return out.read_bytes()


def report_pdf(results: dict[str, Coverage], rules: list[Rule], title: str) -> bytes:
    return html_to_pdf(render_html(results, rules, title=title))


# --------------------------------------------------------------------------- one entry point

CONTENT_TYPES = {
    "pdf": "application/pdf",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "csv": "text/csv",
    "md": "text/markdown",
    "json": "application/json",
    "html": "text/html",
}


def export(
    results: dict[str, Coverage], rules: list[Rule], fmt: str, title: str, table_name: str = "techniques"
) -> bytes:
    if fmt == "pdf":
        return report_pdf(results, rules, title)
    if fmt == "xlsx":
        return workbook(results, rules, title)
    if fmt == "csv":
        return to_csv(table(results, rules, table_name)).encode("utf-8")
    if fmt == "md":
        return to_markdown(results, rules, title).encode("utf-8")
    if fmt == "json":
        return to_json(results).encode("utf-8")
    if fmt == "html":
        return render_html(results, rules, title=title).encode("utf-8")
    raise ExportFailed(f"unknown format '{fmt}' (choose from {', '.join(FORMATS)})")

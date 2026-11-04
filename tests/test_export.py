import csv
import io
import json
import xml.dom.minidom
import zipfile

import pytest

from coveragekit import export
from coveragekit.cli import main
from coveragekit.rules import load_rules
from coveragekit.scoring import score


@pytest.fixture(scope="module")
def results(attack, atlas):
    rules = load_rules("examples/rules.csv")
    return {"attack": score(rules, attack), "atlas": score(rules, atlas)}, rules


def test_tables_have_the_expected_shape(results):
    res, rules = results
    tech = export.technique_rows(res, rules)
    assert len(tech) == 227 + 101 and tech[0]["level_name"] == "High"
    covered = [t for t in tech if t["framework"] == "ATT&CK Enterprise" and t["level"] > 0]
    assert len(covered) == res["attack"].totals["distinct_covered"]
    assert {r["state"] for r in export.rule_rows(rules)} >= {"dead", "high", "medium", "low"}
    assert export.recommendation_rows(res)[0]["recommendation"] == "Restore the data behind the dead rules"


def test_csv_neutralises_formulas():
    out = export.to_csv([{"name": '=HYPERLINK("http://x")', "n": 3}, {"name": "+cmd", "n": 4}])
    rows = list(csv.DictReader(io.StringIO(out)))
    assert rows[0]["name"].startswith("'=") and rows[1]["name"] == "'+cmd"


def test_xlsx_is_a_valid_workbook(results):
    res, rules = results
    data = export.workbook(res, rules, "Example SOC")
    z = zipfile.ZipFile(io.BytesIO(data))
    assert z.testzip() is None
    for name in z.namelist():
        xml.dom.minidom.parseString(z.read(name))  # every part is well-formed XML
    book = z.read("xl/workbook.xml").decode()
    assert all(f'name="{s}"' in book for s in ("Summary", "Techniques", "Rules", "Recommendations"))
    sheet = z.read("xl/worksheets/sheet2.xml").decode()
    assert "T1059" in sheet and 'state="frozen"' in sheet and "<autoFilter" in sheet
    assert "<f>" not in sheet  # strings are inline, never formulas


def test_markdown_summary(results):
    res, rules = results
    md = export.to_markdown(res, rules, "Example SOC")
    t = res["attack"].totals
    assert md.startswith("# Example SOC") and f"({t['distinct_covered']} of {t['distinct_techniques']})" in md
    assert "| Execution |" in md and "**Next actions**" in md


def test_pdf_without_browser_is_a_clear_error(results, monkeypatch):
    res, rules = results
    monkeypatch.setattr(export, "find_browser", lambda: None)
    with pytest.raises(export.ExportFailed, match="print it to PDF"):
        export.export(res, rules, "pdf", "x")


@pytest.mark.skipif(export.find_browser() is None, reason="no Chrome, Chromium or Edge on this machine")
def test_pdf_with_browser(results):
    res, rules = results
    data = export.export(res, rules, "pdf", "Example SOC")
    assert data.startswith(b"%PDF") and len(data) > 10_000


def test_cli_export_picks_format_from_extension(tmp_path):
    for name in ("out.xlsx", "out.md", "out.json", "out.html"):
        assert main(["export", "--rules", "examples/rules.csv", "--out", str(tmp_path / name)]) == 0
    assert zipfile.is_zipfile(tmp_path / "out.xlsx")
    assert "attack" in json.loads((tmp_path / "out.json").read_text())
    assert main(["export", "--rules", "examples/rules.csv", "--table", "rules", "--out", str(tmp_path / "r.csv")]) == 0
    assert next(csv.DictReader(open(tmp_path / "r.csv")))["rule_id"] == "R-001"
    assert main(["export", "--rules", "examples/rules.csv", "--out", str(tmp_path / "x.docx")]) == 1

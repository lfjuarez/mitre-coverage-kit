import json
import re

from coveragekit.cli import main


def test_html_report_is_self_contained_and_matches_the_numbers(tmp_path):
    out = tmp_path / "report.html"
    assert main(["html", "--rules", "examples/rules.csv", "--out", str(out), "--title", "Lab coverage"]) == 0
    page = out.read_text()
    assert "<title>Lab coverage</title>" in page
    assert "<link " not in page and 'src="http' not in page  # no external assets
    cov = json.loads(open("examples/output/coverage.json").read())["attack"]["totals"]
    assert f">{cov['percent']:.0f}%<" in page and f"{cov['distinct_covered']} of {cov['distinct_techniques']}" in page
    assert page.count('class="rec ') >= 4 and "Dead rules" in page and "Coverage by source" in page
    assert page.count("<tr") > 300  # every ATT&CK and ATLAS technique is in the detail table
    assert re.search(r'title="T1059 Command and Scripting Interpreter · (Low|Medium|High)', page)


def test_report_writes_html_too(tmp_path):
    assert main(["report", "--rules", "examples/rules.csv", "--out-dir", str(tmp_path)]) == 0
    assert (tmp_path / "report.html").is_file()
    data = json.loads((tmp_path / "coverage.json").read_text())
    assert data["attack"]["analysis"]["recommendations"][0]["key"] == "restore-data"
    assert data["attack"]["analysis"]["fragile"]


def test_cli_catalog_flag_keeps_coverage(tmp_path):
    cat = tmp_path / "catalog.csv"
    cat.write_text("rule_id,name,techniques,enabled,data_available,source\nS1,Sigma rule,T1005,true,true,Sigma\n")
    plain, with_cat = tmp_path / "a.json", tmp_path / "b.json"
    assert main(["score", "--rules", "examples/rules.csv", "--out", str(plain)]) == 0
    assert main(["score", "--rules", "examples/rules.csv", "--catalog", str(cat), "--out", str(with_cat)]) == 0
    a, b = json.loads(plain.read_text())["attack"], json.loads(with_cat.read_text())["attack"]
    assert a["totals"] == b["totals"]
    assert [e["id"] for e in b["analysis"]["catalog"]] == ["T1005"]

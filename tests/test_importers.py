import csv

import pytest
from conftest import FIXTURES

from coveragekit import importers
from coveragekit.cli import main
from coveragekit.rules import load_rules

EXPORTS = FIXTURES / "exports"


def by_id(rules):
    return {r.rule_id: r for r in rules}


def test_splunk_rest_json():
    rules = by_id(importers.import_splunk(EXPORTS / "splunk-rest.json"))
    assert "Weekly license report" not in rules  # not a correlation search
    ps = rules["ESCU - Windows PowerShell Encoded Command"]
    assert ps.techniques == ["T1059.001"] and ps.enabled
    assert ps.requires == [("datamodel", "Endpoint")]
    sudo = rules["ESCU - Linux Sudo Brute Force"]
    assert sudo.techniques == ["T1110", "T1548.003"]
    assert ("index", "linux") in sudo.requires and ("sourcetype", "linux_secure") in sudo.requires
    assert not rules["ESCU - Disabled USB Rule"].enabled
    assert rules["ESCU - No Mapping"].techniques == []


def test_splunk_csv_keeps_colon_sourcetypes():
    (rule,) = importers.import_splunk(EXPORTS / "splunk-rest.csv")
    assert rule.techniques == ["T1558.003"] and rule.enabled
    assert ("sourcetype", "XmlWinEventLog:Security") in rule.requires


def test_elastic_ndjson_with_subtechniques_esql_and_atlas():
    rules = by_id(importers.import_elastic(EXPORTS / "elastic-export.ndjson"))
    assert len(rules) == 4  # the export summary line is ignored
    assert rules["e1"].techniques == ["T1059", "T1059.001"]
    assert rules["e1"].match == "any"
    assert rules["e2"].requires == [("index", "logs-network.dns-*")]
    assert rules["e3"].techniques == ["AML.T0051"] and not rules["e3"].enabled
    assert rules["e4"].techniques == [] and rules["e4"].requires == []


def test_wazuh_xml_levels_and_groups():
    rules = by_id(importers.import_wazuh(EXPORTS / "wazuh"))
    assert rules["100100"].techniques == ["T1110.001"]
    assert ("group", "sshd") in rules["100100"].requires
    assert ("group", "authentication_failures") in rules["100100"].requires
    assert not rules["100101"].enabled  # level 0 never alerts
    assert rules["100200"].requires == [("group", "sysmon")]


def test_wazuh_api_json():
    rules = by_id(importers.import_wazuh(EXPORTS / "wazuh-api.json"))
    assert rules["5712"].techniques == ["T1110"] and rules["5712"].enabled
    assert not rules["92000"].enabled
    assert rules["1"].techniques == []


def test_sigma_directory():
    rules = by_id(importers.import_sigma(EXPORTS / "sigma"))
    ps = rules["11111111-1111-1111-1111-111111111111"]
    assert ps.techniques == ["T1059.001"] and ps.requires == [("logsource", "windows/process_creation")]
    assert not rules["22222222-2222-2222-2222-222222222222"].enabled
    assert rules["33333333-3333-3333-3333-333333333333"].requires == [("logsource", "aws/cloudtrail")]


def test_sentinel_arm_tables_and_ids():
    rules = by_id(importers.import_sentinel(EXPORTS / "sentinel-arm.json"))
    assert set(rules) == {"Brute force against Azure AD", "def"}  # Fusion has no query
    bf = rules["Brute force against Azure AD"]
    assert bf.techniques == ["T1110", "T1110.003"]
    assert [t for _, t in bf.requires] == ["SigninLogs", "AuditLogs"]
    assert [t for _, t in rules["def"].requires] == ["SecurityEvent", "DeviceProcessEvents"]


def test_kql_tables_ignores_let_and_comments():
    q = "// SecurityEvent\nlet Admins = IdentityInfo | where x;\nAdmins\n| join (Syslog | take 1) on h"
    assert importers.kql_tables(q) == ["IdentityInfo", "Syslog"]


def test_data_sources_formats(tmp_path):
    txt = tmp_path / "active.txt"
    txt.write_text("# comment\ndatamodel:Endpoint\nlinux\nwindows/*\n")
    assert importers.load_data_sources(txt) == [("datamodel", "Endpoint"), (None, "linux"), (None, "windows/*")]
    tstats = tmp_path / "tstats.csv"
    tstats.write_text("index,sourcetype,count\nlinux,linux_secure,10\n")
    assert importers.load_data_sources(tstats) == [("index", "linux"), ("sourcetype", "linux_secure")]


def test_data_availability_all_vs_any(tmp_path):
    active = [("datamodel", "Endpoint"), ("index", "linux"), (None, "winlogbeat-2026.11.04")]
    splunk = by_id(importers.import_splunk(EXPORTS / "splunk-rest.json"))
    importers.apply_data_sources(list(splunk.values()), active)
    assert splunk["ESCU - Windows PowerShell Encoded Command"].data_available
    assert not splunk["ESCU - Linux Sudo Brute Force"].data_available  # sourcetype missing, match=all
    elastic = by_id(importers.import_elastic(EXPORTS / "elastic-export.ndjson"))
    importers.apply_data_sources(list(elastic.values()), active)
    assert elastic["e1"].data_available  # one of two index patterns is enough
    assert not elastic["e2"].data_available
    assert elastic["e4"].data_available and not elastic["e4"].checked


@pytest.mark.parametrize(
    "siem,export",
    [
        ("splunk", "splunk-rest.json"),
        ("elastic", "elastic-export.ndjson"),
        ("wazuh", "wazuh"),
        ("sigma", "sigma"),
        ("sentinel", "sentinel-arm.json"),
    ],
)
def test_cli_import_output_is_a_valid_inventory(tmp_path, capsys, siem, export):
    out = tmp_path / "rules.csv"
    assert main(["import", siem, "--export", str(EXPORTS / export), "--out", str(out)]) == 0
    rules = load_rules(out)
    assert rules and all(r.techniques for r in rules)
    assert "assumed to have data" in capsys.readouterr().err
    assert main(["report", "--rules", str(out), "--out-dir", str(tmp_path / "report")]) == 0


def test_cli_import_keep_from_preserves_manual_columns(tmp_path):
    old = tmp_path / "old.csv"
    old.write_text(
        "rule_id,name,techniques,enabled,data_available,tested,tuned,owner,source\n"
        "e1,x,T1059,true,true,true,true,blue-team,Elastic Security\n"
    )
    out = tmp_path / "rules.csv"
    args = ["import", "elastic", "--export", str(EXPORTS / "elastic-export.ndjson"), "--out", str(out)]
    assert main(args + ["--keep-from", str(old)]) == 0
    rows = {r["rule_id"]: r for r in csv.DictReader(open(out))}
    assert rows["e1"]["tested"] == "true" and rows["e1"]["owner"] == "blue-team"
    assert rows["e2"]["tested"] == "false"


def test_cli_import_errors(tmp_path, capsys):
    out = str(tmp_path / "o.csv")
    assert main(["import", "elastic", "--export", str(tmp_path / "missing.json"), "--out", out]) == 1
    empty = tmp_path / "empty.json"
    empty.write_text('{"data": [{"name": "x", "rule_id": "a", "enabled": true, "threat": []}]}')
    assert main(["import", "elastic", "--export", str(empty), "--out", out]) == 1
    assert "no rule in the export" in capsys.readouterr().err


def test_merge_several_siems_into_one_coverage(tmp_path, capsys):
    splunk, elastic = tmp_path / "splunk.csv", tmp_path / "elastic.csv"
    assert main(["import", "splunk", "--export", str(EXPORTS / "splunk-rest.json"), "--out", str(splunk)]) == 0
    assert main(["import", "elastic", "--export", str(EXPORTS / "elastic-export.ndjson"), "--out", str(elastic)]) == 0
    out = tmp_path / "coverage.json"
    assert main(["score", "--rules", str(splunk), str(elastic), "--out", str(out)]) == 0
    text = capsys.readouterr().out
    assert "Only here" in text
    import json

    data = json.loads(out.read_text())
    sources = {s["source"]: s for s in data["attack"]["sources"]}
    assert set(sources) == {"Splunk ES", "Elastic Security"}
    # T1059 is covered by both, T1110/T1548 only by Splunk, T1048 only by Elastic.
    assert sources["Elastic Security"]["only_here"] == 1
    assert sources["Splunk ES"]["only_here"] == 2
    assert data["attack"]["totals"]["distinct_covered"] == 4


def test_merge_qualifies_duplicate_ids(tmp_path):
    from coveragekit.rules import merge_inventories

    a, b = tmp_path / "a.csv", tmp_path / "b.csv"
    header = "rule_id,techniques,enabled,data_available,source\n"
    a.write_text(header + "R1,T1059,true,true,Splunk ES\n")
    b.write_text(header + "R1,T1110,true,true,Elastic Security\n")
    ids = [r.rule_id for r in merge_inventories([a, b])]
    assert ids == ["R1", "Elastic Security:R1"]


def test_spl_quoted_sourcetype_with_slash():
    sysmon = "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
    reqs = importers.spl_requirements(f'index="wineventlog" sourcetype="{sysmon}"')
    assert reqs == [("index", "wineventlog"), ("sourcetype", sysmon)]


def test_elastic_backing_indices_count_as_their_data_stream(tmp_path):
    f = tmp_path / "indices.txt"
    f.write_text(".ds-logs-aws.cloudtrail-default-2026.11.04-000001\n")
    active = importers.load_data_sources(f)
    assert active == [(None, "logs-aws.cloudtrail-default")]
    assert importers._satisfied(("index", "logs-aws.cloudtrail-*"), active)


def test_import_writes_data_sources_column(tmp_path):
    out = tmp_path / "rules.csv"
    assert main(["import", "splunk", "--export", str(EXPORTS / "splunk-rest.json"), "--out", str(out)]) == 0
    rows = {r["rule_id"]: r for r in csv.DictReader(open(out))}
    assert rows["ESCU - Windows PowerShell Encoded Command"]["data_sources"] == "datamodel:Endpoint"
    assert rows["ESCU - Linux Sudo Brute Force"]["data_sources"] == "index:linux;sourcetype:linux_secure"
    assert load_rules(out)[0].data_sources  # the column round-trips through the loader
    assert all(not r["missing_data"] for r in rows.values())  # nothing was checked


def test_import_records_the_missing_sources(tmp_path):
    active = tmp_path / "active.txt"
    active.write_text("datamodel:Endpoint\nindex:linux\n")  # linux_secure sourcetype is not arriving
    out = tmp_path / "rules.csv"
    args = ["import", "splunk", "--export", str(EXPORTS / "splunk-rest.json"), "--data-sources", str(active)]
    assert main(args + ["--out", str(out)]) == 0
    rows = {r["rule_id"]: r for r in csv.DictReader(open(out))}
    sudo = rows["ESCU - Linux Sudo Brute Force"]
    assert sudo["data_available"] == "false" and sudo["missing_data"] == "sourcetype:linux_secure"
    assert rows["ESCU - Windows PowerShell Encoded Command"]["missing_data"] == ""
    assert load_rules(out)[1].missing_data == ["sourcetype:linux_secure"]

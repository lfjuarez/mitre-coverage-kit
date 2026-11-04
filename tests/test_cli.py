import json

from coveragekit.cli import main


def test_report_writes_all_outputs(tmp_path, capsys):
    assert main(["report", "--rules", "examples/rules.csv", "--out-dir", str(tmp_path)]) == 0
    for name in ("coverage.json", "attack-layer.json", "coverage-attack.svg", "coverage-atlas.svg"):
        assert (tmp_path / name).is_file()
    data = json.loads((tmp_path / "coverage.json").read_text())
    assert set(data) >= {"attack", "atlas"}
    assert "Reconnaissance" in capsys.readouterr().out


def test_bad_input_exits_with_1(tmp_path, capsys):
    bad = tmp_path / "bad.csv"
    bad.write_text("rule_id,name,techniques,enabled,data_available\nA,x,T1059,maybe,true\n")
    assert main(["score", "--rules", str(bad), "--out", str(tmp_path / "o.json")]) == 1
    assert "invalid boolean" in capsys.readouterr().err
    assert main(["score", "--rules", str(tmp_path / "missing.csv"), "--out", str(tmp_path / "o.json")]) == 1

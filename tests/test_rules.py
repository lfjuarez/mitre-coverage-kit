import pytest

from coveragekit import rules as r


def row(**kw):
    base = {"rule_id": "R-1", "name": "x", "techniques": "T1059", "enabled": "true", "data_available": "yes"}
    base.update(kw)
    return base


def test_loads_example_inventory():
    loaded = r.load_rules("examples/rules.csv")
    assert len(loaded) > 60
    assert any(x.techniques[0].startswith("AML.") for x in loaded)


def test_boolean_variants():
    for text, expected in [("TRUE", True), ("no", False), ("1", True), ("0", False), ("Yes", True)]:
        assert r.parse_bool(text, field_name="enabled", row="row 1") is expected


def test_bad_boolean_is_error():
    with pytest.raises(r.RuleError, match="invalid boolean"):
        r.build_rules([row(enabled="maybe")])


def test_duplicate_ids_are_errors():
    with pytest.raises(r.RuleError, match="duplicate rule_id"):
        r.build_rules([row(), row()])


def test_needs_a_valid_technique():
    with pytest.raises(r.RuleError, match="at least one technique"):
        r.build_rules([row(techniques="not-an-id; 1059")])


def test_semicolon_list_and_subtechniques():
    rule = r.build_rules([row(techniques="T1059.001; AML.T0051 ;t1047")])[0]
    assert rule.techniques == ["T1059.001", "AML.T0051", "T1047"]
    assert rule.tested is False and rule.tuned is False


def test_unknown_ids_are_warnings_not_errors(attack, atlas):
    from coveragekit.frameworks import technique_ids

    known = technique_ids(attack) | technique_ids(atlas)
    rules = r.build_rules([row(techniques="T1059.001;T9999;bogus")])
    warnings = r.unknown_technique_warnings(rules, known)
    assert any("T9999" in w for w in warnings)
    assert any("BOGUS" in w for w in warnings)
    assert not any("T1059.001" in w for w in warnings)


def test_json_inventory(tmp_path):
    p = tmp_path / "rules.json"
    p.write_text('[{"rule_id": "A", "techniques": ["T1047"], "enabled": true, "data_available": false}]')
    rule = r.load_rules(p)[0]
    assert rule.enabled and not rule.data_available


def test_missing_column_and_file(tmp_path):
    p = tmp_path / "rules.csv"
    p.write_text("rule_id,name\nA,x\n")
    with pytest.raises(r.RuleError, match="missing required columns"):
        r.load_rules(p)
    with pytest.raises(r.RuleError, match="not found"):
        r.load_rules(tmp_path / "nope.csv")

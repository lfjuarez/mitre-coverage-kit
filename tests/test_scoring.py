from coveragekit import scoring
from coveragekit.rules import Rule


def make(rule_id, techniques, enabled=True, data=True, tested=False, tuned=False):
    return Rule(rule_id, rule_id, techniques, enabled, data, tested, tuned)


def level_of(cov, tid):
    return next(c["level"] for c in cov.cells if c["id"] == tid)


def test_quality_levels():
    assert scoring.rule_quality(make("a", ["T1"], enabled=False)) == 0
    assert scoring.rule_quality(make("a", ["T1"], data=False)) == 0
    assert scoring.rule_quality(make("a", ["T1"])) == 1
    assert scoring.rule_quality(make("a", ["T1"], tested=True)) == 2
    assert scoring.rule_quality(make("a", ["T1"], tested=True, tuned=True)) == 3
    assert scoring.rule_quality(make("a", ["T1"], tuned=True)) == 1  # tuned alone does not count


def test_all_four_levels(mini_attack):
    rules = [
        make("none", ["T1078"], enabled=False),
        make("low", ["T1059"]),
    ]
    cov = scoring.score(rules, mini_attack)
    assert level_of(cov, "T1078") == 0
    assert level_of(cov, "T1059") == 1
    rules = [make("hi", ["T1059"], tested=True, tuned=True), make("med", ["T1078"], tested=True)]
    cov = scoring.score(rules, mini_attack)
    assert level_of(cov, "T1059") == 3
    assert level_of(cov, "T1078") == 2


def test_subtechnique_rolls_up_and_max_wins(mini_attack):
    rules = [make("a", ["T1059.001"]), make("b", ["T1059"], tested=True), make("c", ["T1059.003"], enabled=False)]
    cov = scoring.score(rules, mini_attack)
    cell = next(c for c in cov.cells if c["id"] == "T1059")
    assert cell["level"] == 2
    assert cell["rules"] == ["a", "b", "c"]


def test_multi_tactic_technique_scored_in_each_tactic(mini_attack):
    cov = scoring.score([make("a", ["T1078"])], mini_attack)
    cells = [c for c in cov.cells if c["id"] == "T1078"]
    assert {c["tactic"] for c in cells} == {"Initial Access", "Execution"}
    assert all(c["level"] == 1 for c in cells)
    assert cov.totals["cells"] == 3 and cov.totals["distinct_techniques"] == 2
    assert cov.totals["distinct_covered"] == 1


def test_tactic_stats(mini_attack):
    cov = scoring.score([make("a", ["T1059"], tested=True)], mini_attack)
    execution = next(t for t in cov.tactics if t["tactic"] == "Execution")
    assert execution["techniques"] == 2 and execution["covered"] == 1
    assert execution["percent"] == 50.0 and execution["mean_level"] == 1.0


def test_dead_and_unmapped_rules(mini_attack):
    rules = [
        make("dead", ["T1059"], data=False),
        make("off", ["T1059"], enabled=False, data=False),
        make("unmapped", ["T4242"]),
        make("atlas-only", ["AML.T0051"], data=False),
    ]
    cov = scoring.score(rules, mini_attack)
    assert [d["rule_id"] for d in cov.dead_rules] == ["dead"]
    assert [u["rule_id"] for u in cov.unmapped_rules] == ["unmapped"]


def test_to_dict_is_json_serialisable(mini_attack):
    import json

    cov = scoring.score([make("a", ["T1059"])], mini_attack)
    data = json.loads(json.dumps(cov.to_dict()))
    keys = {"framework", "version", "totals", "tactics", "cells", "dead_rules", "unmapped_rules", "sources"}
    assert set(data) == keys
    assert set(data["cells"][0]) == {"framework", "tactic", "tactic_id", "id", "name", "level", "rules"}


def test_example_inventory_against_bundled_data(attack, atlas):
    from coveragekit.rules import load_rules

    rules = load_rules("examples/rules.csv")
    a = scoring.score(rules, attack)
    b = scoring.score(rules, atlas)
    assert a.unmapped_rules == [] and b.unmapped_rules == []
    assert len(a.dead_rules) + len(b.dead_rules) >= 8
    assert 0 < a.totals["percent"] < 100

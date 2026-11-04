from coveragekit import scoring
from coveragekit.rules import Rule


def make(rule_id, techniques, enabled=True, data=True, tested=False, tuned=False, sources=(), missing=()):
    return Rule(
        rule_id,
        f"Rule {rule_id}",
        techniques,
        enabled,
        data,
        tested,
        tuned,
        data_sources=list(sources),
        missing_data=list(missing),
    )


def analysis(attack, rules):
    return scoring.score(rules, attack).analysis


def test_recoverable_fragile_and_dead_by_source(attack):
    rules = [
        make("hi", ["T1059"], tested=True, tuned=True),  # High, only rule for T1059: fragile
        make("dead", ["T1003"], data=False, sources=["sourcetype:x", "index:y"], missing=["sourcetype:x"]),
        make("dead2", ["T1003.001"], data=False, sources=["sourcetype:x"]),
        make("twin1", ["T1047"], tested=True),
        make("twin2", ["T1047"]),  # T1047 has two rules: not fragile
    ]
    a = analysis(attack, rules)
    assert [f["id"] for f in a["fragile"]] == ["T1059"]
    assert a["recoverable"] == [{"id": "T1003", "name": "OS Credential Dumping", "rules": ["dead", "dead2"]}]
    assert a["dead_by_source"] == [{"source": "sourcetype:x", "rules": ["dead", "dead2"]}]  # index:y is arriving
    assert a["untested_rules"] == 1 and a["low_techniques"] == 0  # only twin2 is live and untested; T1047 is Medium
    assert a["untuned_rules"] == 1 and a["medium_techniques"] == 1


def test_recommendations_follow_the_inventory(attack):
    rules = [
        make("a", ["T1110"]),  # Low, untested
        make("b", ["T1059"], tested=True),  # Medium, untuned
        make("dead", ["T1003"], data=False),
        make("old", ["T1562"]),  # retired in v20: unmapped
    ]
    a = analysis(attack, rules)
    keys = [r["key"] for r in a["recommendations"]]
    assert keys == [
        "restore-data",
        "test-rules",
        "close-gaps",
        "add-redundancy",
        "tune-rules",
        "remap-retired",
        "pre-compromise",
    ]
    test_rec = a["recommendations"][1]
    assert "1 technique move" in test_rec["impact"]
    assert test_rec["items"][0]["link"].endswith("/atomics/T1110")
    assert "T1562" in a["recommendations"][5]["items"][0]["text"]
    assert a["pre_compromise"] == ["Reconnaissance", "Resource Development"]
    assert all(t["percent"] < 20 and t["tactic"] not in a["pre_compromise"] for t in a["weak_tactics"])
    assert len(a["weak_tactics"]) == 3 and a["weak_tactics"][0]["uncovered"]


def test_no_recommendations_without_problems(attack):
    a = analysis(attack, [make("x", ["T1059"], tested=True, tuned=True), make("y", ["T1059"], tested=True, tuned=True)])
    keys = [r["key"] for r in a["recommendations"]]
    assert (
        "restore-data" not in keys
        and "test-rules" not in keys
        and "tune-rules" not in keys
        and "add-redundancy" not in keys
    )


def test_catalog_suggests_but_never_counts(attack):
    deployed = [make("a", ["T1059"], tested=True, tuned=True)]
    catalog = [
        make("s1", ["T1003.001"], sources=["logsource:windows/process_creation"]),  # data arrives: ready
        make(
            "s2", ["T1003"], data=False, sources=["logsource:windows/security"], missing=["logsource:windows/security"]
        ),
        make("s3", ["T1059.001"]),  # T1059 is already covered: not suggested
        make("s4", ["T1110"], enabled=False),  # deprecated in the catalog: ignored
    ]
    with_catalog = scoring.score(deployed, attack, catalog)
    without = scoring.score(deployed, attack)
    assert with_catalog.totals == without.totals  # coverage does not move
    entries = {e["id"]: e for e in with_catalog.analysis["catalog"]}
    assert set(entries) == {"T1003"}
    assert entries["T1003"]["ready_count"] == 1 and entries["T1003"]["needs_data_count"] == 1
    rec = next(r for r in with_catalog.analysis["recommendations"] if r["key"] == "deploy-catalog")
    assert rec["impact"].startswith("1 uncovered technique has a public rule")
    assert "deploy-catalog" not in [r["key"] for r in without.analysis["recommendations"]]

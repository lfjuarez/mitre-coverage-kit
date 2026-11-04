import json

import pytest

from coveragekit import frameworks, navigator, scoring
from coveragekit.rules import load_rules


@pytest.fixture(scope="module")
def layer(attack):
    cov = scoring.score(load_rules("examples/rules.csv"), attack)
    return navigator.build_layer(cov, name="Test layer"), attack


def test_layer_schema(layer):
    data, _ = layer
    assert data["name"] == "Test layer"
    assert data["domain"] == "enterprise-attack"
    assert data["versions"] == {"attack": "20", "navigator": "5.1.0", "layer": "4.5"}
    assert data["gradient"]["colors"] == ["#f6d5d0", "#dc9a2a", "#4a9e5c", "#1e6e42"]
    assert (data["gradient"]["minValue"], data["gradient"]["maxValue"]) == (0, 100)
    assert len(data["legendItems"]) == 4
    assert data["layout"] == {"layout": "side", "showID": True, "showName": True}
    assert data["showTacticRowBackground"] is True
    assert data["selectTechniquesAcrossTactics"] is True
    assert json.loads(json.dumps(data)) == data


def test_scores_and_every_technique_once(layer):
    data, attack = layer
    ids = [t["techniqueID"] for t in data["techniques"]]
    assert len(ids) == len(set(ids)) == len(frameworks.technique_ids(attack))
    assert set(ids) == frameworks.technique_ids(attack)
    assert {t["score"] for t in data["techniques"]} <= {0, 33, 66, 100}
    assert all(set(t) == {"techniqueID", "score", "comment"} for t in data["techniques"])


def test_comment_lists_rules(layer):
    data, _ = layer
    t1003 = next(t for t in data["techniques"] if t["techniqueID"] == "T1003")
    assert t1003["score"] == 100
    assert t1003["comment"].startswith("High · rules: R-")


def test_atlas_is_rejected(atlas):
    cov = scoring.score(load_rules("examples/rules.csv"), atlas)
    with pytest.raises(ValueError):
        navigator.build_layer(cov)

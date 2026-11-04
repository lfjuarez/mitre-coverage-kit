import json
from pathlib import Path

import pytest

from coveragekit import frameworks

FIXTURES = Path(__file__).parent / "fixtures"
LOCAL_ATTACK = Path("/Users/leandrofedericojuarez/Freelance/muestras/data/enterprise-attack.json")
LOCAL_ATLAS = Path("/Users/leandrofedericojuarez/Freelance/muestras/data/ATLAS.yaml")


def test_attack_fixture_order_filters_and_multi_tactic(mini_attack):
    assert mini_attack["version"] == "20.0"
    tactics = mini_attack["tactics"]
    assert [t["id"] for t in tactics] == ["TA0001", "TA0002"]  # matrix order, not file order
    assert tactics[0]["techniques"] == [["T1078", "Valid Accounts"]]
    assert tactics[1]["techniques"] == [
        ["T1059", "Command and Scripting Interpreter"],
        ["T1078", "Valid Accounts"],
    ]  # no sub-technique, revoked or deprecated entries


def test_atlas_fixture_skips_subtechniques():
    package = frameworks.build_atlas(FIXTURES / "mini-atlas.yaml")
    assert package["version"] == "5.6.0"
    recon, execution = package["tactics"]
    assert recon["techniques"] == [
        ["AML.T0000", "Search Open Technical Databases"],
        ["AML.T0051", "LLM Prompt Injection"],
    ]
    assert execution["techniques"] == [["AML.T0051", "LLM Prompt Injection"]]


def test_invalid_inputs_raise():
    with pytest.raises(frameworks.FrameworkError):
        frameworks.parse_attack({"objects": []})
    with pytest.raises(frameworks.FrameworkError):
        frameworks.parse_atlas({"matrices": []})
    with pytest.raises(frameworks.FrameworkError):
        frameworks.load("nope")


def test_parent_id_and_framework():
    assert frameworks.parent_id("T1059.001") == "T1059"
    assert frameworks.parent_id("T1059") == "T1059"
    assert frameworks.parent_id("AML.T0051.000") == "AML.T0051"
    assert frameworks.parent_id("AML.T0051") == "AML.T0051"
    assert frameworks.framework_of("AML.T0051") == "atlas"
    assert frameworks.framework_of("T1059") == "attack"


def test_bundled_data_shape(attack, atlas):
    assert attack["framework"] == "attack" and attack["version"] == "20.0"
    assert atlas["framework"] == "atlas" and atlas["version"] == "5.6.0"
    assert len(attack["tactics"]) == 15
    assert frameworks.cell_count(attack) == 259
    assert len(frameworks.technique_ids(attack)) == 227
    assert len(atlas["tactics"]) == 16
    assert frameworks.cell_count(atlas) == 111
    assert len(frameworks.technique_ids(atlas)) == 101


def test_write_and_load_from_directory(tmp_path, mini_attack):
    path = frameworks.write_package(mini_attack, tmp_path)
    assert path.name == "attack-enterprise-v20.min.json"
    assert frameworks.load("attack", tmp_path) == json.loads(path.read_text())
    with pytest.raises(frameworks.FrameworkError):
        frameworks.load("atlas", tmp_path)


@pytest.mark.skipif(
    not (LOCAL_ATTACK.exists() and LOCAL_ATLAS.exists()), reason="local MITRE source files absent"
)
def test_full_files_match_bundled_data(attack, atlas):
    built_attack = frameworks.build_attack(LOCAL_ATTACK)
    built_atlas = frameworks.build_atlas(LOCAL_ATLAS)
    assert len(built_attack["tactics"]) == 15
    assert frameworks.cell_count(built_attack) == 259
    assert len(frameworks.technique_ids(built_attack)) == 227
    assert len(built_atlas["tactics"]) == 16
    assert frameworks.cell_count(built_atlas) == 111
    assert built_attack == attack
    assert built_atlas == atlas

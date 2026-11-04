"""Elastic Security detection rules for the lab, from lab/catalog.py (one JSON object per line)."""
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE.parent))
from catalog import DETECTIONS, DISABLED  # noqa: E402

DATA = HERE.parents[1] / "src" / "coveragekit" / "data"
TACTIC = {}  # parent technique -> (tactic id, tactic name), first tactic in matrix order
for name in ("attack-enterprise-v20.min.json", "atlas-v5.6.min.json"):
    for tac in json.loads((DATA / name).read_text())["tactics"]:
        for tid, _ in tac["techniques"]:
            TACTIC.setdefault(tid, (tac["id"], tac["name"]))

rules = []
for key, name, techs, where in DETECTIONS:
    if "elastic" not in where:
        continue
    threats = {}
    for t in techs:
        framework = "MITRE ATLAS" if t.startswith("AML.") else "MITRE ATT&CK"
        parent, _, sub = t.partition(".") if framework == "MITRE ATT&CK" else (t, "", "")
        tac_id, tac_name = TACTIC.get(parent, ("TA0000", "Unknown"))
        group = threats.setdefault((framework, tac_id), {"framework": framework,
                 "tactic": {"id": tac_id, "name": tac_name, "reference": "https://attack.mitre.org/"}, "technique": {}})
        entry = group["technique"].setdefault(parent, {"id": parent, "name": parent, "reference": "https://attack.mitre.org/"})
        if sub:
            entry.setdefault("subtechnique", []).append({"id": t, "name": t, "reference": "https://attack.mitre.org/"})
    rules.append({
        "rule_id": f"lab-{key}", "name": name, "description": f"Lab detection: {name}", "type": "query",
        "language": "kuery", "query": f'lab.detection : "{key}"', "index": [where["elastic"]],
        "risk_score": 47, "severity": "medium", "interval": "30m", "from": "now-35m",
        "enabled": key not in DISABLED["elastic"],
        "threat": [{**g, "technique": list(g["technique"].values())} for g in threats.values()],
    })
(HERE / "rules.ndjson").write_text("\n".join(json.dumps(r) for r in rules) + "\n")
print(f"{len(rules)} rules")

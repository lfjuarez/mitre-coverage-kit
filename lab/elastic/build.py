"""Elastic Security detection rules for the lab, from lab/catalog.py (one JSON object per line)."""
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE.parent))
from catalog import DETECTIONS, DISABLED  # noqa: E402

rules = []
for key, name, techs, where in DETECTIONS:
    if "elastic" not in where:
        continue
    threats = {}
    for t in techs:
        framework = "MITRE ATLAS" if t.startswith("AML.") else "MITRE ATT&CK"
        parent, _, sub = t.partition(".") if framework == "MITRE ATT&CK" else (t, "", "")
        entry = threats.setdefault((framework, parent), {"id": parent, "name": parent, "reference": "https://attack.mitre.org/"})
        if sub:
            entry.setdefault("subtechnique", []).append({"id": t, "name": t, "reference": "https://attack.mitre.org/"})
    by_fw = {}
    for (fw, _), tech in threats.items():
        by_fw.setdefault(fw, []).append(tech)
    rules.append({
        "rule_id": f"lab-{key}", "name": name, "description": f"Lab detection: {name}", "type": "query",
        "language": "kuery", "query": f'lab.detection : "{key}"', "index": [where["elastic"]],
        "risk_score": 47, "severity": "medium", "interval": "30m", "from": "now-35m",
        "enabled": key not in DISABLED["elastic"],
        "threat": [{"framework": fw, "tactic": {"id": "TA0000", "name": "lab", "reference": "https://attack.mitre.org/"},
                    "technique": techs} for fw, techs in by_fw.items()],
    })
(HERE / "rules.ndjson").write_text("\n".join(json.dumps(r) for r in rules) + "\n")
print(f"{len(rules)} rules")

"""Wazuh custom rules (local_rules.xml) for the lab, from lab/catalog.py."""
import pathlib
import sys
from xml.sax.saxutils import escape

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE.parent))
from catalog import DETECTIONS  # noqa: E402

by_group: dict[str, list[str]] = {}
rid = 100100
for key, name, techs, where in DETECTIONS:
    if "wazuh" not in where:
        continue
    parent, extra = where["wazuh"]
    mitre = "".join(f"<id>{t}</id>" for t in techs)
    by_group.setdefault(parent, []).append(
        f'  <rule id="{rid}" level="10">\n    <match>LABDETECT {key}</match>\n'
        f"    <description>{escape(name)}</description>\n    <mitre>{mitre}</mitre>\n    <group>{extra},</group>\n  </rule>\n")
    rid += 1
xml = "".join(f'<group name="lab,{g},">\n{"".join(r)}</group>\n' for g, r in by_group.items())
(HERE / "local_rules.xml").write_text(xml)
print(f"{rid - 100100} rules")

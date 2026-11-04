"""Build the Splunk lab app (correlation searches + indexes) and the sample events from lab/catalog.py."""
import pathlib
import sys
import time

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE.parent))
from catalog import DETECTIONS, DISABLED, LOADED  # noqa: E402

app = HERE / "coverage_lab" / "default"
app.mkdir(parents=True, exist_ok=True)
(app / "app.conf").write_text("[ui]\nis_visible = 0\nlabel = Coverage lab\n\n[package]\nid = coverage_lab\n")
indexes = sorted({src[0] for _, _, _, s in DETECTIONS if "splunk" in s for src in [s["splunk"]]})
(app / "indexes.conf").write_text("".join(
    f"[{i}]\nhomePath = $SPLUNK_DB/{i}/db\ncoldPath = $SPLUNK_DB/{i}/colddb\nthawedPath = $SPLUNK_DB/{i}/thaweddb\n\n"
    for i in indexes))
stanzas = []
for key, name, techs, where in DETECTIONS:
    if "splunk" not in where:
        continue
    index, sourcetype = where["splunk"]
    ids = ", ".join(f'"{t}"' for t in techs)
    stanzas.append(
        f"[ESCU - {name} - Rule]\n"
        f"search = index={index} sourcetype=\"{sourcetype}\" lab_detection={key} | stats count by host\n"
        f"disabled = {1 if key in DISABLED['splunk'] else 0}\n"
        "cron_schedule = */30 * * * *\nenableSched = 1\n"
        "action.correlationsearch.enabled = 1\n"
        f"action.correlationsearch.label = ESCU - {name} - Rule\n"
        f"action.correlationsearch.annotations = {{\"mitre_attack\": [{ids}]}}\n"
    )
(app / "savedsearches.conf").write_text("\n".join(stanzas))

events = HERE / "events"
events.mkdir(exist_ok=True)
now = int(time.time())
for index, sourcetype in LOADED["splunk"]:
    fname = sourcetype.replace(":", "_").replace("/", "_") + ".log"
    lines = [f"{time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(now - 60 * n))}Z host=lab-win{n % 3} "
             f"EventCode={4624 + n % 5} message=\"lab event {n}\"" for n in range(50)]
    (events / fname).write_text("\n".join(lines) + "\n")
    print(index, sourcetype, events / fname)
print(f"{len(stanzas)} correlation searches, indexes: {', '.join(indexes)}")

"""Render terminal screenshots of the lab commands. Runs each command for real and captures its output."""
import html
import pathlib
import shlex
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = pathlib.Path(__file__).parent
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
CK = shlex.quote(str(ROOT / ".venv/bin/coveragekit"))

SHOTS = {
    "terminal-import.png": [
        "coveragekit import splunk --export out/splunk/correlation-searches.json --data-sources out/splunk/active-sources.csv --out out/splunk/rules.csv",
        "coveragekit import elastic --export out/elastic/rules.json --data-sources out/elastic/active-indices.txt --out out/elastic/rules.csv",
        "coveragekit import wazuh --export out/wazuh/rules-local.json --data-sources out/wazuh/active-groups.txt --out out/wazuh/rules.csv",
        "coveragekit import sigma --export out/sigma-src/rules --data-sources sigma/active-logsources.txt --out out/sigma/rules.csv",
    ],
    "terminal-unified.png": [
        "coveragekit report --rules out/splunk/rules.csv out/elastic/rules.csv out/wazuh/rules.csv --out-dir out/unified",
    ],
}


def run(cmd: str) -> str:
    real = cmd.replace("coveragekit", CK, 1).replace("", "")
    res = subprocess.run(real, shell=True, cwd=ROOT / "lab", capture_output=True, text=True)
    text = res.stdout
    if "report" in cmd:  # keep the ATT&CK part: totals, tactics and the per-SIEM table
        text = text.split("ATLAS")[0]
    warnings = [ln for ln in res.stderr.splitlines() if ln.startswith("warning:")]
    return "\n".join(warnings + [text.rstrip()])


def colour(line: str) -> str:
    e = html.escape(line)
    if line.startswith(("ATT&CK", "splunk:", "elastic:", "wazuh:", "sigma:")):
        return f'<span class="a">{e}</span>'
    if "without data" in line or "dead rules" in line or line.startswith("warning:"):
        return f'<span class="w">{e}</span>'
    if line.strip().startswith(("Tactic", "Source")):
        return f'<span class="m">{e}</span>'
    if line.startswith("wrote"):
        return f'<span class="m">{e}</span>'
    return e


for name, cmds in SHOTS.items():
    blocks = []
    for cmd in cmds:
        shown = cmd.replace("", "")
        blocks.append(f'<span class="p">$</span> <span class="c">{html.escape(shown)}</span>\n'
                      + "\n".join(colour(ln) for ln in run(cmd).splitlines()))
    body = "\n\n".join(blocks)
    page = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><style>
    body{{margin:0;background:#13213a;padding:40px;font-family:"SF Mono",Menlo,monospace}}
    .t{{background:#0c1628;border:1px solid #24375a;border-radius:14px;overflow:hidden;width:1320px}}
    .bar{{height:40px;background:#101d33;display:flex;gap:9px;align-items:center;padding:0 18px}}
    .bar i{{width:13px;height:13px;border-radius:7px;display:block}}
    .bar b{{margin-left:14px;color:#8fa0ba;font:500 14px "Avenir Next",sans-serif}}
    pre{{margin:0;padding:24px 26px;font-size:15.5px;line-height:1.55;color:#c9d3e3;white-space:pre-wrap;word-break:break-all}}
    .p{{color:#8fa0ba}} .c{{color:#f4f4f1}} .a{{color:#9ec5f4;font-weight:600}} .w{{color:#f0b45a}} .m{{color:#8fa0ba}}
    </style></head><body><div class="t"><div class="bar"><i style="background:#ff5f57"></i><i style="background:#febc2e"></i>
    <i style="background:#28c840"></i><b>mitre-coverage-kit · lab</b></div><pre>{body}</pre></div></body></html>"""
    f = OUT / (name + ".html")
    f.write_text(page)
    lines = body.count("\n") + 1
    height = 40 + 40 + 48 + int(lines * 15.5 * 1.55) + 60
    subprocess.run([CHROME, "--headless=new", "--hide-scrollbars", f"--window-size=1400,{height}",
                    "--force-device-scale-factor=2", f"--screenshot={OUT / name}", f"file://{f}"], capture_output=True)
    f.unlink()
    print(name)

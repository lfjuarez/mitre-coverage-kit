"""Render a terminal screenshot from commands that really run. Used to build the integration guides.

python docs/guides/term.py OUT.png 'shown command' 'real command' ['shown' 'real' ...]
The shown text is what the guide displays (secrets replaced by placeholders); the real command runs in lab/.
"""
import html
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"


def colour(line: str) -> str:
    e = html.escape(line)
    if line.startswith(("splunk:", "elastic:", "wazuh:", "ATT&CK", "ATLAS")):
        return f'<span class="a">{e}</span>'
    if line.startswith(("warning:", "error:")) or "without data" in line or "dead rules" in line:
        return f'<span class="w">{e}</span>'
    if line.startswith(("wrote", "exports saved", "coveragekit ")) or line.strip().startswith(("Tactic", "Source")):
        return f'<span class="m">{e}</span>'
    return e


out, pairs = str(pathlib.Path(sys.argv[1]).resolve()), sys.argv[2:]
blocks = []
for shown, real in zip(pairs[::2], pairs[1::2]):
    res = subprocess.run(real, shell=True, cwd=ROOT / "lab", capture_output=True, text=True, executable="/bin/zsh")
    text = (res.stdout + res.stderr).rstrip()
    lines = [f'<span class="p">$</span> <span class="c">{html.escape(ln)}</span>' for ln in shown.splitlines()]
    blocks.append("\n".join(lines + [colour(x) for x in text.splitlines()]))
body = "\n\n".join(blocks)
page = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><style>
body{{margin:0;background:#13213a;padding:28px;font-family:"SF Mono",Menlo,monospace}}
.t{{background:#0c1628;border:1px solid #24375a;border-radius:12px;overflow:hidden;width:1180px}}
.bar{{height:36px;background:#101d33;display:flex;gap:8px;align-items:center;padding:0 16px}}.bar i{{width:12px;height:12px;border-radius:6px;display:block}}
pre{{margin:0;padding:20px 22px;font-size:14.5px;line-height:1.55;color:#c9d3e3;white-space:pre-wrap;word-break:break-all}}
.p{{color:#8fa0ba}}.c{{color:#f4f4f1}}.a{{color:#9ec5f4;font-weight:600}}.w{{color:#f0b45a}}.m{{color:#8fa0ba}}
</style></head><body><div class="t"><div class="bar"><i style="background:#ff5f57"></i><i style="background:#febc2e"></i><i style="background:#28c840"></i></div><pre>{body}</pre></div></body></html>"""
f = pathlib.Path(out).with_suffix(".html")
f.write_text(page)
lines = body.count("\n") + 1
height = 56 + 36 + 40 + int(lines * 14.5 * 1.55) + 30
subprocess.run([CHROME, "--headless=new", "--hide-scrollbars", f"--window-size=1236,{height}", "--force-device-scale-factor=2",
                f"--screenshot={out}", f.as_uri()], capture_output=True, timeout=90)
f.unlink()
print(out)

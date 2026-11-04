"""Load, fetch and parse the MITRE ATT&CK Enterprise and MITRE ATLAS matrices.

Both frameworks are reduced to one minimal structure, a list of tactics in matrix order::

    [{"id": "TA0043", "name": "Reconnaissance",
      "techniques": [["T1589", "Gather Victim Identity Information"], ...]}, ...]

A technique that belongs to several tactics appears under each of them.
"""

from __future__ import annotations

import json
import shutil
import urllib.request
from collections.abc import Iterable
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
ATLAS_URL = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml"

FRAMEWORKS = ("attack", "atlas")

Matrix = list[dict[str, Any]]


class FrameworkError(ValueError):
    """Raised when a framework file cannot be read or parsed."""


def _external_id(obj: dict[str, Any]) -> str | None:
    refs = obj.get("external_references") or []
    return refs[0].get("external_id") if refs else None


def parse_attack(stix: dict[str, Any]) -> tuple[Matrix, str]:
    """Parse an ATT&CK Enterprise STIX 2.1 bundle into ``(matrix, version)``."""
    objects = stix.get("objects")
    if not isinstance(objects, list):
        raise FrameworkError("not a STIX bundle: missing 'objects' list")

    tactics: dict[str, dict[str, Any]] = {}
    matrix_obj: dict[str, Any] | None = None
    version = ""
    for obj in objects:
        kind = obj.get("type")
        if kind == "x-mitre-tactic":
            tactics[obj["id"]] = obj
        elif kind == "x-mitre-matrix" and matrix_obj is None:
            matrix_obj = obj
        elif kind == "x-mitre-collection" and not version:
            version = str(obj.get("x_mitre_version", ""))
    if matrix_obj is None:
        raise FrameworkError("STIX bundle has no x-mitre-matrix object")

    ordered = [tactics[ref] for ref in matrix_obj.get("tactic_refs", []) if ref in tactics]
    by_shortname = {t["x_mitre_shortname"]: [] for t in ordered}
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_is_subtechnique") or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        tid = _external_id(obj)
        if not tid:
            continue
        for phase in obj.get("kill_chain_phases") or []:
            bucket = by_shortname.get(phase.get("phase_name"))
            if bucket is not None and [tid, obj["name"]] not in bucket:
                bucket.append([tid, obj["name"]])

    matrix: Matrix = []
    for t in ordered:
        techniques = sorted(by_shortname[t["x_mitre_shortname"]], key=lambda x: x[0])
        matrix.append({"id": _external_id(t) or "", "name": t["name"], "techniques": techniques})
    return matrix, version


def parse_atlas(doc: dict[str, Any]) -> tuple[Matrix, str]:
    """Parse the ATLAS.yaml document into ``(matrix, version)``."""
    try:
        m = doc["matrices"][0]
        tactics = m["tactics"]
        techniques = m["techniques"]
    except (KeyError, IndexError, TypeError) as exc:
        raise FrameworkError("not an ATLAS document: missing matrices[0].tactics/techniques") from exc

    cells: dict[str, list[list[str]]] = {t["id"]: [] for t in tactics}
    for tech in techniques:
        tid = tech["id"]
        if tid.count(".") > 1:  # AML.T0000.000 is a sub-technique
            continue
        for tactic_id in tech.get("tactics") or []:
            if tactic_id in cells:
                cells[tactic_id].append([tid, tech["name"]])
    matrix = [
        {"id": t["id"], "name": t["name"], "techniques": sorted(cells[t["id"]], key=lambda x: x[0])}
        for t in tactics
    ]
    return matrix, str(doc.get("version", ""))


def _package(matrix: Matrix, version: str, framework: str) -> dict[str, Any]:
    return {"framework": framework, "version": version, "tactics": matrix}


def build_attack(stix_path: Path) -> dict[str, Any]:
    with open(stix_path, encoding="utf-8") as fh:
        matrix, version = parse_attack(json.load(fh))
    return _package(matrix, version, "attack")


def build_atlas(yaml_path: Path) -> dict[str, Any]:
    with open(yaml_path, encoding="utf-8") as fh:
        matrix, version = parse_atlas(yaml.safe_load(fh))
    return _package(matrix, version, "atlas")


def output_name(framework: str, version: str) -> str:
    """File name used for a minimal framework map, e.g. ``attack-enterprise-v20.min.json``."""
    if framework == "attack":
        return f"attack-enterprise-v{version.split('.')[0]}.min.json"
    return f"atlas-v{version.rsplit('.', 1)[0] if version.count('.') > 1 else version}.min.json"


def write_package(package: dict[str, Any], dest_dir: Path) -> Path:
    dest_dir.mkdir(parents=True, exist_ok=True)
    path = dest_dir / output_name(package["framework"], package["version"])
    path.write_text(json.dumps(package, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    return path


def _download(url: str, target: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "mitre-coverage-kit"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response, open(target, "wb") as out:
            shutil.copyfileobj(response, out)
    except OSError as exc:
        raise FrameworkError(f"download failed for {url}: {exc}") from exc


def fetch(dest_dir: str | Path) -> list[Path]:
    """Download ATT&CK Enterprise and ATLAS and write the two minimal JSON files to ``dest_dir``."""
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    raw_attack = dest / ".enterprise-attack.download"
    raw_atlas = dest / ".ATLAS.download"
    try:
        _download(ATTACK_URL, raw_attack)
        written.append(write_package(build_attack(raw_attack), dest))
        _download(ATLAS_URL, raw_atlas)
        written.append(write_package(build_atlas(raw_atlas), dest))
    finally:
        raw_attack.unlink(missing_ok=True)
        raw_atlas.unlink(missing_ok=True)
    return written


def _find(directory: Path, framework: str) -> Path:
    pattern = "attack-enterprise-v*.min.json" if framework == "attack" else "atlas-v*.min.json"
    matches = sorted(directory.glob(pattern))
    if not matches:
        raise FrameworkError(f"no {framework} map ({pattern}) found in {directory}")
    return matches[-1]


def load(framework: str, directory: str | Path | None = None) -> dict[str, Any]:
    """Return the minimal framework map for ``attack`` or ``atlas``.

    By default the copy bundled with the package is used; pass ``directory`` to use files
    written by :func:`fetch`.
    """
    if framework not in FRAMEWORKS:
        raise FrameworkError(f"unknown framework '{framework}' (expected one of {', '.join(FRAMEWORKS)})")
    if directory is not None:
        path = _find(Path(directory), framework)
        return json.loads(path.read_text(encoding="utf-8"))
    data = resources.files("coveragekit").joinpath("data")
    pattern_prefix = "attack-enterprise-v" if framework == "attack" else "atlas-v"
    names = sorted(
        p.name for p in data.iterdir() if p.name.startswith(pattern_prefix) and p.name.endswith(".min.json")
    )
    if not names:
        raise FrameworkError(f"bundled {framework} data is missing")
    return json.loads(data.joinpath(names[-1]).read_text(encoding="utf-8"))


def technique_ids(package: dict[str, Any]) -> set[str]:
    """All distinct technique ids in a framework map."""
    return {tid for tactic in package["tactics"] for tid, _ in tactic["techniques"]}


def cell_count(package: dict[str, Any]) -> int:
    return sum(len(t["techniques"]) for t in package["tactics"])


def parent_id(technique: str) -> str:
    """Map a sub-technique id (``T1059.001`` or ``AML.T0051.000``) to its parent id."""
    head, sep, tail = technique.rpartition(".")
    if sep and tail.isdigit() and len(tail) == 3 and (head.startswith("T") or head.startswith("AML.T")):
        return head
    return technique


def framework_of(technique: str) -> str:
    return "atlas" if technique.startswith("AML.") else "attack"


def iter_cells(package: dict[str, Any]) -> Iterable[tuple[dict[str, Any], str, str]]:
    for tactic in package["tactics"]:
        for tid, name in tactic["techniques"]:
            yield tactic, tid, name

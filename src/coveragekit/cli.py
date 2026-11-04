"""Command line interface: ``coveragekit``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__, frameworks, importers
from .html import render_html
from .navigator import build_layer
from .render import render_svg
from .rules import Rule, RuleError, merge_inventories, unknown_technique_warnings
from .scoring import Coverage, score


class CliError(Exception):
    """A user-facing error; the CLI prints it and exits with status 1."""


def _write(path: Path, text: str) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    except OSError as exc:
        raise CliError(f"cannot write {path}: {exc}") from exc


def _prepare(args: argparse.Namespace, names: list[str]) -> tuple[dict[str, Coverage], list[Rule]]:
    try:
        rules = merge_inventories(args.rules)
        packages = {n: frameworks.load(n, args.frameworks_dir) for n in names}
    except (RuleError, frameworks.FrameworkError, OSError, json.JSONDecodeError) as exc:
        raise CliError(str(exc)) from exc
    known: set[str] = set()
    for package in frameworks.load("attack", args.frameworks_dir), frameworks.load("atlas", args.frameworks_dir):
        known |= frameworks.technique_ids(package)
    for warning in unknown_technique_warnings(rules, known):
        print(f"warning: {warning}", file=sys.stderr)
    return {n: score(rules, p) for n, p in packages.items()}, rules


def _names(choice: str) -> list[str]:
    return ["attack", "atlas"] if choice == "both" else [choice]


def _print_summary(coverage: Coverage) -> None:
    label = "ATT&CK Enterprise" if coverage.framework == "attack" else "ATLAS"
    t = coverage.totals
    covered = f"{t['distinct_covered']}/{t['distinct_techniques']}"
    print(f"{label} v{coverage.version}: {covered} techniques ({t['percent']}%)")
    width = max(len(x["tactic"]) for x in coverage.tactics)
    print(f"  {'Tactic'.ljust(width)}  {'Covered':>9}  {'Percent':>8}  {'Mean level':>10}")
    for x in coverage.tactics:
        covered = f"{x['covered']}/{x['techniques']}"
        print(f"  {x['tactic'].ljust(width)}  {covered:>9}  {x['percent']:>7.1f}%  {x['mean_level']:>10.2f}")
    print(f"  dead rules: {len(coverage.dead_rules)}  unmapped rules: {len(coverage.unmapped_rules)}")
    if coverage.sources:
        width = max(len(x["source"]) for x in coverage.sources)
        print(f"  {'Source'.ljust(width)}  {'Rules':>6}  {'Techniques':>10}  {'Only here':>9}")
        for x in coverage.sources:
            print(f"  {x['source'].ljust(width)}  {x['rules']:>6}  {x['covered']:>10}  {x['only_here']:>9}")


def _coverage_json(results: dict[str, Coverage]) -> str:
    payload: dict[str, Any] = {"generator": f"mitre-coverage-kit {__version__}"}
    payload.update({name: cov.to_dict() for name, cov in results.items()})
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def cmd_fetch(args: argparse.Namespace) -> None:
    try:
        for path in frameworks.fetch(args.dest):
            print(f"wrote {path}")
    except (frameworks.FrameworkError, json.JSONDecodeError, KeyError) as exc:
        raise CliError(f"fetch failed: {exc}") from exc


def cmd_score(args: argparse.Namespace) -> None:
    results, _ = _prepare(args, _names(args.framework))
    for cov in results.values():
        _print_summary(cov)
    _write(Path(args.out), _coverage_json(results))
    print(f"wrote {args.out}")


def cmd_layer(args: argparse.Namespace) -> None:
    cov = _prepare(args, ["attack"])[0]["attack"]
    layer = build_layer(cov, name=args.name)
    _write(Path(args.out), json.dumps(layer, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {args.out}")


def cmd_render(args: argparse.Namespace) -> None:
    cov = _prepare(args, [args.framework])[0][args.framework]
    _write(Path(args.out), render_svg(cov))
    print(f"wrote {args.out}")


def cmd_html(args: argparse.Namespace) -> None:
    results, rules = _prepare(args, ["attack", "atlas"])
    _write(Path(args.out), render_html(results, rules, title=args.title))
    print(f"wrote {args.out}")


def cmd_report(args: argparse.Namespace) -> None:
    results, rules = _prepare(args, ["attack", "atlas"])
    out = Path(args.out_dir)
    for cov in results.values():
        _print_summary(cov)
    _write(out / "coverage.json", _coverage_json(results))
    layer = build_layer(results["attack"], name=args.name)
    _write(out / "attack-layer.json", json.dumps(layer, indent=2, ensure_ascii=False) + "\n")
    _write(out / "coverage-attack.svg", render_svg(results["attack"]))
    _write(out / "coverage-atlas.svg", render_svg(results["atlas"]))
    _write(out / "report.html", render_html(results, rules, title=args.title))
    print(f"wrote coverage.json, attack-layer.json, coverage-attack.svg, coverage-atlas.svg, report.html to {out}")


def _keep_rows(path: str | None) -> dict[str, dict[str, str]]:
    if not path:
        return {}
    import csv

    try:
        with open(path, newline="", encoding="utf-8-sig") as fh:
            return {row["rule_id"]: row for row in csv.DictReader(fh) if row.get("rule_id")}
    except (OSError, KeyError) as exc:
        raise CliError(f"cannot read --keep-from {path}: {exc}") from exc


def cmd_import(args: argparse.Namespace) -> None:
    try:
        mapped, unmapped, warnings = importers.run_import(args.siem, args.export, args.data_sources)
    except importers.ExportError as exc:
        raise CliError(str(exc)) from exc
    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)
    rows = importers.to_rows(mapped, _keep_rows(args.keep_from))
    try:
        importers.write_csv(rows, Path(args.out))
    except OSError as exc:
        raise CliError(f"cannot write {args.out}: {exc}") from exc
    enabled = sum(r.enabled for r in mapped)
    dead = sum(r.enabled and not r.data_available for r in mapped)
    print(f"{args.siem}: {len(mapped) + len(unmapped)} rules read, {len(mapped)} mapped to ATT&CK/ATLAS, "
          f"{len(unmapped)} without a technique id")
    print(f"  enabled: {enabled}  enabled without data: {dead}")
    print(f"wrote {args.out}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="coveragekit",
        description="Measure SIEM detection coverage against MITRE ATT&CK and MITRE ATLAS.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--rules", required=True, nargs="+", help="rule inventory (.csv or .json); several files are merged"
        )
        p.add_argument("--frameworks-dir", help="directory with maps written by 'coveragekit fetch'")

    p = sub.add_parser("fetch", help="download ATT&CK and ATLAS and write the minimal maps")
    p.add_argument("--dest", required=True, help="output directory")
    p.set_defaults(func=cmd_fetch)

    p = sub.add_parser("import", help="convert a SIEM rule export into a rule inventory CSV")
    p.add_argument("siem", choices=sorted(importers.IMPORTERS), help="where the export comes from")
    p.add_argument("--export", required=True, help="export file or directory (see README for each SIEM)")
    p.add_argument("--data-sources", help="sources with recent events (CSV or one per line)")
    p.add_argument("--keep-from", help="previous inventory CSV: keep its tested, tuned and owner columns")
    p.add_argument("--out", required=True, help="output inventory CSV")
    p.set_defaults(func=cmd_import)

    p = sub.add_parser("score", help="score coverage and write coverage.json")
    common(p)
    p.add_argument("--framework", choices=["attack", "atlas", "both"], default="both")
    p.add_argument("--out", required=True, help="output JSON file")
    p.set_defaults(func=cmd_score)

    p = sub.add_parser("layer", help="export an ATT&CK Navigator layer")
    common(p)
    p.add_argument("--out", required=True, help="output layer JSON file")
    p.add_argument("--name", default="SIEM detection coverage", help="layer name")
    p.set_defaults(func=cmd_layer)

    p = sub.add_parser("render", help="render an SVG heat map")
    common(p)
    p.add_argument("--framework", choices=["attack", "atlas"], default="attack")
    p.add_argument("--out", required=True, help="output SVG file")
    p.set_defaults(func=cmd_render)

    p = sub.add_parser("html", help="write a self-contained HTML report with statistics and recommendations")
    common(p)
    p.add_argument("--out", required=True, help="output HTML file")
    p.add_argument("--title", default="Detection coverage report", help="report title")
    p.set_defaults(func=cmd_html)

    p = sub.add_parser("report", help="write coverage.json, the layer, both SVGs and the HTML report")
    common(p)
    p.add_argument("--out-dir", required=True, help="output directory")
    p.add_argument("--name", default="SIEM detection coverage", help="layer name")
    p.add_argument("--title", default="Detection coverage report", help="HTML report title")
    p.set_defaults(func=cmd_report)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

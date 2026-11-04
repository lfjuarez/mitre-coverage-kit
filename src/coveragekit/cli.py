"""Command line interface: ``coveragekit``."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from . import __version__, connectors, frameworks, importers
from .diff import diff, format_diff
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
    _snapshot(args.history, _coverage_json(results))


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
    _snapshot(args.history, _coverage_json(results))


def _keep_rows(path: str | None) -> dict[str, dict[str, str]]:
    if not path:
        return {}
    import csv

    try:
        with open(path, newline="", encoding="utf-8-sig") as fh:
            return {row["rule_id"]: row for row in csv.DictReader(fh) if row.get("rule_id")}
    except (OSError, KeyError) as exc:
        raise CliError(f"cannot read --keep-from {path}: {exc}") from exc


def _import_to_csv(
    siem: str, export: Path | str, data_sources: Path | str | None, keep_from: str | None, out: str
) -> None:
    try:
        mapped, unmapped, warnings = importers.run_import(siem, export, data_sources)
    except importers.ExportError as exc:
        raise CliError(str(exc)) from exc
    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)
    rows = importers.to_rows(mapped, _keep_rows(keep_from))
    try:
        importers.write_csv(rows, Path(out))
    except OSError as exc:
        raise CliError(f"cannot write {out}: {exc}") from exc
    enabled = sum(r.enabled for r in mapped)
    dead = sum(r.enabled and not r.data_available for r in mapped)
    print(
        f"{siem}: {len(mapped) + len(unmapped)} rules read, {len(mapped)} mapped to ATT&CK/ATLAS, "
        f"{len(unmapped)} without a technique id"
    )
    print(f"  enabled: {enabled}  enabled without data: {dead}")
    print(f"wrote {out}")


def cmd_import(args: argparse.Namespace) -> None:
    _import_to_csv(args.siem, args.export, args.data_sources, args.keep_from, args.out)


def cmd_pull(args: argparse.Namespace) -> None:
    if args.insecure:
        print("warning: TLS certificate verification is disabled", file=sys.stderr)
    http = connectors.Http(verify=not args.insecure, ca=args.ca)
    temp = None if args.save_exports else tempfile.mkdtemp(prefix="coveragekit-")
    out_dir = Path(args.save_exports or temp)
    try:
        try:
            if args.siem == "splunk":
                export, active = connectors.pull_splunk(args.url, out_dir, days=args.days, http=http)
            elif args.siem == "elastic":
                export, active = connectors.pull_elastic(
                    args.url, out_dir, es_url=args.es_url, days=args.days, indices=args.indices, http=http
                )
            else:
                export, active = connectors.pull_wazuh(
                    args.url, out_dir, indexer_url=args.indexer_url, days=args.days, http=http
                )
        except connectors.ConnectorError as exc:
            raise CliError(str(exc)) from exc
        if active is None:
            flag = "--es-url" if args.siem == "elastic" else "--indexer-url"
            print(f"warning: pass {flag} to check which rules have data", file=sys.stderr)
        _import_to_csv(args.siem, export, active, args.keep_from, args.out)
        if args.save_exports:
            print(f"exports saved in {out_dir}")
    finally:
        if temp:
            shutil.rmtree(temp, ignore_errors=True)


def cmd_diff(args: argparse.Namespace) -> None:
    try:
        before = json.loads(Path(args.before).read_text(encoding="utf-8"))
        after = json.loads(Path(args.after).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CliError(f"cannot read coverage file: {exc}") from exc
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise CliError("both files must be coverage.json files written by coveragekit")
    result = diff(before, after)
    print(format_diff(result))
    if args.out:
        _write(Path(args.out), json.dumps(result, indent=2, ensure_ascii=False) + "\n")
        print(f"wrote {args.out}")


def _snapshot(history: str | None, payload: str) -> None:
    if history:
        stamp = dt.datetime.now().strftime("%Y-%m-%dT%H%M")
        path = Path(history) / f"coverage-{stamp}.json"
        _write(path, payload)
        print(f"wrote {path}")


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

    p = sub.add_parser("pull", help="read the rules and the active data sources straight from a SIEM (read-only)")
    p.add_argument("siem", choices=sorted(connectors.CONNECTORS), help="which connector to use")
    p.add_argument(
        "--url", required=True, help="Splunk management URL (port 8089), Kibana URL, or Wazuh API URL (port 55000)"
    )
    p.add_argument("--es-url", help="Elasticsearch URL, to check which indices have data (elastic)")
    p.add_argument("--indexer-url", help="Wazuh indexer URL, to check which rule groups have alerts (wazuh)")
    p.add_argument("--indices", default="logs-*,*beat-*", help="index patterns to check for data (elastic)")
    p.add_argument("--days", type=int, default=7, help="a source counts as active if it has events in the last N days")
    p.add_argument("--save-exports", metavar="DIR", help="keep the raw exports in this directory")
    p.add_argument("--ca", metavar="FILE", help="CA bundle for the SIEM's TLS certificate")
    p.add_argument("--insecure", action="store_true", help="skip TLS verification (labs only)")
    p.add_argument("--keep-from", help="previous inventory CSV: keep its tested, tuned and owner columns")
    p.add_argument("--out", required=True, help="output inventory CSV")
    p.set_defaults(func=cmd_pull)

    p = sub.add_parser("score", help="score coverage and write coverage.json")
    common(p)
    p.add_argument("--framework", choices=["attack", "atlas", "both"], default="both")
    p.add_argument("--out", required=True, help="output JSON file")
    p.add_argument("--history", metavar="DIR", help="also save a dated copy of coverage.json here")
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
    p.add_argument("--history", metavar="DIR", help="also save a dated copy of coverage.json here")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("diff", help="compare two coverage.json files")
    p.add_argument("before", help="older coverage.json")
    p.add_argument("after", help="newer coverage.json")
    p.add_argument("--out", help="write the comparison as JSON")
    p.set_defaults(func=cmd_diff)
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

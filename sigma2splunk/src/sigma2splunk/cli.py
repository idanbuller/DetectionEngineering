from __future__ import annotations

import argparse
import os
import re
import sys
from typing import List, Optional

import yaml

from . import __version__
from .convert import CONVERTED, Conversion, convert_rule
from .errors import UnsupportedSigma
from .inventory import load_inventory
from .mapping import load_mapping
from .report import report_json, report_text
from .sigma import SigmaError, discover, load_rules

EXIT_OK, EXIT_PROBLEM, EXIT_ERROR = 0, 1, 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sigma2splunk",
        description="Convert Sigma rules to Splunk SPL and detection-as-code, only for the data you collect.",
    )
    p.add_argument("--version", action="version", version=f"sigma2splunk {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("convert", help="convert Sigma rules")
    c.add_argument("paths", nargs="+", help="Sigma rule files or directories")
    c.add_argument("--mapping", help="a logsource/field mapping file (default: a small built-in mapping)")
    c.add_argument("--inventory", help="index/sourcetype you collect (also accepts a detcov health file)")
    c.add_argument("--only-available", action="store_true", help="skip rules whose data isn't in the inventory")
    c.add_argument("-o", "--out", help="write one detection file per converted rule into this directory")
    c.add_argument("-f", "--format", choices=["spl", "yaml", "json"], default="spl", help="stdout format (no -o)")
    c.add_argument("--no-strict-lint", action="store_true", help="emit rules even if spl-lint finds an error")
    c.add_argument("-v", "--verbose", action="store_true", help="list converted rules too, with notes")
    c.add_argument("--fail-on-unsupported", action="store_true", help="exit 1 if any rule could not be converted")
    return p


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_") or "detection"


def cmd_convert(args) -> int:
    try:
        mapping = load_mapping(args.mapping)
        inventory = load_inventory(args.inventory) if args.inventory else None
    except (OSError, ValueError, yaml.YAMLError) as exc:
        sys.stderr.write(f"sigma2splunk: {exc}\n")
        return EXIT_ERROR
    if args.only_available and not inventory:
        sys.stderr.write("sigma2splunk: --only-available needs --inventory\n")
        return EXIT_ERROR

    results: List[Conversion] = []
    for path in discover(args.paths):
        try:
            rules = load_rules(path)
        except SigmaError as exc:
            sys.stderr.write(f"sigma2splunk: skipping {path}: {exc}\n")
            continue
        for rule in rules:
            try:
                results.append(
                    convert_rule(rule, mapping, inventory, args.only_available, strict_lint=not args.no_strict_lint)
                )
            except UnsupportedSigma as exc:
                from .convert import UNSUPPORTED

                results.append(Conversion(rule, UNSUPPORTED, reason=str(exc)))

    converted = [r for r in results if r.status == CONVERTED]
    if args.out:
        _write_out(converted, args.out)
        report_text(results, sys.stderr, color=sys.stderr.isatty(), verbose=args.verbose)
    elif args.format == "json":
        report_json(results, sys.stdout)
    elif args.format == "yaml":
        docs = [r.detection for r in converted]
        sys.stdout.write(yaml.safe_dump_all(docs, sort_keys=False) if docs else "")
        report_text(results, sys.stderr, color=sys.stderr.isatty(), verbose=args.verbose)
    else:  # spl
        for r in converted:
            sys.stdout.write(f"# {r.rule.title}\n{r.spl}\n\n")
        report_text(results, sys.stderr, color=sys.stderr.isatty(), verbose=args.verbose)

    if args.fail_on_unsupported and any(r.status != CONVERTED and r.status != "filtered" for r in results):
        return EXIT_PROBLEM
    return EXIT_OK


def _write_out(converted: List[Conversion], out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    seen = set()
    for r in converted:
        base = _slug(r.rule.title)
        name = base
        n = 2
        while name in seen:
            name, n = f"{base}_{n}", n + 1
        seen.add(name)
        with open(os.path.join(out_dir, f"{name}.yml"), "w", encoding="utf-8") as fh:
            fh.write(yaml.safe_dump(r.detection, sort_keys=False, width=1000))


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "convert":
        return cmd_convert(args)
    return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())

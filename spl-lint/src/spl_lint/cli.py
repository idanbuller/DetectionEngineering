from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

import yaml

from . import __version__
from .config import Config, find_config, load_config
from .linter import Result, lint_source
from .reporters import REPORTERS
from .rules import Severity, all_rules
from .sources import QuerySource, iter_files, line_map, read_sources

EXIT_OK, EXIT_FINDINGS, EXIT_USAGE = 0, 1, 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="spl-lint",
        description="Lint Splunk SPL for correctness traps and performance problems.",
    )
    p.add_argument(
        "paths", nargs="*", help="files or directories (.spl, .yml/.yaml, savedsearches.conf); '-' for stdin"
    )
    p.add_argument("-f", "--format", choices=sorted(REPORTERS), default="text", help="output format (default: text)")
    p.add_argument("--select", help="comma-separated rule ids, prefixes, names or categories to enable")
    p.add_argument("--ignore", help="comma-separated rule ids, prefixes, names or categories to disable")
    p.add_argument("--fail-on", help="lowest severity that makes the exit code 1 (default: warning)")
    p.add_argument("--yaml-keys", help="comma-separated YAML keys that hold SPL (default: search,spl,query)")
    p.add_argument("--config", help="config file (default: nearest .spl-lint.yml)")
    p.add_argument("--no-config", action="store_true", help="ignore config files")
    p.add_argument("--color", choices=["auto", "always", "never"], default="auto")
    p.add_argument("--list-rules", action="store_true", help="list rules and exit")
    p.add_argument("--explain", metavar="RULE", help="explain a rule (id or name) and exit")
    p.add_argument("--version", action="version", version=f"spl-lint {__version__}")
    return p


def _resolve_config(args) -> Config:
    if args.no_config:
        cfg = Config()
    else:
        cfg = load_config(args.config or find_config(os.getcwd()))
    if args.select:
        cfg.select = [s for s in args.select.split(",") if s.strip()]
    if args.ignore:
        cfg.ignore += [s for s in args.ignore.split(",") if s.strip()]
    if args.fail_on:
        cfg.fail_on = Severity.parse(args.fail_on)
    if args.yaml_keys:
        cfg.yaml_keys = [s.strip() for s in args.yaml_keys.split(",") if s.strip()]
    return cfg


def _list_rules(out) -> None:
    for r in all_rules():
        out.write(f"{r.id}  {r.name:<30} {str(r.severity):<8} {r.summary}\n")


def _explain(key: str, out) -> int:
    for r in all_rules():
        if key.upper() == r.id or key.lower() == r.name:
            out.write(f"{r.id} {r.name} ({r.category}, default severity: {r.severity})\n\n")
            out.write(f"{r.summary}\n\n{r.doc()}\n\nBad:\n\n")
            out.write("".join(f"    {line}\n" for line in r.bad.splitlines()))
            out.write("\nGood:\n\n")
            out.write("".join(f"    {line}\n" for line in r.good.splitlines()))
            return EXIT_OK
    sys.stderr.write(f"spl-lint: unknown rule {key!r}\n")
    return EXIT_USAGE


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    out = sys.stdout
    if args.list_rules:
        _list_rules(out)
        return EXIT_OK
    if args.explain:
        return _explain(args.explain, out)

    try:
        cfg = _resolve_config(args)
    except (ValueError, OSError, yaml.YAMLError) as exc:
        sys.stderr.write(f"spl-lint: config error: {exc}\n")
        return EXIT_USAGE

    paths = args.paths or (["-"] if not sys.stdin.isatty() else [])
    if not paths:
        build_parser().print_usage(sys.stderr)
        sys.stderr.write("spl-lint: no paths given\n")
        return EXIT_USAGE

    results: List[Result] = []
    files = queries = 0
    errors = False
    for path in iter_files([p for p in paths if p != "-"], cfg.exclude):
        try:
            with open(path, encoding="utf-8") as fh:
                content = fh.read()
            sources = read_sources(path, content, cfg.yaml_keys)
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
            sys.stderr.write(f"spl-lint: {path}: {exc}\n")
            errors = True
            continue
        files += 1
        for source in sources:
            queries += 1
            results.extend(lint_source(source, cfg))
    if "-" in paths:
        text = sys.stdin.read()
        files += 1
        queries += 1
        results.extend(lint_source(QuerySource("-", text, None, line_map(text, 1, 1, 1)), cfg))

    color = args.color == "always" or (args.color == "auto" and out.isatty() and "NO_COLOR" not in os.environ)
    REPORTERS[args.format](results, out, color=color, files=files, queries=queries)

    if errors:
        return EXIT_USAGE
    if any(r.finding.severity >= cfg.fail_on for r in results):
        return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())

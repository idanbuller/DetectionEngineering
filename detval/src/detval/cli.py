from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from . import __version__
from .casespec import CaseError, discover, load_case
from .executors import atomic_command
from .report import navigator_layer, report_json, report_text, write_junit
from .runner import CaseResult, run_case
from .splunk import SplunkClient, SplunkError

EXIT_OK, EXIT_FAILED, EXIT_ERROR = 0, 1, 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="detval",
        description="Continuous detection validation: run ATT&CK techniques and confirm Splunk detects them.",
    )
    p.add_argument("--version", action="version", version=f"detval {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    ls = sub.add_parser("list", help="list cases and how each one would execute")
    ls.add_argument("paths", nargs="+")

    for cmd in ("run", "verify"):
        sp = sub.add_parser(
            cmd,
            help="execute cases and verify detection" if cmd == "run" else "verify detection only (never executes)",
        )
        sp.add_argument("paths", nargs="+", help="*.case.yml files or directories")
        sp.add_argument("--splunk-url", default=os.environ.get("SPLUNK_URL"))
        sp.add_argument("--token-env", default="SPLUNK_TOKEN")
        sp.add_argument("--username", default=os.environ.get("SPLUNK_USERNAME"))
        sp.add_argument("--password-env", default="SPLUNK_PASSWORD")
        sp.add_argument("--insecure", action="store_true")
        sp.add_argument("-f", "--format", choices=["text", "json"], default="text")
        sp.add_argument("--junit")
        sp.add_argument("--layer", help="write an ATT&CK Navigator layer here")
        sp.add_argument("-v", "--verbose", action="store_true")
        if cmd == "run":
            sp.add_argument(
                "--allow-execution",
                action="store_true",
                help="actually run command/atomic executors (only for cases marked authorized: true)",
            )
            sp.add_argument("--assume-executed", action="store_true", help="treat manual cases as already executed")

    lay = sub.add_parser("layer", help="build an ATT&CK Navigator layer from a JSON results file")
    lay.add_argument("results", help="a detval JSON report (from run/verify -f json), or - for stdin")
    lay.add_argument("--name", default="detval coverage")
    return p


def _client(args) -> SplunkClient:
    if not args.splunk_url:
        raise SplunkError("set --splunk-url or $SPLUNK_URL (the management port, usually 8089)")
    return SplunkClient(
        args.splunk_url,
        token=os.environ.get(args.token_env),
        username=args.username,
        password=os.environ.get(args.password_env),
        verify_tls=not args.insecure,
    )


def _load_all(paths: List[str]) -> List:
    files = discover(paths)
    if not files:
        raise CaseError("no *.case.yml files found")
    return [load_case(f) for f in files]


def _emit(results: List[CaseResult], args) -> int:
    if args.format == "json":
        report_json(results, sys.stdout)
    else:
        color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
        report_text(results, sys.stdout, color=color, verbose=args.verbose)
    if args.junit:
        write_junit(results, args.junit)
    if args.layer:
        with open(args.layer, "w", encoding="utf-8") as fh:
            json.dump(navigator_layer(results), fh, indent=2)
    if any(r.status == "error" for r in results):
        return EXIT_ERROR
    return EXIT_OK if all(r.status in ("pass", "blocked") for r in results) else EXIT_FAILED


def cmd_list(args) -> int:
    for case in _load_all(args.paths):
        ex = case.execute
        planned = ""
        if ex.executor == "command" and ex.command:
            planned = f"  cmd: {ex.command}"
        elif ex.atomic_guid or ex.atomic_test:
            planned = f"  atomic: {atomic_command(ex, case.technique)}"
        auth = "authorized" if case.authorized else "not authorized"
        sys.stdout.write(f"{case.technique:12} {ex.executor:8} [{auth}] {case.name}{planned}\n")
    return EXIT_OK


def _run(args, allow_execution: bool) -> int:
    client = _client(args)
    confirm = None
    if getattr(args, "assume_executed", False):
        confirm = lambda _prompt: True  # noqa: E731
    results = [
        run_case(case, client.search, allow_execution=allow_execution, confirm=confirm)
        for case in _load_all(args.paths)
    ]
    return _emit(results, args)


def cmd_run(args) -> int:
    return _run(args, allow_execution=args.allow_execution)


def cmd_verify(args) -> int:
    return _run(args, allow_execution=False)


def cmd_layer(args) -> int:
    text = sys.stdin.read() if args.results == "-" else open(args.results, encoding="utf-8").read()
    data = json.loads(text)
    # Rebuild lightweight CaseResults isn't needed; the JSON already has status per technique.
    from collections import defaultdict

    groups = defaultdict(list)
    for item in data:
        groups[item["technique"]].append(item["status"])
    from .report import _LAYER_COLORS

    order = {"error": 0, "fail": 1, "blocked": 2, "pass": 3}
    techniques = []
    for tech, statuses in sorted(groups.items()):
        worst = min(statuses, key=lambda s: order.get(s, 0))
        passed = sum(1 for s in statuses if s == "pass")
        techniques.append(
            {
                "techniqueID": tech,
                "color": _LAYER_COLORS.get(worst, "#888888"),
                "comment": f"detval: {passed}/{len(statuses)} case(s) validated",
                "metadata": [{"name": "status", "value": worst}],
            }
        )
    layer = {
        "name": args.name,
        "versions": {"layer": "4.5", "navigator": "4.9.1", "attack": "15"},
        "domain": "enterprise-attack",
        "techniques": techniques,
        "legendItems": [{"label": k, "color": v} for k, v in _LAYER_COLORS.items()],
    }
    json.dump(layer, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return EXIT_OK


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {"list": cmd_list, "run": cmd_run, "verify": cmd_verify, "layer": cmd_layer}
    try:
        return handlers[args.command](args)
    except (CaseError, SplunkError, ValueError, OSError) as exc:
        sys.stderr.write(f"detval: {exc}\n")
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())

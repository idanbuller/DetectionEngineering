from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from . import __version__
from .report import report_json, report_text, write_junit
from .runner import DEFAULT_MAX_EVENTS, prepare, run_test, score_saved
from .splunk import SplunkClient, SplunkError, load_results
from .testspec import SpecFileError, discover, load_test

EXIT_OK, EXIT_FAILED, EXIT_ERROR = 0, 1, 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="spltest",
        description="Test Splunk detections against synthetic datasets with known attacks and benign look-alikes.",
    )
    p.add_argument("--version", action="version", version=f"spltest {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp):
        sp.add_argument("--max-events", type=int, default=DEFAULT_MAX_EVENTS, help="inline dataset size limit")

    run = sub.add_parser("run", help="run tests on Splunk over REST and score them")
    run.add_argument("paths", nargs="+", help="*.test.yml files or directories")
    run.add_argument("--splunk-url", default=os.environ.get("SPLUNK_URL"), help="e.g. https://splunk:8089")
    run.add_argument("--token-env", default="SPLUNK_TOKEN", help="env var with a Splunk auth token")
    run.add_argument("--username", default=os.environ.get("SPLUNK_USERNAME"))
    run.add_argument("--password-env", default="SPLUNK_PASSWORD", help="env var with the password")
    run.add_argument("--insecure", action="store_true", help="skip TLS verification")
    run.add_argument("-f", "--format", choices=["text", "json"], default="text")
    run.add_argument("--junit", help="also write a JUnit XML report here")
    run.add_argument("-v", "--verbose", action="store_true", help="show hints and row counts for passing tests too")
    common(run)

    comp = sub.add_parser("compose", help="print the search a test would run (paste it into Splunk)")
    comp.add_argument("test")
    common(comp)

    sc = sub.add_parser("score", help="score results that were saved from a Splunk run of `compose` output")
    sc.add_argument("test")
    sc.add_argument("--results", required=True, help="JSON list of rows, {results: [...]}, or export JSON lines")
    sc.add_argument("-f", "--format", choices=["text", "json"], default="text")
    sc.add_argument("--junit")
    sc.add_argument("-v", "--verbose", action="store_true")
    common(sc)
    return p


def _report(results, args) -> int:
    if args.format == "json":
        report_json(results, sys.stdout)
    else:
        color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
        report_text(results, sys.stdout, color=color, verbose=args.verbose)
    if args.junit:
        write_junit(results, args.junit)
    if any(r.error for r in results):
        return EXIT_ERROR
    return EXIT_OK if all(r.passed for r in results) else EXIT_FAILED


def cmd_run(args) -> int:
    if not args.splunk_url:
        raise SplunkError("set --splunk-url or $SPLUNK_URL (the management port, usually 8089)")
    client = SplunkClient(
        args.splunk_url,
        token=os.environ.get(args.token_env),
        username=args.username,
        password=os.environ.get(args.password_env),
        verify_tls=not args.insecure,
    )
    paths = discover(args.paths)
    if not paths:
        raise SpecFileError("no *.test.yml files found")
    results = [run_test(load_test(p), client.search, args.max_events) for p in paths]
    return _report(results, args)


def cmd_compose(args) -> int:
    test = load_test(args.test)
    _, composed = prepare(test, args.max_events)
    for note in composed.notes:
        sys.stderr.write(f"note: {note}\n")
    sys.stdout.write(composed.search + "\n")
    return EXIT_OK


def cmd_score(args) -> int:
    test = load_test(args.test)
    rows = load_results(args.results)
    return _report([score_saved(test, rows, args.max_events)], args)


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return {"run": cmd_run, "compose": cmd_compose, "score": cmd_score}[args.command](args)
    except (SpecFileError, SplunkError, ValueError, OSError) as exc:
        sys.stderr.write(f"spltest: {exc}\n")
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())

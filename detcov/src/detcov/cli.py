from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from . import __version__
from .catalog import CatalogError, load_catalog
from .coverage import AT_RISK, BROKEN, NO_DATA, build, load_detval_results, summary
from .health import HealthError, empty, from_splunk, load_health_file
from .report import navigator_layer, report_json, report_text

EXIT_OK, EXIT_GAPS, EXIT_ERROR = 0, 1, 2
_UNITS = {"m": 60, "h": 3600, "d": 86400, "w": 604800}


def _seconds(text: str) -> float:
    text = str(text).strip()
    if text[-1:] in _UNITS:
        return float(text[:-1]) * _UNITS[text[-1]]
    return float(text)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="detcov",
        description="Build an honest ATT&CK coverage map: rule presence x data health x validation.",
    )
    p.add_argument("--version", action="version", version=f"detcov {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser("report", help="build the coverage map")
    r.add_argument("catalog", nargs="+", help="detection files or directories")
    r.add_argument("--detval", help="a detval JSON report, to fold in validation results")
    r.add_argument("--health", help="a health file (JSON/YAML) of index/sourcetype freshness")
    r.add_argument("--splunk-url", default=os.environ.get("SPLUNK_URL"), help="compute health live from Splunk")
    r.add_argument("--token-env", default="SPLUNK_TOKEN")
    r.add_argument("--username", default=os.environ.get("SPLUNK_USERNAME"))
    r.add_argument("--password-env", default="SPLUNK_PASSWORD")
    r.add_argument("--insecure", action="store_true")
    r.add_argument("--lookback", default="-30d", help="how far back to look for data when computing health")
    r.add_argument("--freshness", default="24h", help="data newer than this is healthy (e.g. 24h, 3d)")
    r.add_argument("-f", "--format", choices=["text", "json"], default="text")
    r.add_argument("--layer", help="write an ATT&CK Navigator layer here")
    r.add_argument("--layer-name", default="detcov coverage")
    r.add_argument("-v", "--verbose", action="store_true")
    r.add_argument(
        "--fail-on",
        default="none",
        choices=["none", "at_risk", "broken"],
        help="exit 1 when techniques land in this tier or worse (default none)",
    )

    lay = sub.add_parser("layer", help="build a Navigator layer from a detcov JSON report")
    lay.add_argument("report", help="a detcov JSON report, or - for stdin")
    lay.add_argument("--name", default="detcov coverage")
    return p


def _health(args):
    freshness = _seconds(args.freshness)
    if args.health:
        return load_health_file(args.health, freshness)
    if args.splunk_url:
        return from_splunk(
            args.splunk_url,
            token=os.environ.get(args.token_env),
            username=args.username,
            password=os.environ.get(args.password_env),
            verify_tls=not args.insecure,
            lookback=args.lookback,
            freshness_seconds=freshness,
        )
    return empty(freshness)


def cmd_report(args) -> int:
    detections = load_catalog(args.catalog)
    if not detections:
        raise CatalogError("no detections found in the given paths")
    validation = load_detval_results(args.detval) if args.detval else None
    coverage = build(detections, _health(args), validation)

    if args.format == "json":
        report_json(coverage, sys.stdout)
    else:
        color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
        report_text(coverage, sys.stdout, color=color, verbose=args.verbose)
    if args.layer:
        with open(args.layer, "w", encoding="utf-8") as fh:
            json.dump(navigator_layer(coverage, args.layer_name), fh, indent=2)
        sys.stderr.write(f"wrote {args.layer}\n")

    counts = summary(coverage)
    if args.fail_on == "broken" and counts[BROKEN]:
        return EXIT_GAPS
    if args.fail_on == "at_risk" and (counts[BROKEN] or counts[NO_DATA] or counts[AT_RISK]):
        return EXIT_GAPS
    return EXIT_OK


def cmd_layer(args) -> int:
    from .coverage import TechniqueCoverage
    from .report import navigator_layer as build_layer

    text = sys.stdin.read() if args.report == "-" else open(args.report, encoding="utf-8").read()
    data = json.loads(text)
    coverage = [
        TechniqueCoverage(
            technique=d["technique"],
            tier=d["tier"],
            rule_count=d.get("rule_count", 0),
            data_status=d.get("data_status", "unknown"),
            validated=d.get("validated"),
            detections=d.get("detections", []),
            reason=d.get("reason", ""),
        )
        for d in data
    ]
    json.dump(build_layer(coverage, args.name), sys.stdout, indent=2)
    sys.stdout.write("\n")
    return EXIT_OK


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return {"report": cmd_report, "layer": cmd_layer}[args.command](args)
    except (CatalogError, HealthError, ValueError, OSError) as exc:
        sys.stderr.write(f"detcov: {exc}\n")
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())

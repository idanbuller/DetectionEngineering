from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from typing import List, Optional

from . import __version__, outputs, render
from .engine import Dataset, generate
from .generators import SpecError, Template
from .infer import infer_spec, load_samples
from .spec import DatasetSpec, load_spec, parse_duration, parse_time

EXIT_OK, EXIT_ERROR = 0, 2


def _add_spec_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("spec", help="dataset spec (YAML)")
    p.add_argument("--seed", type=int, help="override the spec's seed")
    p.add_argument("--start", help="override the start time (ISO 8601, or now-24h)")
    p.add_argument("--duration", help="override the duration (e.g. 6h, 7d)")
    p.add_argument("--no-background", action="store_true", help="only emit scenario events")
    p.add_argument("--label-field", help="add a field naming the scenario that produced each event")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="synthlog",
        description="Generate realistic synthetic logs with injected attack scenarios and ground truth.",
    )
    p.add_argument("--version", action="version", version=f"synthlog {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    g = sub.add_parser("generate", help="write events to files (one per source) plus truth.json")
    _add_spec_args(g)
    g.add_argument("-o", "--out", default="synthlog-out", help="output directory (default: synthlog-out)")

    s = sub.add_parser("spl", help="print a | makeresults search that recreates the events inside Splunk")
    _add_spec_args(s)
    s.add_argument("--source", action="append", help="only include this source (repeatable)")
    s.add_argument("--max-events", type=int, default=2000, help="refuse to build bigger searches (default 2000)")

    h = sub.add_parser("hec", help="send events to Splunk's HTTP Event Collector")
    _add_spec_args(h)
    h.add_argument("--url", required=True, help="HEC base URL, e.g. https://splunk:8088")
    h.add_argument("--token-env", default="SPLUNK_HEC_TOKEN", help="env var holding the HEC token")
    h.add_argument("--insecure", action="store_true", help="skip TLS certificate verification")
    h.add_argument("--batch-size", type=int, default=500)

    v = sub.add_parser("preview", help="print a few events per source and the scenario summary")
    _add_spec_args(v)
    v.add_argument("-n", type=int, default=3, help="events per source (default 3)")

    c = sub.add_parser("validate", help="check a spec and summarize what it would generate")
    c.add_argument("spec")

    i = sub.add_parser("infer", help="draft a spec from sample JSON events")
    i.add_argument("samples", nargs="+", help=".json / .jsonl sample files")
    i.add_argument("--name", default="source", help="source name in the spec")
    i.add_argument("--sourcetype")
    i.add_argument("--index")
    i.add_argument("--max-enum", type=int, default=20, help="max distinct values to keep as an enumeration")
    i.add_argument(
        "--no-values", action="store_true", help="copy no sample values (numeric fields keep their min/max range)"
    )
    i.add_argument("-o", "--out", help="write the spec here instead of stdout")
    return p


def _load(args) -> DatasetSpec:
    spec = load_spec(args.spec)
    if getattr(args, "seed", None) is not None:
        spec.seed = args.seed
    if getattr(args, "duration", None):
        spec.duration = parse_duration(args.duration, "--duration")
    if getattr(args, "start", None):
        spec.start = parse_time(args.start, "--start")
    return spec


def _dataset(args) -> Dataset:
    return generate(_load(args), include_background=not args.no_background)


def _summary(dataset: Dataset, out) -> None:
    spec = dataset.spec
    end = spec.start + spec.duration
    out.write(f"{spec.start:%Y-%m-%d %H:%M} to {end:%Y-%m-%d %H:%M} UTC, seed {spec.seed}\n")
    for name, events in dataset.events.items():
        injected = sum(1 for e in events if e.scenario)
        extra = f" ({injected} from scenarios)" if injected else ""
        out.write(f"  {name}: {len(events)} events{extra}\n")
    for t in dataset.truth:
        counts = ", ".join(f"{n} {s}" for s, n in t["events"].items())
        out.write(f"  scenario {t['scenario']}#{t['instance']} [{t['label']}] {t['start']} ({counts})\n")


def cmd_generate(args) -> int:
    dataset = _dataset(args)
    paths = outputs.write_files(dataset, args.out, args.label_field)
    _summary(dataset, sys.stderr)
    for path in paths:
        sys.stderr.write(f"wrote {path}\n")
    return EXIT_OK


def cmd_spl(args) -> int:
    dataset = _dataset(args)
    wanted = set(args.source or [])
    unknown = wanted - set(dataset.spec.sources)
    if unknown:
        raise SpecError("--source", f"unknown source(s): {', '.join(sorted(unknown))}")
    n = sum(len(ev) for name, ev in dataset.events.items() if not wanted or name in wanted)
    if n > args.max_events:
        raise SpecError(
            "",
            f"{n} events is too many for one inline search (limit {args.max_events}); "
            "use --no-background, a shorter --duration, or the hec command",
        )
    sys.stdout.write(outputs.makeresults_search(dataset, sorted(wanted) or None, args.label_field) + "\n")
    return EXIT_OK


def cmd_hec(args) -> int:
    token = os.environ.get(args.token_env)
    if not token:
        raise SpecError("", f"set the HEC token in ${args.token_env}")
    dataset = _dataset(args)
    sent = outputs.send_hec(dataset, args.url, token, not args.insecure, args.label_field, args.batch_size)
    _summary(dataset, sys.stderr)
    sys.stderr.write(f"sent {sent} events to {args.url}\n")
    return EXIT_OK


def cmd_preview(args) -> int:
    dataset = _dataset(args)
    out = sys.stdout
    for name, events in dataset.events.items():
        source = dataset.spec.sources[name]
        template = Template(source.raw) if source.raw else None
        out.write(f"== {name} ({len(events)} events)\n")
        for e in events[: args.n]:
            if template:
                out.write(render.raw_line(e, source, template, args.label_field) + "\n")
            else:
                out.write(json.dumps(render.fields(e, source, args.label_field), ensure_ascii=False) + "\n")
    out.write("\n")
    _summary(dataset, out)
    return EXIT_OK


def cmd_validate(args) -> int:
    spec = load_spec(args.spec)
    dataset = generate(spec, include_background=False)  # also exercises every scenario
    sys.stdout.write(f"{args.spec}: ok\n")
    for name, source in spec.sources.items():
        total = (
            source.events
            if source.events is not None
            else round(source.rate_per_second * spec.duration.total_seconds())
        )
        sys.stdout.write(f"  source {name}: ~{total} background events, {len(source.fields)} fields\n")
    for name, entity in spec.entities.items():
        sys.stdout.write(f"  entity {name}: {entity.count} instances\n")
    counts = Counter(t["scenario"] for t in dataset.truth)
    for scenario in spec.scenarios:
        sys.stdout.write(f"  scenario {scenario.id}: {counts[scenario.id]} instance(s) [{scenario.label}]\n")
    return EXIT_OK


def cmd_infer(args) -> int:
    samples = load_samples(args.samples)
    text = infer_spec(samples, args.name, args.sourcetype, args.index, args.max_enum, not args.no_values)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        sys.stderr.write(f"wrote {args.out} from {len(samples)} sample event(s)\n")
    else:
        sys.stdout.write(text)
    return EXIT_OK


COMMANDS = {
    "generate": cmd_generate,
    "spl": cmd_spl,
    "hec": cmd_hec,
    "preview": cmd_preview,
    "validate": cmd_validate,
    "infer": cmd_infer,
}


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return COMMANDS[args.command](args)
    except (SpecError, ValueError, OSError, RuntimeError) as exc:
        sys.stderr.write(f"synthlog: {exc}\n")
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())

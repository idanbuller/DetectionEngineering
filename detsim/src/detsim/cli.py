from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from typing import List, Optional

import yaml
from spl_lint.sources import read_sources

from . import __version__, guide
from .predicate import PredicateError, from_spl
from .synth import Unsatisfiable, synthesize

EXIT_OK, EXIT_PROBLEM, EXIT_ERROR = 0, 1, 2
TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?(?!\d)")


@dataclass
class Simulation:
    name: str
    path: str
    techniques: List[str]
    status: str  # auto | manual
    event: Optional[dict]
    verification: Optional[str]
    reason: str
    guide: str


def _techniques(path: str, content: str) -> List[str]:
    found = TECHNIQUE.findall(os.path.basename(path).upper())
    if path.endswith((".yml", ".yaml")):
        try:
            for doc in yaml.safe_load_all(content):
                if isinstance(doc, dict):
                    for key in ("mitre", "mitre_attack", "techniques", "tags"):
                        val = doc.get(key)
                        if val:
                            found += TECHNIQUE.findall(
                                " ".join(map(str, val if isinstance(val, list) else [val])).upper()
                            )
        except yaml.YAMLError:
            pass
    return sorted(set(found))


def _makeresults(event: dict, search_args: List[str]) -> str:
    data = json.dumps([event], ensure_ascii=False, separators=(",", ":"))
    escaped = data.replace("\\", "\\\\").replace('"', '\\"')
    search = " ".join(search_args)
    return f'| makeresults format=json data="{escaped}"\n| search {search}'


def simulate_detection(path: str) -> List[Simulation]:
    with open(path, encoding="utf-8") as fh:
        content = fh.read()
    sources = read_sources(path, content, ["search", "spl", "query"])
    techniques = _techniques(path, content)
    sims = []
    for src in sources:
        name = src.name or os.path.basename(path)
        try:
            predicate = from_spl(src.text)
            synth = synthesize(predicate)
            verification = _makeresults(synth.event, predicate.search_args)
            g = guide.build(name, techniques, synth.event, "", verification)
            sims.append(Simulation(name, path, techniques, "auto", synth.event, verification, "", g))
        except (PredicateError, Unsatisfiable) as exc:
            g = guide.build(name, techniques, None, str(exc), None)
            sims.append(Simulation(name, path, techniques, "manual", None, None, str(exc), g))
    return sims


def _discover(paths: List[str]) -> List[str]:
    out: List[str] = []
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = sorted(d for d in dirs if not d.startswith(".") and d not in ("node_modules", ".venv"))
                out += [os.path.join(root, f) for f in sorted(files) if f.endswith((".yml", ".yaml", ".spl"))]
        else:
            out.append(p)
    return out


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_") or "detection"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="detsim",
        description="Generate a hit for each detection: a synthetic event that trips it, or a "
        "guide (with the Atomic Red Team test) for the ones that need real simulation.",
    )
    p.add_argument("--version", action="version", version=f"detsim {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("simulate", help="synthesize a hit per detection")
    s.add_argument("paths", nargs="+", help="detection files or directories")
    s.add_argument("-o", "--out", help="write a .spl hit search and .md guide per detection here")
    s.add_argument("-f", "--format", choices=["text", "json"], default="text")
    s.add_argument("-v", "--verbose", action="store_true", help="print the hit search for each detection")
    s.add_argument("--fail-on-manual", action="store_true", help="exit 1 if any detection needs manual simulation")
    return p


def cmd_simulate(args) -> int:
    sims: List[Simulation] = []
    for path in _discover(args.paths):
        try:
            sims.extend(simulate_detection(path))
        except OSError as exc:
            sys.stderr.write(f"detsim: {path}: {exc}\n")
    if not sims:
        sys.stderr.write("detsim: no detections found\n")
        return EXIT_ERROR

    if args.format == "json":
        json.dump(
            [
                {
                    "name": s.name,
                    "path": s.path,
                    "techniques": s.techniques,
                    "status": s.status,
                    "event": s.event,
                    "verification": s.verification,
                    "reason": s.reason,
                }
                for s in sims
            ],
            sys.stdout,
            indent=2,
        )
        sys.stdout.write("\n")
    else:
        _report_text(sims, args.verbose)

    if args.out:
        _write_out(sims, args.out)
        auto = sum(s.status == "auto" for s in sims)
        sys.stderr.write(f"wrote {len(sims)} guide(s) to {args.out} ({auto} auto, {len(sims) - auto} manual)\n")

    if args.fail_on_manual and any(s.status == "manual" for s in sims):
        return EXIT_PROBLEM
    return EXIT_OK


def _report_text(sims: List[Simulation], verbose: bool) -> None:
    auto = sum(s.status == "auto" for s in sims)
    for s in sims:
        mark = "hit " if s.status == "auto" else "MANUAL"
        line = f"{mark}  {', '.join(s.techniques) or '-':20} {s.name}"
        sys.stdout.write(line + ("" if s.status == "auto" else f"  ({s.reason})") + "\n")
        if verbose and s.verification:
            sys.stdout.write("    " + s.verification.replace("\n", "\n    ") + "\n")
    sys.stdout.write(
        f"\n{auto}/{len(sims)} detection(s) auto-simulatable; "
        f"{len(sims) - auto} need manual simulation (see the guides).\n"
    )


def _write_out(sims: List[Simulation], out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    seen: dict = {}
    index = ["# Simulation guides", ""]
    for s in sims:
        base = _slug(s.name)
        seen[base] = seen.get(base, 0) + 1
        slug = base if seen[base] == 1 else f"{base}_{seen[base]}"
        with open(os.path.join(out_dir, f"{slug}.guide.md"), "w", encoding="utf-8") as fh:
            fh.write(s.guide)
        if s.verification:
            with open(os.path.join(out_dir, f"{slug}.spl"), "w", encoding="utf-8") as fh:
                fh.write(s.verification + "\n")
        mark = "auto" if s.status == "auto" else "manual"
        index.append(f"- [{s.name}]({slug}.guide.md) — {mark}")
    with open(os.path.join(out_dir, "SIMULATE.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(index) + "\n")


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "simulate":
        return cmd_simulate(args)
    return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())

"""Human-facing simulation guidance: how to trip a detection for real.

For every detection we point at the Atomic Red Team test folder for its technique(s) (a real,
stable path in the redcanaryco/atomic-red-team repo). When detsim could synthesize an event,
we also give the synthetic recipe; when it couldn't, we spell out the conditions to satisfy so
a human can craft or execute it.
"""

from __future__ import annotations

from typing import Dict, List, Optional

ATT_BASE = "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics"
ATTACK_BASE = "https://attack.mitre.org/techniques"


def atomic_url(technique: str) -> str:
    return f"{ATT_BASE}/{technique}/{technique}.md"


def attack_url(technique: str) -> str:
    return f"{ATTACK_BASE}/{technique.replace('.', '/')}/"


def _recipe(event: Dict[str, object]) -> List[str]:
    index = event.get("index", "<index>")
    sourcetype = event.get("sourcetype", "<sourcetype>")
    fields = {k: v for k, v in event.items() if k not in ("index", "sourcetype")}
    lines = [f"Emit one `{sourcetype}` event into `{index}` with:"]
    for k, v in fields.items():
        lines.append(f"  - `{k}` = `{v}`")
    return lines


def build(
    name: str, techniques: List[str], event: Optional[Dict[str, object]], reason: str, verification: Optional[str]
) -> str:
    out = [f"# Simulating: {name}", ""]
    if techniques:
        out.append("**Technique(s):**")
        for t in techniques:
            out.append(f"- {t} — Atomic Red Team: {atomic_url(t)} · ATT&CK: {attack_url(t)}")
        out.append("")
    if event is not None:
        out.append("## Synthetic hit (no execution)")
        out += _recipe(event)
        if verification:
            out += ["", "Run this in Splunk to confirm it fires:", "", "```spl", verification, "```"]
        out += [
            "",
            "Inject it for real with `synthlog hec` (into a test index) or paste the search above.",
        ]
    else:
        out.append("## Manual simulation required")
        out.append(f"detsim could not auto-generate an event: {reason}")
        out.append("")
        if techniques:
            out.append(
                "Simulate it for real by running the matching Atomic Red Team test on a "
                "canary (see the links above), then confirm the detection fires with detval."
            )
        else:
            out.append(
                "Craft an event that satisfies the detection's search conditions, or run the "
                "real technique on a canary and confirm with detval."
            )
    return "\n".join(out) + "\n"

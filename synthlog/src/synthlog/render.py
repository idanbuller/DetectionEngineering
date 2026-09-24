"""Turn events into what a log source would actually emit."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from .engine import Event
from .generators import MISSING, Template, format_value
from .spec import SourceSpec


def epoch(t: datetime) -> float:
    return round(t.timestamp(), 3)


def format_time(t: datetime, fmt: str) -> Any:
    if fmt == "iso":
        return t.strftime("%Y-%m-%dT%H:%M:%SZ")
    if fmt == "iso_ms":
        return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"
    if fmt == "epoch":
        return int(t.timestamp())
    if fmt == "epoch_ms":
        return int(round(t.timestamp() * 1000))
    return t.strftime(fmt)


def fields(event: Event, source: SourceSpec, label_field: Optional[str] = None) -> Dict[str, Any]:
    """The event as a JSON object: time field first, then fields in spec order."""
    out: Dict[str, Any] = {source.time.field: format_time(event.time, source.time.format)}
    out.update(event.values)
    if label_field:
        out[label_field] = event.scenario or "background"
    return nest(out) if source.nested else out


def nest(flat: Dict[str, Any]) -> Dict[str, Any]:
    """{"process.name": x} -> {"process": {"name": x}}; keys that would collide stay flat."""
    out: Dict[str, Any] = {}
    for key, value in flat.items():
        parts = key.split(".")
        node = out
        ok = all(p for p in parts)
        for p in parts[:-1]:
            if not ok:
                break
            child = node.setdefault(p, {})
            if not isinstance(child, dict):
                ok = False
                break
            node = child
        if ok and parts[-1] not in node:
            node[parts[-1]] = value
        elif key not in out:
            out[key] = value
    return out


def raw_line(event: Event, source: SourceSpec, template: Template, label_field: Optional[str] = None) -> str:
    def lookup(name: str, spec: Optional[str]) -> str:
        if name in (source.time.field, "_time"):
            return format_value(event.time, spec) if spec else str(format_time(event.time, source.time.format))
        if label_field and name == label_field:
            return event.scenario or "background"
        return format_value(event.values.get(name, MISSING), spec)

    return template.render(lookup)


def host(event: Event, source: SourceSpec) -> Optional[str]:
    if source.host_field and source.host_field in event.values:
        return str(event.values[source.host_field])
    return None

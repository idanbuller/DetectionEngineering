"""Draft a source spec from sample events.

The goal is a runnable starting point that is safe to commit: it learns field
names, types, null rates, numeric ranges, event rate and the distribution of
low-cardinality enumerations (action=success/failure). Identity-like values
(users, hosts, emails, IP addresses) are never copied; they are replaced by
synthetic entity pools and generic address ranges. With values=False no sample
value is copied at all; numeric fields keep only their min/max range.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

import yaml

_TIME_NAMES = (
    "_time",
    "@timestamp",
    "timestamp",
    "time",
    "eventTime",
    "event_time",
    "EventTime",
    "TimeCreated",
    "created_at",
    "createdAt",
    "date",
    "ts",
)
_IDENTITY_NAME = re.compile(r"user|account|email|mail|upn|principal|host|computer|device|workstation|phone", re.I)
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEX = re.compile(r"^[0-9a-f]+$", re.I)
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", re.I)
_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$")


def load_samples(paths: Sequence[str]) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        stripped = text.lstrip()
        if stripped.startswith("["):
            data = json.loads(text)
            events.extend(e for e in data if isinstance(e, dict))
            continue
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                events.append(data)
                continue
        except json.JSONDecodeError:
            pass
        for n, line in enumerate(text.splitlines(), 1):
            if line.strip():
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"{path}:{n}: not JSON ({exc.msg})") from None
                if isinstance(obj, dict):
                    events.append(obj)
    if not events:
        raise ValueError("no JSON events found in the samples")
    return events


def flatten(obj: Dict[str, Any], prefix: str = "") -> Tuple[Dict[str, Any], bool]:
    out: Dict[str, Any] = {}
    nested = False
    for key, value in obj.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict) and value:
            inner, _ = flatten(value, f"{name}.")
            out.update(inner)
            nested = True
        else:
            out[name] = value
    return out, nested


def _parse_time(value: Any) -> Optional[Tuple[datetime, str]]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        if 1e9 <= value < 1e11:
            return datetime.fromtimestamp(value, timezone.utc), "epoch"
        if 1e12 <= value < 1e14:
            return datetime.fromtimestamp(value / 1000, timezone.utc), "epoch_ms"
        return None
    if isinstance(value, str) and _ISO.match(value.strip()):
        text = value.strip().replace(" ", "T").replace("Z", "+00:00")
        if re.search(r"[+-]\d{4}$", text):
            text = text[:-2] + ":" + text[-2:]
        try:
            dt = datetime.fromisoformat(re.sub(r"(\.\d{6})\d+", r"\1", text))
        except ValueError:
            return None
        dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        return dt, "iso_ms" if "." in value else "iso"
    return None


def _find_time_field(flat_events: List[Dict[str, Any]]) -> Optional[Tuple[str, str, List[datetime]]]:
    keys = {k for e in flat_events for k in e}
    ordered = [k for k in _TIME_NAMES if k in keys] + sorted(k for k in keys if k.lower().endswith("time"))
    for key in ordered:
        parsed = [_parse_time(e[key]) for e in flat_events if key in e]
        good = [p for p in parsed if p]
        if good and len(good) >= 0.9 * len(parsed):
            fmt = Counter(p[1] for p in good).most_common(1)[0][0]
            return key, fmt, [p[0] for p in good]
    return None


def _ip_range(values: List[str]) -> List[str]:
    """Generic ranges that match the address class of the samples, never the samples' own networks."""
    ranges = []
    for v in values:
        ip = ipaddress.ip_address(v)
        if ip in ipaddress.ip_network("10.0.0.0/8"):
            ranges.append("10.0.0.0/8")
        elif ip in ipaddress.ip_network("172.16.0.0/12"):
            ranges.append("172.16.0.0/12")
        elif ip in ipaddress.ip_network("192.168.0.0/16"):
            ranges.append("192.168.0.0/16")
        elif ip.is_loopback:
            ranges.append("127.0.0.1/32")
        else:
            ranges.append("198.51.100.0/24")  # TEST-NET-2, documentation range
    return sorted(set(ranges))


def _is_ipv4(v: Any) -> bool:
    try:
        return isinstance(v, str) and isinstance(ipaddress.ip_address(v), ipaddress.IPv4Address)
    except ValueError:
        return False


class _Inference:
    def __init__(self, max_enum: int, copy_values: bool) -> None:
        self.max_enum = max_enum
        self.copy_values = copy_values
        self.entities: Dict[str, Dict[str, Any]] = {}
        self.notes: Dict[str, str] = {}

    def field(self, name: str, values: List[Any], total: int) -> Any:
        present = [v for v in values if v is not None]
        null_rate = round(1 - len(present) / total, 2) if total else 0.0
        spec = self._spec(name, present)
        if null_rate > 0 and isinstance(spec, dict):
            spec = {**spec, "null_rate": null_rate}
        elif null_rate > 0:
            spec = {"value": spec, "null_rate": null_rate}
        return spec

    def _enum(self, name: str, values: List[Any]) -> Optional[Dict[str, Any]]:
        if not self.copy_values or _IDENTITY_NAME.search(name):
            return None
        counts = Counter(json.dumps(v) if isinstance(v, (list, dict)) else v for v in values)
        if len(counts) > self.max_enum or len(counts) > max(2, len(values) // 2):
            return None
        if len(counts) == 1:
            return {"value": next(iter(counts))}
        return {"choice": dict(counts.most_common())}

    def _spec(self, name: str, values: List[Any]) -> Any:
        if not values:
            self.notes[name] = "always null in the samples"
            return {"value": None}
        if all(isinstance(v, list) for v in values):
            items = [i for v in values for i in v if not isinstance(i, (dict, list))]
            lengths = [len(v) for v in values]
            if not items:
                self.notes[name] = "list of objects in the samples; replace with a template"
                return {"value": []}
            return {"list": self._spec(name, items), "min": min(lengths), "max": max(lengths)}
        if all(isinstance(v, bool) for v in values):
            return {"bool": round(sum(values) / len(values), 2)}
        if all(isinstance(v, int) and not isinstance(v, bool) for v in values):
            return self._enum(name, values) or {"int": [min(values), max(values)]}
        if all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in values):
            return {"float": [min(values), max(values)]}
        strings = [str(v) for v in values]
        if all(_is_ipv4(v) for v in strings):
            ranges = _ip_range(strings)
            return {"ipv4": ranges[0] if len(ranges) == 1 else ranges}
        if all(_UUID.match(v) for v in strings):
            return {"uuid": True}
        if all(_EMAIL.match(v) for v in strings):
            self._user_entity(email=True)
            return {"entity": "user.email"}
        if _IDENTITY_NAME.search(name):
            return self._identity(name)
        lengths = {len(v) for v in strings}
        if len(lengths) == 1 and all(_HEX.match(v) for v in strings) and next(iter(lengths)) >= 8:
            return {"hex": next(iter(lengths))}
        if all(_parse_time(v) for v in strings):
            return "{_time}"
        enum = self._enum(name, strings)
        if enum:
            return enum
        self.notes[name] = "free text in the samples; replace with a template"
        return "{word}-{digits:6}"

    def _user_entity(self, email: bool = False) -> None:
        user = self.entities.setdefault("user", {"count": 50, "skew": 1.1, "fields": {"name": "{first}.{last}"}})
        if email:
            user["fields"]["email"] = "{name}@example.com"

    def _identity(self, name: str) -> Dict[str, Any]:
        if re.search(r"host|computer|device|workstation", name, re.I):
            self.entities.setdefault(
                "host", {"count": 30, "skew": 0.8, "fields": {"name": "host-{n:04}", "ip": {"ipv4": "10.0.0.0/16"}}}
            )
            return {"entity": "host.name"}
        if re.search(r"phone", name, re.I):
            return "+1555{digits:7}"
        self._user_entity()
        return {"entity": "user.name"}


def infer_spec(
    samples: List[Dict[str, Any]],
    source_name: str = "source",
    sourcetype: Optional[str] = None,
    index: Optional[str] = None,
    max_enum: int = 20,
    copy_values: bool = True,
) -> str:
    """Return a runnable dataset spec (YAML text) for one source."""
    flat_events = []
    nested = False
    for e in samples:
        flat, was_nested = flatten(e)
        flat_events.append(flat)
        nested = nested or was_nested

    time_info = _find_time_field(flat_events)
    order: List[str] = []
    for e in flat_events:
        for k in e:
            if k not in order:
                order.append(k)

    inf = _Inference(max_enum, copy_values)
    fields: Dict[str, Any] = {}
    for key in order:
        if time_info and key == time_info[0]:
            continue
        fields[key] = inf.field(key, [e.get(key) for e in flat_events], len(flat_events))

    rate = "100/h"
    if time_info and len(time_info[2]) >= 2:
        span_h = (max(time_info[2]) - min(time_info[2])).total_seconds() / 3600
        if span_h > 0:
            rate = f"{max(1, round(len(time_info[2]) / span_h))}/h"

    source: Dict[str, Any] = {}
    if index:
        source["index"] = index
    source["sourcetype"] = sourcetype or source_name
    source["rate"] = rate
    if time_info:
        source["time"] = {"field": time_info[0], "format": time_info[1]}
    if nested:
        source["nested"] = True
    return _render_yaml(source_name, source, fields, inf, len(samples))


def _dump_inline(value: Any) -> str:
    text = yaml.safe_dump(value, default_flow_style=True, sort_keys=False, width=10_000, allow_unicode=True)
    return text.strip().removesuffix("...").strip()


def _render_yaml(name: str, source: Dict[str, Any], fields: Dict[str, Any], inf: _Inference, n: int) -> str:
    lines = [
        f"# Drafted by `synthlog infer` from {n} sample event(s). Review before use:",
        "# numeric ranges and enumerations are only as good as the samples.",
        "seed: 1",
        "duration: 24h",
    ]
    if inf.entities:
        lines += ["", "entities:"]
        lines += ["  " + line for line in yaml.safe_dump(inf.entities, sort_keys=False).splitlines()]
    lines += ["", "sources:", f"  {_dump_inline(name)}:"]
    for key, value in source.items():
        lines.append(f"    {key}: {_dump_inline(value)}")
    lines.append("    fields:")
    for key, spec in fields.items():
        note = f"  # {inf.notes[key]}" if key in inf.notes else ""
        lines.append(f"      {_dump_inline(key)}: {_dump_inline(spec)}{note}")
    lines += [
        "",
        "# scenarios:",
        "#   - id: example",
        "#     at: 6h",
        "#     steps:",
        f"#       - source: {name}",
        "#         count: 20",
        "#         interval: 5s",
        "#         set: {}",
    ]
    return "\n".join(lines) + "\n"

"""Load and validate a dataset spec (see docs/spec.md for the format)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import yaml

from .generators import Gen, SpecError, compile_spec

_DURATION_PART = re.compile(r"(\d+(?:\.\d+)?)\s*(ms|s|m|h|d|w)")
_UNITS = {"ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
_RATE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*/\s*(s|m|h|d)\s*$")
_TIME_FORMATS = ("iso", "iso_ms", "epoch", "epoch_ms")


def parse_duration(value: Any, path: str) -> timedelta:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return timedelta(seconds=float(value))
    text = str(value).replace(" ", "")
    pos, seconds = 0, 0.0
    for m in _DURATION_PART.finditer(text):
        if m.start() != pos:
            break
        seconds += float(m.group(1)) * _UNITS[m.group(2)]
        pos = m.end()
    if not text or pos != len(text):
        raise SpecError(path, f"invalid duration {value!r} (examples: 30s, 5m, 1h30m, 7d)")
    return timedelta(seconds=seconds)


def parse_time(value: Any, path: str) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value).strip()
    if text.startswith("now"):
        now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        rest = text[3:]
        if not rest:
            return now
        if rest[0] in "+-":
            delta = parse_duration(rest[1:], path)
            return now - delta if rest[0] == "-" else now + delta
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise SpecError(path, f"invalid time {value!r} (use ISO 8601, e.g. 2026-01-05T00:00:00Z, or now-24h)") from None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _require_mapping(value: Any, path: str) -> Dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise SpecError(path, "expected a mapping")
    return value


def _check_keys(data: Dict[str, Any], allowed: set, path: str) -> None:
    unknown = set(data) - allowed
    if unknown:
        raise SpecError(path, f"unknown key(s): {', '.join(sorted(map(str, unknown)))}")


@dataclass
class EntitySpec:
    name: str
    count: int
    skew: float
    fields: Dict[str, Gen]
    unique: Optional[str]


@dataclass
class TimeSpec:
    field: str = "_time"
    format: str = "iso"  # iso | iso_ms | epoch | epoch_ms | a strftime pattern


@dataclass
class SourceSpec:
    name: str
    index: Optional[str]
    sourcetype: Optional[str]
    host_field: Optional[str]
    rate_per_second: float
    events: Optional[int]
    diurnal: bool
    time: TimeSpec
    nested: bool
    raw: Optional[str]
    fields: Dict[str, Gen]
    field_order: List[str]


@dataclass
class Binding:
    entity: Optional[str]  # pick from this pool
    pick: Any  # "random" or an index
    where: Dict[str, Any]
    values: Dict[str, Gen]  # or build an ad hoc entity from these


@dataclass
class Step:
    source: str
    count: int
    interval: timedelta
    jitter: timedelta
    delay: timedelta
    set: Dict[str, Gen]


@dataclass
class ScenarioSpec:
    id: str
    label: str
    description: str
    mitre: List[str]
    at: Any  # timedelta offset or "random"
    repeat: int
    every: Optional[timedelta]
    bind: Dict[str, Binding]
    steps: List[Step]


@dataclass
class DatasetSpec:
    seed: int
    start: datetime
    duration: timedelta
    entities: Dict[str, EntitySpec] = field(default_factory=dict)
    sources: Dict[str, SourceSpec] = field(default_factory=dict)
    scenarios: List[ScenarioSpec] = field(default_factory=list)


def load_spec(path: str) -> DatasetSpec:
    with open(path, encoding="utf-8") as fh:
        try:
            data = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            raise SpecError(path, f"invalid YAML: {exc}") from None
    return parse_spec(data)


def parse_spec(data: Any) -> DatasetSpec:
    data = _require_mapping(data, "")
    _check_keys(data, {"seed", "start", "duration", "entities", "sources", "scenarios"}, "")
    seed = data.get("seed", 0)
    if not isinstance(seed, int):
        raise SpecError("seed", "must be an integer")
    duration = parse_duration(data.get("duration", "24h"), "duration")
    if duration.total_seconds() <= 0:
        raise SpecError("duration", "must be positive")
    start = parse_time(data["start"], "start") if "start" in data else parse_time("now", "start") - duration
    spec = DatasetSpec(seed=seed, start=start, duration=duration)

    for name, entity in _require_mapping(data.get("entities"), "entities").items():
        spec.entities[str(name)] = _parse_entity(str(name), entity, f"entities.{name}")

    sources = _require_mapping(data.get("sources"), "sources")
    if not sources:
        raise SpecError("sources", "define at least one source")
    for name, source in sources.items():
        spec.sources[str(name)] = _parse_source(str(name), source, f"sources.{name}")

    scenarios = data.get("scenarios") or []
    if not isinstance(scenarios, list):
        raise SpecError("scenarios", "expected a list")
    seen = set()
    for i, scenario in enumerate(scenarios):
        parsed = _parse_scenario(scenario, f"scenarios[{i}]", spec)
        if parsed.id in seen:
            raise SpecError(f"scenarios[{i}].id", f"duplicate scenario id {parsed.id!r}")
        seen.add(parsed.id)
        spec.scenarios.append(parsed)

    _check_entity_refs(spec)
    return spec


def _parse_entity(name: str, data: Any, path: str) -> EntitySpec:
    data = _require_mapping(data, path)
    _check_keys(data, {"count", "skew", "fields", "unique"}, path)
    count = data.get("count", 10)
    if not isinstance(count, int) or count < 1:
        raise SpecError(f"{path}.count", "must be a positive integer")
    skew = data.get("skew", 1.0)
    if not isinstance(skew, (int, float)) or skew < 0:
        raise SpecError(f"{path}.skew", "must be a number >= 0 (0 = every instance equally active)")
    fields = _require_mapping(data.get("fields"), f"{path}.fields")
    if not fields:
        raise SpecError(f"{path}.fields", "an entity needs at least one field")
    compiled = {str(k): compile_spec(v, f"{path}.fields.{k}") for k, v in fields.items()}
    unique = data.get("unique", next(iter(compiled)))
    if unique is not None and unique not in compiled:
        raise SpecError(f"{path}.unique", f"{unique!r} is not one of the entity's fields")
    return EntitySpec(name, count, float(skew), compiled, unique)


def _parse_rate(value: Any, path: str) -> float:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value) / 3600  # a bare number means events per hour
    m = _RATE.match(str(value))
    if not m:
        raise SpecError(path, f"invalid rate {value!r} (examples: 200/h, 5/m, 10000/d)")
    return float(m.group(1)) / _UNITS[m.group(2)]


def _parse_source(name: str, data: Any, path: str) -> SourceSpec:
    data = _require_mapping(data, path)
    allowed = {"index", "sourcetype", "host_field", "rate", "events", "diurnal", "time", "nested", "raw", "fields"}
    _check_keys(data, allowed, path)
    if "rate" in data and "events" in data:
        raise SpecError(path, "set either rate or events, not both")
    rate = _parse_rate(data.get("rate", "100/h"), f"{path}.rate")
    events = data.get("events")
    if events is not None and (not isinstance(events, int) or events < 0):
        raise SpecError(f"{path}.events", "must be a non-negative integer")

    time_data = data.get("time", {})
    if isinstance(time_data, str):
        time_data = {"field": time_data}
    time_data = _require_mapping(time_data, f"{path}.time")
    _check_keys(time_data, {"field", "format"}, f"{path}.time")
    time = TimeSpec(str(time_data.get("field", "_time")), str(time_data.get("format", "iso")))
    if time.format not in _TIME_FORMATS and "%" not in time.format:
        raise SpecError(f"{path}.time.format", f"use one of {', '.join(_TIME_FORMATS)} or a strftime pattern")

    fields_data = _require_mapping(data.get("fields"), f"{path}.fields")
    fields = {str(k): compile_spec(v, f"{path}.fields.{k}") for k, v in fields_data.items()}
    if time.field in fields:
        raise SpecError(f"{path}.fields.{time.field}", "is the time field; it is generated automatically")

    if data.get("nested"):
        names = set(fields) | {time.field}
        for fname in names:
            parts = fname.split(".")
            for i in range(1, len(parts)):
                prefix = ".".join(parts[:i])
                if prefix in names:
                    raise SpecError(
                        f"{path}.fields.{fname}",
                        f"conflicts with field {prefix!r}: nested JSON can't hold both a value and an object there",
                    )

    raw = data.get("raw")
    if raw is not None and not isinstance(raw, str):
        raise SpecError(f"{path}.raw", "must be a template string")
    host_field = data.get("host_field")
    if host_field is not None and host_field not in fields:
        raise SpecError(f"{path}.host_field", f"{host_field!r} is not one of the source's fields")
    return SourceSpec(
        name=name,
        index=data.get("index"),
        sourcetype=data.get("sourcetype"),
        host_field=host_field,
        rate_per_second=rate,
        events=events,
        diurnal=bool(data.get("diurnal", True)),
        time=time,
        nested=bool(data.get("nested", False)),
        raw=raw,
        fields=fields,
        field_order=list(fields),
    )


def _parse_scenario(data: Any, path: str, spec: DatasetSpec) -> ScenarioSpec:
    data = _require_mapping(data, path)
    allowed = {"id", "label", "description", "mitre", "at", "repeat", "every", "bind", "steps"}
    _check_keys(data, allowed, path)
    if "id" not in data:
        raise SpecError(path, "a scenario needs an id")
    sid = str(data["id"])
    label = str(data.get("label", "malicious"))
    if label not in ("malicious", "benign"):
        raise SpecError(f"{path}.label", "must be malicious or benign (a benign scenario is a hard negative)")
    mitre = data.get("mitre", [])
    mitre = [mitre] if isinstance(mitre, str) else [str(m) for m in mitre]

    at_raw = data.get("at", "random")
    at = "random" if at_raw == "random" else parse_duration(at_raw, f"{path}.at")
    repeat = data.get("repeat", 1)
    if not isinstance(repeat, int) or repeat < 1:
        raise SpecError(f"{path}.repeat", "must be a positive integer")
    every = parse_duration(data["every"], f"{path}.every") if "every" in data else None
    if repeat > 1 and every is None and at != "random":
        raise SpecError(f"{path}.every", "a repeated scenario with a fixed start needs `every`")

    bind = {}
    for role, b in _require_mapping(data.get("bind"), f"{path}.bind").items():
        bind[str(role)] = _parse_binding(str(role), b, f"{path}.bind.{role}", spec)

    steps_data = data.get("steps")
    if not isinstance(steps_data, list) or not steps_data:
        raise SpecError(f"{path}.steps", "a scenario needs a non-empty list of steps")
    steps = [_parse_step(s, f"{path}.steps[{i}]", spec) for i, s in enumerate(steps_data)]
    return ScenarioSpec(sid, label, str(data.get("description", "")), mitre, at, repeat, every, bind, steps)


def _parse_binding(role: str, data: Any, path: str, spec: DatasetSpec) -> Binding:
    data = _require_mapping(data, path)
    _check_keys(data, {"entity", "pick", "where", "values"}, path)
    if "values" in data:
        if "pick" in data or "where" in data:
            raise SpecError(path, "use either values (an ad hoc entity) or pick/where, not both")
        values = _require_mapping(data["values"], f"{path}.values")
        compiled = {str(k): compile_spec(v, f"{path}.values.{k}") for k, v in values.items()}
        return Binding(entity=data.get("entity"), pick=None, where={}, values=compiled)
    entity = str(data.get("entity", role))
    if entity not in spec.entities:
        raise SpecError(path, f"no entity pool named {entity!r} (set entity: to pick from another pool)")
    pick = data.get("pick", "random")
    if pick != "random" and not (isinstance(pick, int) and 0 <= pick < spec.entities[entity].count):
        raise SpecError(f"{path}.pick", f"must be random or an index below {spec.entities[entity].count}")
    where = _require_mapping(data.get("where"), f"{path}.where")
    return Binding(entity=entity, pick=pick, where=where, values={})


def _parse_step(data: Any, path: str, spec: DatasetSpec) -> Step:
    data = _require_mapping(data, path)
    _check_keys(data, {"source", "count", "interval", "jitter", "delay", "set"}, path)
    source = data.get("source")
    if source is None and len(spec.sources) == 1:
        source = next(iter(spec.sources))
    if source not in spec.sources:
        raise SpecError(f"{path}.source", f"unknown source {source!r}")
    count = data.get("count", 1)
    if not isinstance(count, int) or count < 1:
        raise SpecError(f"{path}.count", "must be a positive integer")
    overrides = _require_mapping(data.get("set"), f"{path}.set")
    compiled = {str(k): compile_spec(v, f"{path}.set.{k}") for k, v in overrides.items()}
    return Step(
        source=str(source),
        count=count,
        interval=parse_duration(data.get("interval", "1s"), f"{path}.interval"),
        jitter=parse_duration(data.get("jitter", 0), f"{path}.jitter"),
        delay=parse_duration(data.get("delay", 0), f"{path}.delay"),
        set=compiled,
    )


def _check_entity_refs(spec: DatasetSpec) -> None:
    from .generators import EntityRef, MapGen

    def walk(gen, path, known):
        if isinstance(gen, EntityRef) and gen.entity not in known:
            hint = " (an entity can only use entities declared before it)" if gen.entity in spec.entities else ""
            raise SpecError(path, f"unknown entity {gen.entity!r}{hint}")
        if isinstance(gen, MapGen):
            for k, v in gen.values.items():
                walk(v, f"{path}.values.{k}", known)

    declared: List[str] = []
    for name, entity in spec.entities.items():
        for fname, gen in entity.fields.items():
            walk(gen, f"entities.{name}.fields.{fname}", set(declared))
        declared.append(name)
    for name, source in spec.sources.items():
        for fname, gen in source.fields.items():
            walk(gen, f"sources.{name}.fields.{fname}", spec.entities)
        for i, scenario in enumerate(spec.scenarios):
            for j, step in enumerate(scenario.steps):
                for fname, gen in step.set.items():
                    walk(gen, f"scenarios[{i}].steps[{j}].set.{fname}", spec.entities)

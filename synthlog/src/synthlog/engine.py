"""Turn a DatasetSpec into events: benign background traffic plus injected scenarios."""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from .generators import Context, SpecError, cumulative, weighted_index
from .spec import Binding, DatasetSpec, EntitySpec, ScenarioSpec, SourceSpec


@dataclass
class Event:
    source: str
    time: datetime
    values: Dict[str, Any]
    scenario: Optional[str] = None  # scenario id, or None for background traffic


@dataclass
class Dataset:
    spec: DatasetSpec
    events: Dict[str, List[Event]] = field(default_factory=dict)
    truth: List[Dict[str, Any]] = field(default_factory=list)

    def all_events(self) -> List[Event]:
        merged = [e for events in self.events.values() for e in events]
        merged.sort(key=lambda e: e.time)
        return merged


def _rng(seed: int, *parts: str) -> random.Random:
    # One independent stream per component, so adding a source or scenario
    # doesn't change the events generated for the others.
    return random.Random(":".join([str(seed), *parts]))


class EntityPool:
    def __init__(self, spec: EntitySpec, seed: int, pools: Optional[Dict[str, EntityPool]] = None) -> None:
        rng = _rng(seed, "entity", spec.name)
        self.name = spec.name
        self.instances: List[Dict[str, Any]] = []
        seen = set()
        for i in range(spec.count):
            for _ in range(25):
                instance = Context(spec.fields, rng, pools, index=i + 1).evaluate()
                key = instance.get(spec.unique) if spec.unique else None
                if key is None or key not in seen:
                    break
            else:
                instance[spec.unique] = f"{key}{i + 1}"
            seen.add(instance.get(spec.unique))
            self.instances.append(instance)
        # Zipf-like activity: a few instances generate most of the events.
        self._cum = cumulative([1.0 / (rank + 1) ** spec.skew for rank in range(spec.count)])

    def pick(self, rng: random.Random) -> Dict[str, Any]:
        return self.instances[weighted_index(rng, self._cum)]


def diurnal_weight(t: datetime) -> float:
    """Relative activity: a working-hours peak around 13:30 UTC and quieter weekends."""
    hour = t.hour + t.minute / 60
    w = 0.15 + 0.85 * math.exp(-(((hour - 13.5) / 4.5) ** 2))
    return w * (0.35 if t.weekday() >= 5 else 1.0)


def _background_times(source: SourceSpec, spec: DatasetSpec, rng: random.Random) -> List[datetime]:
    total_seconds = spec.duration.total_seconds()
    n = source.events if source.events is not None else int(round(source.rate_per_second * total_seconds))
    if n <= 0:
        return []
    # Hour-long buckets (the last one may be partial), weighted by activity.
    buckets = []
    t = spec.start
    end = spec.start + spec.duration
    while t < end:
        nxt = min(t + timedelta(hours=1), end)
        width = (nxt - t).total_seconds()
        weight = (diurnal_weight(t) if source.diurnal else 1.0) * width
        buckets.append((t, width, weight))
        t = nxt
    cum = cumulative([b[2] for b in buckets])
    times = []
    for _ in range(n):
        start, width, _ = buckets[weighted_index(rng, cum)]
        times.append(start + timedelta(seconds=round(rng.uniform(0, width), 3)))
    times.sort()
    return times


def _make_event(
    source: SourceSpec,
    specs,
    t: datetime,
    rng: random.Random,
    pools,
    roles=None,
    scenario: Optional[str] = None,
) -> Event:
    ctx = Context(specs, rng, pools, roles=roles, preset={source.time.field: t, "_time": t})
    return Event(source.name, t, ctx.evaluate(), scenario)


def _bind(role: str, binding: Binding, pools: Dict[str, EntityPool], rng: random.Random, path: str):
    if binding.values:
        return Context(binding.values, rng, pools).evaluate()
    pool = pools[binding.entity]
    candidates = [i for i in pool.instances if _matches(i, binding.where)]
    if not candidates:
        raise SpecError(path, f"no {binding.entity} instance matches where: {binding.where}")
    if binding.pick == "random":
        return rng.choice(candidates)
    return pool.instances[binding.pick]


def _matches(instance: Dict[str, Any], where: Dict[str, Any]) -> bool:
    for key, expected in where.items():
        value = instance.get(key)
        if isinstance(expected, list):
            if value not in expected:
                return False
        elif value != expected:
            return False
    return True


def _scenario_span(scenario: ScenarioSpec) -> timedelta:
    span = timedelta(0)
    for step in scenario.steps:
        span += step.delay + step.interval * (step.count - 1) + step.jitter
    return span


def _run_scenario(scenario: ScenarioSpec, spec: DatasetSpec, pools, rng: random.Random, dataset: Dataset) -> None:
    roles = {
        role: _bind(role, b, pools, rng, f"scenario {scenario.id}: bind.{role}") for role, b in scenario.bind.items()
    }
    span = _scenario_span(scenario)
    room = max((spec.duration - span).total_seconds(), 0.0)
    first_start = None
    for rep in range(scenario.repeat):
        if scenario.at == "random" and (rep == 0 or scenario.every is None):
            start = spec.start + timedelta(seconds=round(rng.uniform(0, room), 3))
        elif scenario.at == "random":
            start = first_start + scenario.every * rep
        else:
            start = spec.start + scenario.at + (scenario.every or timedelta(0)) * rep
        first_start = first_start or start

        cursor = start
        counts: Dict[str, int] = {}
        first = last = None
        for step in scenario.steps:
            source = spec.sources[step.source]
            specs = dict(source.fields)
            specs.update(step.set)
            cursor += step.delay
            for k in range(step.count):
                t = cursor + step.interval * k
                if step.jitter:
                    t += timedelta(seconds=round(rng.uniform(-1, 1) * step.jitter.total_seconds(), 3))
                    t = max(t, cursor)
                event = _make_event(source, specs, t, rng, pools, roles=dict(roles), scenario=scenario.id)
                dataset.events[source.name].append(event)
                counts[source.name] = counts.get(source.name, 0) + 1
                first = t if first is None or t < first else first
                last = t if last is None or t > last else last
            cursor += step.interval * (step.count - 1)
        dataset.truth.append(
            {
                "scenario": scenario.id,
                "instance": rep,
                "label": scenario.label,
                "mitre": scenario.mitre,
                "description": scenario.description,
                "start": _iso(first),
                "end": _iso(last),
                "events": counts,
                "entities": roles,
            }
        )


def _iso(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def generate(spec: DatasetSpec, include_background: bool = True) -> Dataset:
    pools: Dict[str, EntityPool] = {}
    for name, entity in spec.entities.items():  # declaration order: a pool may use earlier pools
        pools[name] = EntityPool(entity, spec.seed, pools)
    dataset = Dataset(spec)
    for name, source in spec.sources.items():
        rng = _rng(spec.seed, "source", name)
        times = _background_times(source, spec, rng) if include_background else []
        dataset.events[name] = [_make_event(source, source.fields, t, rng, pools) for t in times]
    for scenario in spec.scenarios:
        _run_scenario(scenario, spec, pools, _rng(spec.seed, "scenario", scenario.id), dataset)
    for events in dataset.events.values():
        events.sort(key=lambda e: e.time)
    dataset.truth.sort(key=lambda t: t["start"])
    return dataset

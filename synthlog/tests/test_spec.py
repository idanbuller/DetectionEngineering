from datetime import timedelta

import pytest

from synthlog.generators import SpecError
from synthlog.spec import parse_duration, parse_spec, parse_time


def base(**extra):
    spec = {"start": "2026-01-05T00:00:00Z", "sources": {"s": {"fields": {"a": 1}}}}
    spec.update(extra)
    return spec


def test_durations():
    assert parse_duration("1h30m", "d") == timedelta(minutes=90)
    assert parse_duration("250ms", "d") == timedelta(milliseconds=250)
    assert parse_duration(90, "d") == timedelta(seconds=90)
    with pytest.raises(SpecError, match="invalid duration"):
        parse_duration("5 minutes", "d")


def test_times():
    assert parse_time("2026-01-05T00:00:00Z", "t").isoformat() == "2026-01-05T00:00:00+00:00"
    assert parse_time("2026-01-05", "t").tzinfo is not None
    now = parse_time("now", "t")
    assert parse_time("now-24h", "t") == now - timedelta(hours=24)
    with pytest.raises(SpecError):
        parse_time("yesterday", "t")


def test_rates():
    spec = parse_spec(base(sources={"s": {"rate": "60/m", "fields": {"a": 1}}}))
    assert spec.sources["s"].rate_per_second == 1.0
    assert parse_spec(base(sources={"s": {"rate": 3600, "fields": {}}})).sources["s"].rate_per_second == 1.0


@pytest.mark.parametrize(
    "spec, message",
    [
        ({"sources": {}}, "at least one source"),
        (base(colour=1), "unknown key"),
        (base(sources={"s": {"rate": "fast", "fields": {}}}), "invalid rate"),
        (base(sources={"s": {"rate": "1/h", "events": 3, "fields": {}}}), "either rate or events"),
        (base(sources={"s": {"time": {"format": "weird"}, "fields": {}}}), "strftime"),
        (base(sources={"s": {"fields": {"_time": 1}}}), "time field"),
        (base(sources={"s": {"host_field": "h", "fields": {}}}), "host_field"),
        (base(sources={"s": {"nested": True, "fields": {"a": 1, "a.b": 2}}}), "conflicts with field 'a'"),
        (base(sources={"s": {"fields": {"u": {"entity": "user.name"}}}}), "unknown entity 'user'"),
        (
            base(
                entities={
                    "a": {"fields": {"x": {"entity": "b.y"}}},
                    "b": {"fields": {"y": 1}},
                }
            ),
            "declared before",
        ),
        (base(scenarios=[{"steps": [{}]}]), "needs an id"),
        (base(scenarios=[{"id": "x", "steps": []}]), "non-empty list of steps"),
        (base(scenarios=[{"id": "x", "label": "evil", "steps": [{}]}]), "malicious or benign"),
        (base(scenarios=[{"id": "x", "steps": [{"source": "nope"}]}]), "unknown source"),
        (base(scenarios=[{"id": "x", "bind": {"user": {}}, "steps": [{}]}]), "no entity pool named 'user'"),
        (base(scenarios=[{"id": "x", "steps": [{}]}, {"id": "x", "steps": [{}]}]), "duplicate"),
        (base(scenarios=[{"id": "x", "at": "1h", "repeat": 3, "steps": [{}]}]), "needs `every`"),
    ],
)
def test_spec_errors(spec, message):
    with pytest.raises(SpecError, match=message):
        parse_spec(spec)


def test_single_source_steps_default_to_it():
    spec = parse_spec(base(scenarios=[{"id": "x", "steps": [{"count": 2}]}]))
    assert spec.scenarios[0].steps[0].source == "s"

import random
import re

import pytest

from synthlog.generators import MISSING, Context, SpecError, Template, compile_spec


def run(spec, n=1, seed=1, **fields):
    rng = random.Random(seed)
    specs = {k: compile_spec(v, k) for k, v in fields.items()}
    gen = compile_spec(spec, "f")
    out = []
    for _ in range(n):
        ctx = Context({**specs, "f": gen}, rng)
        out.append(ctx.get("f"))
    return out


def test_constants_and_templates():
    assert run(42) == [42]
    assert run("plain text") == ["plain text"]
    assert run("literal {{braces}}") == ["literal {braces}"]
    assert run("{a}-{b}", a="x", b={"value": 7}) == ["x-7"]
    assert run({"value": "{not a template}"}) == ["{not a template}"]


def test_template_format_specs_and_builtins():
    assert run("{n:03}") == ["000"]
    [v] = run("{first}.{last}@{domain}")
    assert re.fullmatch(r"[a-z]+\.[a-z]+@example\.(com|org|net)", v)
    [h] = run("{hex:12}")
    assert re.fullmatch(r"[0-9a-f]{12}", h)
    [d] = run("{digits:5}")
    assert re.fullmatch(r"\d{5}", d)
    assert run("{x:>5}", x=42) == ["   42"]


def test_choice_weights():
    values = run({"choice": {"a": 99, "b": 1}}, n=2000)
    assert 0.95 < values.count("a") / 2000 < 1.0
    assert set(run({"choice": ["x", "y"]}, n=200)) == {"x", "y"}


def test_numbers():
    ints = run({"int": [5, 10]}, n=500)
    assert min(ints) >= 5 and max(ints) <= 10 and all(isinstance(i, int) for i in ints)
    floats = run({"float": {"min": 0, "max": 1, "round": 2}}, n=200)
    assert all(0 <= f <= 1 and round(f, 2) == f for f in floats)
    logn = run({"int": {"min": 0, "max": 10000, "dist": "lognormal"}}, n=2000)
    assert sorted(logn)[1000] < 3000  # most values are small, with a long tail


def test_ipv4_uuid_hex_bool():
    ips = run({"ipv4": "10.1.2.0/30"}, n=100)
    assert set(ips) <= {"10.1.2.1", "10.1.2.2"}
    [u] = run({"uuid": True})
    assert re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", u)
    [h] = run({"hex": 40})
    assert len(h) == 40
    bools = run({"bool": 0.25}, n=2000)
    assert 0.2 < sum(bools) / 2000 < 0.3


def test_null_rate():
    values = run({"int": [1, 2], "null_rate": 0.5}, n=2000)
    assert 0.45 < values.count(MISSING) / 2000 < 0.55


def test_map_and_forward_references():
    spec = {"map": "action", "values": {"ok": "allowed {user}", "bad": "denied {user}"}, "default": "?"}
    assert run(spec, action="bad", user="eve") == ["denied eve"]
    assert run(spec, action="other", user="eve") == ["?"]
    assert run({"map": "code", "values": {404: "not found"}}, code=404) == ["not found"]


def test_list():
    values = run({"list": {"choice": ["a", "b"]}, "min": 2, "max": 2}, n=20)
    assert all(len(v) == 2 and set(v) <= {"a", "b"} for v in values)


def test_circular_reference_is_reported():
    with pytest.raises(SpecError, match="circular"):
        run("{a}", a="{f}")


@pytest.mark.parametrize(
    "spec, message",
    [
        ({"int": [5, 1]}, "min <= max"),
        ({"choice": []}, "non-empty"),
        ({"choice": {"a": -1}}, "non-negative"),
        ({"ipv4": "10.0.0.300/8"}, "10.0.0.300"),
        ({"entity": "user"}, "<entity>.<attribute>"),
        ({"int": [1, 2], "choice": [1]}, "exactly one generator"),
        ({"int": [1, 2], "colour": "red"}, "unknown key"),
        ({"int": [1, 2], "null_rate": 2}, "between 0 and 1"),
        (["a", "b"], "did you mean"),
    ],
)
def test_spec_errors_name_the_path(spec, message):
    with pytest.raises(SpecError, match=message) as info:
        compile_spec(spec, "sources.x.fields.f")
    assert str(info.value).startswith("sources.x.fields.f")


def test_template_refs():
    assert Template("{a} and {b.c:%H} {{x}}").refs == ["a", "b.c"]

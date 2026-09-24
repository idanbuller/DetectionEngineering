import json

import yaml

from synthlog.engine import generate
from synthlog.infer import infer_spec, load_samples
from synthlog.spec import parse_spec

SAMPLES = [
    {
        "timestamp": f"2026-03-01T10:{i:02d}:00Z",
        "user": {"name": f"secret.person{i % 4}", "email": f"secret.person{i % 4}@corp-internal.io"},
        "src_ip": f"10.44.{i}.7",
        "public_ip": "8.8.8.8",
        "action": "success" if i % 5 else "failure",
        "event_code": 4624 if i % 5 else 4625,
        "bytes": 100 + i * 10,
        "ratio": 0.5,
        "session": f"{i:08x}deadbeef",
        "request_id": "6f1c1f0e-8f3a-4b6e-9d1c-0a1b2c3d4e5f",
        "tags": ["a", "b"],
        "message": f"free text number {i}",
        "optional": "x" if i % 2 else None,
        "computer": f"CORP-LAPTOP-{i}",
    }
    for i in range(20)
]


def test_infer_produces_a_runnable_spec_without_identities():
    text = infer_spec(SAMPLES, "idp", sourcetype="idp:json", index="auth")
    for secret in ("secret.person", "corp-internal", "10.44.", "CORP-LAPTOP", "8.8.8.8"):
        assert secret not in text
    spec = parse_spec(yaml.safe_load(text))
    src = spec.sources["idp"]
    assert src.time.field == "timestamp" and src.time.format == "iso"
    assert src.nested and src.sourcetype == "idp:json" and src.index == "auth"
    assert abs(src.rate_per_second * 3600 - 63) < 2  # 20 events over 19 minutes
    ds = generate(spec)
    assert ds.events["idp"]


def test_infer_field_types():
    spec = yaml.safe_load(infer_spec(SAMPLES, "idp"))
    fields = spec["sources"]["idp"]["fields"]
    assert fields["action"] == {"choice": {"success": 16, "failure": 4}}
    assert fields["event_code"] == {"choice": {4624: 16, 4625: 4}}
    assert fields["bytes"] == {"int": [100, 290]}
    assert fields["src_ip"] == {"ipv4": "10.0.0.0/8"}
    assert fields["public_ip"] == {"ipv4": "198.51.100.0/24"}
    assert fields["request_id"] == {"value": "6f1c1f0e-8f3a-4b6e-9d1c-0a1b2c3d4e5f"} or fields["request_id"] == {
        "uuid": True
    }
    assert fields["session"] == {"hex": 16}
    assert fields["user.name"] == {"entity": "user.name"}
    assert fields["user.email"] == {"entity": "user.email"}
    assert fields["computer"] == {"entity": "host.name"}
    assert fields["optional"]["null_rate"] == 0.5
    assert fields["tags"]["list"] == {"choice": {"a": 20, "b": 20}}
    assert fields["message"] == "{word}-{digits:6}"
    assert set(spec["entities"]) == {"user", "host"}


def test_no_values_copies_nothing():
    text = infer_spec(SAMPLES, "idp", copy_values=False)
    for value in ("success", "failure", "6f1c1f0e", "secret"):
        assert value not in text
    assert "event_code: {int: [4624, 4625]}" in text  # numeric fields keep their range
    parse_spec(yaml.safe_load(text))


def test_load_samples_formats(tmp_path):
    (tmp_path / "a.jsonl").write_text('{"a": 1}\n\n{"a": 2}\n')
    (tmp_path / "b.json").write_text(json.dumps([{"a": 3}, {"a": 4}]))
    (tmp_path / "c.json").write_text('{"a": 5}')
    events = load_samples([str(tmp_path / n) for n in ("a.jsonl", "b.json", "c.json")])
    assert [e["a"] for e in events] == [1, 2, 3, 4, 5]

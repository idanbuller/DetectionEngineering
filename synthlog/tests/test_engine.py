from collections import Counter

from synthlog import render

WORLD = """
seed: 7
start: 2026-01-05T00:00:00Z   # Monday
duration: 24h
entities:
  workstation:
    count: 20
    fields: {name: "ws-{n:03}", ip: {ipv4: 10.0.0.0/16}}
  user:
    count: 30
    skew: 1.2
    fields:
      name: "{first}.{last}"
      dept: {choice: [it, eng, sales]}
      ws: {entity: workstation.name}
      ws_ip: {entity: workstation.ip}
sources:
  auth:
    rate: 200/h
    fields:
      user: {entity: user.name}
      src: {entity: user.ws_ip}
      action: {choice: {success: 95, failure: 5}}
  edr:
    rate: 100/h
    diurnal: false
    fields:
      host: {entity: user.ws}
      user: {entity: user.name}
"""


def test_deterministic(build):
    a = build(WORLD)
    b = build(WORLD)
    assert [(e.time, e.values) for e in a.events["auth"]] == [(e.time, e.values) for e in b.events["auth"]]


def test_adding_a_source_does_not_change_the_others(build):
    a = build(WORLD)
    b = build(WORLD + "  extra:\n    rate: 50/h\n    fields: {x: 1}\n")
    assert [(e.time, e.values) for e in a.events["auth"]] == [(e.time, e.values) for e in b.events["auth"]]


def test_volume_and_diurnal_curve(build):
    ds = build(WORLD)
    auth = ds.events["auth"]
    assert len(auth) == 4800
    by_hour = Counter(e.time.hour for e in auth)
    assert by_hour[13] > 3 * by_hour[3]  # busy afternoon, quiet night
    flat = Counter(e.time.hour for e in ds.events["edr"])
    assert flat[13] < 2 * flat[3]  # diurnal: false
    assert all(ds.spec.start <= e.time < ds.spec.start + ds.spec.duration for e in auth)
    assert auth == sorted(auth, key=lambda e: e.time)


def test_skewed_activity(build):
    counts = Counter(e.values["user"] for e in build(WORLD).events["auth"]).most_common()
    top3 = sum(c for _, c in counts[:3])
    assert top3 > 0.35 * 4800  # a few users dominate


def test_entities_stay_consistent(build):
    ds = build(WORLD)
    home = {}
    for e in ds.events["auth"] + ds.events["edr"]:
        if "src" in e.values:
            home.setdefault(e.values["user"], set()).add(e.values["src"])
    assert all(len(ips) == 1 for ips in home.values())


def test_unique_entity_names(build):
    ds = build(WORLD.replace("count: 30", "count: 3000"))
    users = {e.values["user"] for e in ds.events["auth"]}
    assert len(users) == len(set(users))


SCENARIOS = (
    WORLD
    + """
scenarios:
  - id: brute
    mitre: T1110
    at: 14h
    bind:
      user: {where: {dept: it}}
      attacker: {values: {ip: {ipv4: 203.0.113.0/24}}}
    steps:
      - {source: auth, count: 10, interval: 2s, set: {src: "{attacker.ip}", action: failure}}
      - {source: auth, delay: 5s, set: {src: "{attacker.ip}", action: success}}
      - {source: edr, delay: 1m, count: 2, interval: 10s, set: {note: "after {attacker.ip}"}}
  - id: beacon
    label: benign
    at: 1h
    repeat: 3
    every: 2h
    bind: {user: {pick: 0}}
    steps:
      - {source: edr}
"""
)


def test_scenario_events_and_truth(build):
    ds = build(SCENARIOS, background=False)
    brute = [e for e in ds.events["auth"] if e.scenario == "brute"]
    assert len(brute) == 11
    attacker = brute[0].values["src"]
    assert attacker.startswith("203.0.113.")
    assert {e.values["src"] for e in brute} == {attacker}
    assert [e.values["action"] for e in brute].count("failure") == 10
    victim = brute[0].values["user"]
    assert {e.values["user"] for e in ds.events["edr"] if e.scenario == "brute"} == {victim}
    edr = [e for e in ds.events["edr"] if e.scenario == "brute"]
    assert edr[0].values["note"] == f"after {attacker}"
    assert edr[0].values["host"] == ds.truth[-1]["entities"]["user"]["ws"]

    [truth] = [t for t in ds.truth if t["scenario"] == "brute"]
    assert truth["label"] == "malicious" and truth["mitre"] == ["T1110"]
    assert truth["events"] == {"auth": 11, "edr": 2}
    assert truth["entities"]["user"]["dept"] == "it"
    assert truth["entities"]["attacker"]["ip"] == attacker
    assert truth["start"].startswith("2026-01-05T14:00:00")


def test_repeated_scenario(build):
    ds = build(SCENARIOS, background=False)
    beacons = [t for t in ds.truth if t["scenario"] == "beacon"]
    assert [t["start"][11:16] for t in beacons] == ["01:00", "03:00", "05:00"]
    assert len({e.values["user"] for e in ds.events["edr"] if e.scenario == "beacon"}) == 1


def test_random_start_is_inside_the_window(build):
    ds = build(WORLD + "scenarios:\n  - {id: r, steps: [{source: auth, count: 3}]}\n", background=False)
    assert all(ds.spec.start <= e.time <= ds.spec.start + ds.spec.duration for e in ds.events["auth"])


def test_rendering(build):
    ds = build(
        """
        start: 2026-01-05T00:00:00Z
        duration: 1h
        sources:
          s:
            events: 1
            nested: true
            time: {field: ts, format: epoch_ms}
            fields: {a.b: 1, a.c: x, e: 2, d: {int: [1, 1], null_rate: 1}}
        """
    )
    [e] = ds.events["s"]
    out = render.fields(e, ds.spec.sources["s"], label_field="label")
    assert out["a"] == {"b": 1, "c": "x"} and out["e"] == 2 and out["label"] == "background"
    assert "d" not in out and isinstance(out["ts"], int)
    assert render.format_time(e.time, "iso").endswith("Z")
    assert render.format_time(e.time, "%Y") == "2026"

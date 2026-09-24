# Dataset spec reference

A spec is one YAML file with five top-level keys. Only `sources` is required.

```yaml
seed: 42                      # same seed + same spec = identical output
start: 2026-01-05T00:00:00Z   # ISO 8601, or now / now-24h (default: now minus duration)
duration: 24h                 # 30s, 5m, 1h30m, 7d, 2w
entities: {...}               # pools of users, hosts, ... shared by all sources
sources: {...}                # the log sources to generate
scenarios: [...]              # attacks (and benign look-alikes) injected on top
```

Each entity pool, source and scenario gets its own random stream derived from the seed.
Adding a new source or scenario therefore doesn't change the events already generated for
the others, which keeps test fixtures stable as a spec grows.

## Field specs

The same field syntax is used for entity attributes, source fields, scenario `set:`
overrides and ad hoc `values:`.

| Spec | Produces |
|------|----------|
| `"Failed password for {user}"` | A template. `{name}` is another field of the same event or entity; `{role.attr}` is an attribute of an entity picked for this event. |
| `"{_time:%b %d %H:%M:%S}"` | Formatting: a strftime pattern for times, a Python format spec for numbers (`{n:04}`) |
| `"{{literal}}"` | Literal braces |
| `42`, `true`, `null` | A constant |
| `{value: "{not a template}"}` | A constant, even one that contains braces |
| `{choice: [a, b, c]}` | A uniform choice |
| `{choice: {success: 95, failure: 5}}` | A weighted choice |
| `{int: [1, 100]}` | An integer. The long form is `{int: {min: 1, max: 100, dist: lognormal}}`, with `dist` one of `uniform`, `normal` or `lognormal`. |
| `{float: [0, 1], round: 2}` | A float, with the same options as `int` |
| `{bool: 0.3}` | `true` 30% of the time |
| `{ipv4: 10.0.0.0/16}` | An address in the range (a list of CIDRs is allowed) |
| `{uuid: true}` | A random UUID (v4 format) |
| `{hex: 32}` | 32 hex characters |
| `{entity: user.name}` | An attribute of the `user` picked for this event |
| `{entity: host.ip, role: dest}` | Picks a second, independent host under the role `dest` |
| `{map: action, values: {success: "...", failure: "..."}, default: "..."}` | A value chosen by another field's value |
| `{list: {choice: [a, b]}, min: 1, max: 3}` | A JSON list |

Any field spec can carry `null_rate: 0.2`, which leaves the field out of 20% of events.
Templates and maps can refer to fields declared later in the same event; circular
references are reported as errors.

Built-in pattern values, used when no field of that name exists: `{first}`, `{last}`,
`{word}`, `{domain}` (example.com/org/net), `{n}` (the 1-based index of an entity
instance), `{hex:N}` and `{digits:N}`.

## Entities

```yaml
entities:
  workstation:
    count: 60
    fields:
      name: "ws-{n:04}"
      ip: {ipv4: 10.20.0.0/16}
  user:
    count: 60
    skew: 1.1            # Zipf exponent: a few users generate most activity; 0 = all equal
    unique: name         # regenerate on collisions (default: the first field)
    fields:
      name: "{first}.{last}"
      department: {choice: {engineering: 45, sales: 25, it: 15, finance: 15}}
      workstation: {entity: workstation.name}   # an earlier pool: each user gets a home machine
      workstation_ip: {entity: workstation.ip}  # same pick as the line above
```

Within one event, every `{entity: user.*}` field refers to the same picked user. This
works across entities too: `{entity: user.workstation}` and `{entity: user.workstation_ip}`
always describe the same machine. An entity can use pools declared before it.

## Sources

```yaml
sources:
  linux_auth:
    index: os                 # used by the hec and spl outputs
    sourcetype: linux_secure
    host_field: host          # which field becomes Splunk's host
    rate: 120/h               # or 5/m, 3000/d; or `events: 500` for an exact count
    diurnal: true             # working-hours peak, quieter nights and weekends (default)
    time: {field: timestamp, format: iso}   # iso | iso_ms | epoch | epoch_ms | a strftime pattern
    nested: false             # true: "process.name" becomes {"process": {"name": ...}}
    raw: "{timestamp:%b %d %H:%M:%S} {host} sshd[{pid}]: {message}"   # optional text line
    fields: {...}
```

With `raw`, each event is written as that text line (to `<source>.log`, or as `_raw` in
Splunk). Without it, each event is a JSON object (to `<source>.jsonl`).

## Scenarios

```yaml
scenarios:
  - id: ssh_bruteforce_then_discovery
    label: malicious          # or benign: a hard negative a good detection must NOT fire on
    description: ...
    mitre: [T1110.001, T1087.001]
    at: 14h                   # offset from start, or random (default)
    repeat: 3                 # optional: run it several times...
    every: 2h                 # ...this far apart (with random, only the first start is random)
    bind:
      user: {where: {department: engineering}}   # pick from the pool named like the role
      server: {pick: random}                     # or pick: 3 for a fixed instance
      admin: {entity: user, where: {department: it}}  # a role name that differs from the pool
      attacker: {values: {ip: {ipv4: 203.0.113.0/24}}}  # an ad hoc entity outside the pools
    steps:
      - source: linux_auth    # optional when there is only one source
        count: 40
        interval: 3s
        jitter: 1s            # +/- random offset per event
        delay: 0s             # wait before this step starts
        set: {src_ip: "{attacker.ip}", action: failure}
```

Binding a role pins it for the whole scenario. Every field that resolves through that role,
such as `{entity: user.name}` or `{entity: user.workstation}`, uses the same instance in
every step and every source. Fields you don't `set` are generated exactly as for background
traffic, so injected events look like the rest of the data.

Every scenario run is recorded in `truth.json`:

```json
{
  "scenario": "ssh_bruteforce_then_discovery",
  "instance": 0,
  "label": "malicious",
  "mitre": ["T1110.001", "T1087.001", "T1033"],
  "description": "Password guessing from the internet, a successful login, then discovery commands.",
  "start": "2026-01-05T14:00:00.862Z",
  "end": "2026-01-05T14:05:41.000Z",
  "events": {"linux_auth": 41, "edr_process": 3},
  "entities": {
    "user": {"name": "ron.nguyen", "department": "engineering", "workstation": "ws-0025", "workstation_ip": "10.20.64.104"},
    "server": {"name": "srv-forge-09", "ip": "10.10.0.70"},
    "attacker": {"ip": "203.0.113.226"}
  }
}
```

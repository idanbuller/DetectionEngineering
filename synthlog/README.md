# synthlog

Realistic synthetic security logs with **injected attack scenarios and ground truth**, for
testing detections without production data.

You describe a small world in YAML: users with home workstations, servers, and log sources
with realistic field distributions. On top of that you script the attacks you want a
detection to catch, plus benign look-alikes it must not catch. synthlog generates the
background traffic, injects the scenarios, and records exactly what it injected in
`truth.json`. The events can be written to files, sent to Splunk HEC, or turned into a
self-contained `| makeresults` search that runs on any Splunk 9.1+ without indexing
anything.

```text
$ synthlog preview examples/corp.yml -n 1
== linux_auth (2926 events)
Jan 05 00:01:48 srv-frost-12 sshd[37718]: Accepted publickey for adam.cohen from 10.20.139.158 port 33964 ssh2
== edr_process (21604 events)
{"timestamp": "2026-01-05T00:00:04.049Z", "event_id": "4cc8c9ad-…", "device": {"name": "ws-0007", "ip": "10.20.7.0"}, "user": {"name": "adam.wang"}, "process": {"name": "explorer.exe", …}, "parent": {"name": "services.exe"}}

2026-01-05 00:00 to 2026-01-06 00:00 UTC, seed 42
  linux_auth: 2926 events (46 from scenarios)
  edr_process: 21604 events (4 from scenarios)
  scenario office_encoded_powershell#0 [malicious] 2026-01-05T05:55:37.606Z (1 edr_process)
  scenario admin_password_typos#0 [benign] 2026-01-05T09:30:00.000Z (5 linux_auth)
  scenario ssh_bruteforce_then_discovery#0 [malicious] 2026-01-05T14:00:00.862Z (41 linux_auth, 3 edr_process)
```

## Why

Detection tests usually use either a handful of hand-written events or a copy of production
logs. Hand-written events are too clean to reveal false positives. Production copies can't
be shared or committed, and they don't say which events are the attack.

synthlog sits between the two:

- **Realistic background.** Activity follows a working-hours curve with quiet nights and
  weekends. A few users do most of the work (Zipf skew). Every user has a home workstation
  and logs in from it. Fields have realistic types, ranges and null rates.
- **Scripted scenarios.** An attack is a sequence of steps across sources, with timing and
  jitter. It can bind the same victim, server and attacker in every step. For example: 40
  failed SSH logins from the internet, a success, then `whoami` / `nltest` on the victim's
  own workstation three minutes later.
- **Hard negatives.** `label: benign` scenarios, such as an admin mistyping a password four
  times, test that a detection isn't too sensitive.
- **Ground truth.** `truth.json` lists every injected run with its time window, event counts
  and the exact entities involved, so a detection's output can be scored automatically.
- **Deterministic.** The same seed and spec produce byte-identical output, so it's safe to
  commit as a test fixture. Adding a source or scenario doesn't change the events already
  generated for the others.

## Install

```bash
pip install "git+https://github.com/idanbuller/DetectionEngineering#subdirectory=synthlog"
```

It needs Python 3.9+. The only dependency is PyYAML.

## Usage

```bash
synthlog validate examples/corp.yml          # check the spec, summarize what it will generate
synthlog preview  examples/corp.yml -n 3     # a few events per source + the scenario list
synthlog generate examples/corp.yml -o out/  # out/linux_auth.log, out/edr_process.jsonl, out/truth.json
synthlog generate examples/corp.yml --duration 7d --seed 7 -o out/   # overrides
synthlog hec examples/corp.yml --url https://splunk:8088             # token in $SPLUNK_HEC_TOKEN
synthlog spl examples/corp.yml --no-background > test.spl            # an inline makeresults search
synthlog infer samples.jsonl --name vpn --sourcetype vpn:json -o vpn.yml   # draft a spec from samples
```

`--label-field synthetic` adds a field with the scenario id (or `background`) to every
event, which helps with debugging. Leave it off when testing a detection, so the detection
can't accidentally key on it.

## Testing a Splunk detection with no indexing

`synthlog spl` builds a search that recreates the events inside Splunk. Each event carries
`_time`, `index`, `sourcetype`, `source` and `host`, and `_raw` is exactly what the source
would have logged. JSON sources are then extracted with `spath`, as `KV_MODE=json` would.
That means a detection's own base search can follow as `| search`:

```spl
<output of: synthlog spl scenarios.yml --no-background>
| search index=os sourcetype=linux_secure "Failed password"
| rex "Failed password for (?<user>\S+) from (?<src>\S+)"
| stats count min(_time) as firstTime by src user
| where count >= 10
```

Run against a spec with a 12-attempt brute force and a 4-typo admin, on a real Splunk
instance, this returned exactly one row: the attacker's IP with count 12. The admin's
benign typos correctly stayed below the threshold. Round-tripping Windows paths, embedded
quotes and nested JSON through the search was verified the same way.

For bigger datasets (a week of background traffic is ~170k events and takes a few seconds
to generate), send them to a test index with `synthlog hec`.

## Writing a spec

A minimal spec:

```yaml
seed: 1
start: 2026-01-05T00:00:00Z
duration: 24h

entities:
  user:
    count: 50
    fields:
      name: "{first}.{last}"

sources:
  vpn:
    index: network
    sourcetype: vpn:json
    rate: 300/h
    fields:
      user: {entity: user.name}
      src_ip: {ipv4: 198.51.100.0/24}
      result: {choice: {allowed: 97, denied: 3}}

scenarios:
  - id: password_spray
    mitre: T1110.003
    at: 3h
    bind: {attacker: {values: {ip: {ipv4: 203.0.113.0/24}}}}
    steps:
      - count: 50
        interval: 5s
        set: {src_ip: "{attacker.ip}", result: denied}   # user is still random: a spray
```

The full reference is in [docs/spec.md](docs/spec.md). [examples/corp.yml](examples/corp.yml)
is a complete two-source example with a cross-source attack, a phishing-to-PowerShell
chain and a benign near-miss.

## Bootstrapping from real samples

`synthlog infer` drafts a source spec from sample JSON events. It learns:

- field names and nesting
- types
- null rates
- numeric ranges
- the time field and its format
- the event rate
- the distribution of low-cardinality enumerations (`action: {success: 16, failure: 4}`)

The draft is meant to be committed, so it never copies identity-like values:

- Users, hosts and emails become synthetic entity pools (`{first}.{last}`, `host-{n:04}`).
- IP addresses become generic ranges for their address class (10.0.0.0/8, 198.51.100.0/24,
  ...), never your real subnets.
- Free text becomes a placeholder marked `# replace with a template`.

With `--no-values`, no sample values are copied at all; numeric fields keep only their
min/max range. Review the draft before committing: the heuristics are only as good as the
samples.

## Development

```bash
cd synthlog
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## License

MIT

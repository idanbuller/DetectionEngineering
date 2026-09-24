# detval

Continuous detection validation — purple team as code. detval executes an ATT&CK technique
on a canary you control, then polls Splunk to confirm the telemetry, notable, or risk event
you expect actually shows up. Every detection gets a live pass/fail, a detection latency, and
a spot on an ATT&CK Navigator coverage map.

Where [spltest](../spltest/) checks a detection's logic offline against synthetic data,
detval checks the whole pipeline end to end: agent, ingestion, parsing, the search, and the
alert. A rule can be perfect and still fail here because the log source stopped flowing.

```text
$ detval run cases/ --splunk-url https://splunk:8089 --layer coverage.json
PASS  T1059.001  Encoded PowerShell from Office  cases/T1059.001_encoded_powershell.case.yml
      execute: executed - executed
  ok  [telemetry] EDR captured encoded PowerShell: 1 row(s) in 41s
  ok  [notable] ES raised a notable: 1 row(s) in 3m20s
FAIL  T1071.001  C2 over HTTPS beacon  cases/T1071.001_https_beacon.case.yml
      execute: executed - executed
  ok  [telemetry] proxy logged the beacon: 3 row(s) in 22s
  !!  [notable] beacon notable fired: 0 row(s), expected 1

1 pass, 1 fail (2 case(s)).
```

## Safety

detval runs real attack techniques, so it is built to make that deliberate and never
accidental:

- **No payloads live here.** The `atomic` executor references [Atomic Red
  Team](https://github.com/redcanaryco/atomic-red-team) tests by GUID; the payloads live in
  the ART repo you install on the canary. The `command` executor runs a command you wrote.
- **Execution is gated twice.** A case runs its technique only when the case sets
  `authorized: true` *and* you pass `--allow-execution`. Otherwise detval prints what it
  *would* run and still does the verification step.
- **`verify` never executes anything.** Use it to re-check detections against events that are
  already in Splunk.
- **`dryrun` (the default executor) and `manual`** don't run code on their own; `manual`
  prints steps for a human and records their confirmation.

Only run detval against systems and data you are authorized to test.

## A case file

```yaml
# cases/T1059.001_encoded_powershell.case.yml
technique: T1059.001
name: Encoded PowerShell from Office
tactic: execution
authorized: true                 # you assert this canary is yours to test
execute:
  executor: atomic               # dryrun (default) | manual | command | atomic
  atomic_guid: 3c73d728-...      # an Atomic Red Team test; nothing offensive is stored here
  target: canary-01
  ssh: operator@canary-01        # optional: run it over SSH
  input_args: {command_to_encode: "Start-Process calc.exe"}
  cleanup: "Invoke-AtomicTest T1059.001 -TestGuids 3c73d728-... -Cleanup"   # optional
expect:
  - name: EDR captured encoded PowerShell
    kind: telemetry              # telemetry | notable | risk
    search: |
      index=edr sourcetype=edr:process
      | spath | search process_name=powershell.exe cmdline="*-enc*"
    match: {dest: "{target}"}    # a returned row must have dest = the target
    settle: 30s                  # wait this long before the first check
    window: 15m                  # keep checking for this long after execution
    poll: 30s                    # re-check this often
  - name: ES raised a notable
    kind: notable
    search: index=notable source="*Encoded PowerShell*"
```

A check passes when at least `min_rows` (default 1) rows match within the window. `match`
values are templated: `{target}` is the execution target and `{technique}` the technique id.
Detection latency is the time from execution to the earliest matching event.

## Usage

```bash
detval list cases/                                    # what each case is and how it would run
detval verify cases/ --splunk-url https://splunk:8089 # check detections only, never execute
detval run cases/ --splunk-url https://splunk:8089 --allow-execution   # execute + verify
detval run cases/ --junit detval.xml --layer coverage.json            # CI + Navigator layer
detval layer results.json > coverage.json             # build a layer from a saved JSON report
```

Credentials come from `$SPLUNK_TOKEN`, or `--username` with `$SPLUNK_PASSWORD`. Exit codes:
`0` all cases passed (or were safely blocked), `1` a detection is missing, `2` a
configuration or connection error.

`run` on a schedule (cron, or a Splunk-adjacent runner) gives you a daily heartbeat: which
detections still fire, which went silent, and how detection latency is trending.

## The coverage layer

`--layer coverage.json` writes an [ATT&CK
Navigator](https://mitre-attack.github.io/attack-navigator/) layer. Each tested technique is
colored by its worst result: green if detection was proven end to end, red if the technique
ran but nothing fired, amber if it wasn't executed, purple if it errored. Unlike a coverage
map built from "we have a rule for this," every green square here was proven by a real
execution.

## Statuses

| Status | Meaning |
|--------|---------|
| `pass` | Executed (or dry-run) and every expected signal appeared |
| `fail` | A signal that should have appeared didn't — a detection gap |
| `blocked` | Execution was needed but not authorized/enabled, so detection can't be judged (exit 0) |
| `error` | The technique failed to run, or a check couldn't be evaluated |

## Install

```bash
pip install "git+https://github.com/idanbuller/DetectionEngineering#subdirectory=detval"
```

Python 3.9+, PyYAML only. For the `atomic` executor, install
[Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam) on the canary.

## License

MIT

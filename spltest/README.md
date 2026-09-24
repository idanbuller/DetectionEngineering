# spltest

Unit tests for Splunk detections. spltest runs a detection's own SPL against a
[synthlog](../synthlog/) dataset containing known attacks and benign look-alikes. It then
scores the results against the dataset's ground truth: what it caught, what it missed, and
where it fired when it shouldn't have.

```text
$ spltest run examples/tests --splunk-url https://splunk:8089
PASS  SSH brute force from a single source  examples/tests/ssh_bruteforce.test.yml
  ok  ssh_bruteforce [malicious] fires: 1/1 run(s) detected (1 row(s))
  ok  admin_password_typos [benign] does not fire: 0/1 run(s) matched
      note: removed time modifier earliest=-24h (the dataset sets the time range)
PASS  Office application spawns encoded PowerShell  examples/tests/office_spawns_powershell.test.yml
  ok  office_spawns_encoded_powershell [malicious] fires: 1/1 run(s) detected (1 row(s))
  ok  admin_runs_powershell_script [benign] does not fire: 0/1 run(s) matched
FAIL  Office application spawns encoded PowerShell (buggy)  examples/tests/office_spawns_powershell_buggy.test.yml
  !!  office_spawns_encoded_powershell [malicious] fires: 0/1 run(s) detected (0 row(s))
  ok  admin_runs_powershell_script [benign] does not fire: 0/1 run(s) matched
      hint: spl-lint SPL104 (line 6): `parent.name` is evaluated as parent . name (concatenation). ...
      hint: the search returned no rows at all

2/3 test(s) passed.
```

That output is what the examples in this directory produce against a real Splunk
instance. The results were recorded with `compose` and `score`, and are kept in
[tests/fixtures](tests/fixtures/), so the unit tests re-score them on every CI run.

## How it works

1. **Generate.** spltest builds the test's synthlog dataset. By default that's only the
   scenario events, which keeps the search small; `background: 2h` adds realistic
   background traffic.
2. **Compose.** spltest uses [spl-lint](../spl-lint/)'s parser to split off the detection's
   base search, and rewrites the detection as:

   ```spl
   | makeresults format=json data="[...synthetic events...]"
   | search index=os sourcetype=linux_secure "Failed password"
   | rex ... | stats ... | where count >= 8
   ```

   Every synthetic event carries `index`, `sourcetype`, `source`, `host` and the vendor's
   exact `_raw`. The detection's own base-search terms therefore filter the inline data the
   same way they'd filter an index. Nothing is indexed, and nothing touches production data.
   Time modifiers (`earliest=-24h`) are removed, because the dataset defines the time range.
3. **Run.** The composed search runs on any Splunk 9.1+, over REST (`spltest run`) or
   anywhere else you can run a search (`spltest compose`, then `spltest score`).
4. **Score.** Each result row is attributed to the scenario runs it matches, by the fields in
   `match:` and by time. Then spltest checks:
   - every malicious run was detected
   - no benign run was
   - optionally, that no row was left unexplained (`max_unexpected: 0`), which catches false
     positives on background traffic

   When a test fails, spl-lint's findings for the detection are shown as hints.

## A test file

```yaml
# examples/tests/ssh_bruteforce.test.yml
detection: ../detections/ssh_bruteforce.yml   # a YAML detection (search: key) or a .spl file
dataset: ../datasets/small_corp.yml           # a synthlog spec
sources: [linux_auth]                         # only inline the sources this detection reads
max_unexpected: 0                             # any row no scenario explains is a failure
expect:
  - scenario: ssh_bruteforce                  # malicious: must fire...
    match: {src: "{attacker.ip}", user: "{user.name}"}   # ...on this attacker and victim
  - scenario: admin_password_typos            # benign: must NOT fire
    match: {user: "{user.name}"}
```

| Key | Meaning |
|-----|---------|
| `detection` / `search` | The detection file, or the SPL inline (exactly one) |
| `dataset` | A synthlog spec. Paths are relative to the test file. |
| `background` | `false` (default): scenario events only. `true`: the dataset's full duration. A duration such as `2h`: that much background traffic. |
| `sources` | Only inline these dataset sources |
| `macros` | `{name: definition}`, for when the test Splunk doesn't have a macro the detection uses |
| `max_unexpected` | Fail when more result rows than this are explained by no scenario |
| `expect` | Scenario ids, each optionally with `match`, `fires` and `instances` |

In an `expect` entry:
- `match` maps result fields to templates filled from the scenario's bound entities in
  `truth.json` (`{attacker.ip}`, `{user.workstation}`). Without `match`, a row counts if any
  of its values equals any entity value of the run.
- `fires` defaults to `true` for `malicious` scenarios and `false` for `benign` ones.
- `instances: all` (default) or `any` controls how many runs of a repeated scenario must
  behave as expected.

## Usage

```bash
# Run over REST: token in $SPLUNK_TOKEN, or --username with $SPLUNK_PASSWORD
spltest run tests/ --splunk-url https://splunk:8089 --junit spltest.xml

# No REST access? Compose the search, run it wherever you can, save the rows, score them.
spltest compose tests/ssh_bruteforce.test.yml > search.spl
spltest score tests/ssh_bruteforce.test.yml --results results.json
```

`score` accepts a JSON list of rows, `{"results": [...]}`, or the export endpoint's JSON
lines. Exit codes: `0` means everything passed, `1` means a test failed, and `2` means a
configuration or connection error. `--junit` writes a report that CI systems render
natively.

## Limits

- The detection must start with a base search. Searches that start with `| tstats` or
  `| datamodel` read accelerated data that inline events can't populate. Test the raw-event
  version of the logic instead.
- A subsearch that searches an index still reads real data. spltest reports each one in a
  note.
- The composed search carries the data inline, so keep datasets focused. `--max-events`
  (default 5000) guards against oversized searches. For large-scale background testing,
  load the data with `synthlog hec` and run the detection normally.

## Install

```bash
pip install \
  "git+https://github.com/idanbuller/DetectionEngineering#subdirectory=spl-lint" \
  "git+https://github.com/idanbuller/DetectionEngineering#subdirectory=synthlog" \
  "git+https://github.com/idanbuller/DetectionEngineering#subdirectory=spltest"
```

## License

MIT

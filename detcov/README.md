# detcov

An honest ATT&CK coverage map. Most coverage dashboards color a technique green when a rule
exists for it. That hides the two ways coverage actually fails: the rule sits on a data
source that stopped flowing, or the rule has never been shown to fire. detcov combines three
signals per technique —

- **a rule exists** (from your detection repo),
- **its data is healthy** (fresh events in the index/sourcetype the rule queries), and
- **it was proven to fire** (from a [detval](../detval/) validation run) —

into one ATT&CK Navigator layer, so a green square means detection actually works.

```text
$ detcov report detections/ --health health.json --detval detval-results.json
Coverage over 5 technique(s):
  proven                          1  ######
  covered                         1  ######
  unknown data                    1  ######
  at risk (stale data)            1  ######
  no data                         0
  broken (validated miss)         1  ######

Rules likely not firing (data problem):
  T1071.001    at risk (stale data) C2 beacon over HTTPS

Rules that failed validation:
  T1110.001    SSH brute force
```

## Tiers

Each technique lands in exactly one tier, worst-first:

| Tier | Meaning |
|------|---------|
| `broken` | A rule exists, but detval executed the technique and the rule didn't fire. |
| `no data` | A rule exists, but the index/sourcetype it queries has never been seen. |
| `at risk` | A rule exists, but its data is stale — the rule is probably silent right now. |
| `unknown` | A rule exists, but its data can't be resolved (index comes from a macro, or no health data). |
| `covered` | A rule exists on healthy data; not yet validated. |
| `proven` | A rule exists on healthy data and detval proved it fires end to end. |

`broken`, `no data`, and `at risk` are the point of the tool: they're techniques you'd have
counted as "covered" on a normal heat map, but which aren't protecting you.

## How coverage is derived

- **Rules and techniques.** detcov reads any `.yml`/`.yaml` with a `search`/`spl`/`query` key
  (or a bare `.spl` file), and pulls techniques from a `mitre`/`techniques`/`tags` field,
  the `technique` key, or a `Txxxx.xxx` in the filename.
- **Data a rule needs.** It parses each rule's SPL with [spl-lint](../spl-lint/)'s parser and
  extracts the `index=` / `index IN (...)` / `sourcetype=` terms. Coverage tracks what the
  rule really queries, not a hand-maintained field. A rule whose index comes from a macro is
  marked `unknown` rather than guessed.
- **Data health.** Either a `--health` file, or `--splunk-url` to compute it live from one
  `tstats latest(_time) count by index, sourcetype`. A source is healthy if it has events
  newer than `--freshness` (default 24h).
- **Validation.** A [detval](../detval/) JSON report via `--detval`. A technique detval
  proved (`pass`) becomes `proven`; one it executed but missed (`fail`) becomes `broken`.

## Usage

```bash
# From a health file (compute it once, reuse it):
detcov report detections/ --health health.json --detval detval.json --layer coverage.json

# Live health from Splunk (token in $SPLUNK_TOKEN, or --username with $SPLUNK_PASSWORD):
detcov report detections/ --splunk-url https://splunk:8089 --freshness 24h --lookback -30d

# JSON for further processing, and a Navigator layer from a saved report:
detcov report detections/ -f json > coverage-report.json
detcov layer coverage-report.json > coverage.json

# Gate CI on coverage regressions:
detcov report detections/ --health health.json --fail-on at_risk
```

`--fail-on at_risk` exits 1 if any technique is `at_risk`, `no_data`, or `broken`;
`--fail-on broken` only trips on validated misses. Load `coverage.json` into the [ATT&CK
Navigator](https://mitre-attack.github.io/attack-navigator/).

## The health file

Compute it however you like (a scheduled Splunk export, another SIEM, a data-observability
tool) and hand detcov the result:

```json
[
  {"index": "edr", "sourcetype": "edr:process", "last_seen": 1727270000, "events": 120000},
  {"index": "proxy", "sourcetype": "proxy:web", "last_seen": 1726400000, "events": 900000}
]
```

`last_seen` accepts epoch seconds or ISO 8601. A `{"index::sourcetype": {...}}` mapping works
too. If a rule's exact sourcetype isn't listed, detcov falls back to index-level health.

## Where it fits

detcov is the capstone of a four-tool detection-as-code loop:

1. [spl-lint](../spl-lint/) — the SPL is correct.
2. [synthlog](../synthlog/) — realistic data with known attacks.
3. [spltest](../spltest/) — the detection logic works offline.
4. [detval](../detval/) — the detection fires end to end on a live technique.
5. **detcov** — roll it all up into one coverage map that leadership can read and CI can gate.

## Install

```bash
pip install \
  "git+https://github.com/idanbuller/DetectionEngineering#subdirectory=spl-lint" \
  "git+https://github.com/idanbuller/DetectionEngineering#subdirectory=detcov"
```

Python 3.9+, PyYAML and spl-lint only.

## License

MIT

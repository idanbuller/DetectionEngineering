# End-to-end example: catching a macOS AppleScript payload

This walks one detection through all six tools, on a macOS technique:
**osascript (AppleScript) spawning a shell that curls down a payload** —
[T1059.002](https://attack.mitre.org/techniques/T1059/002/). The tricky part is a benign
look-alike (a developer's AppleScript that shells out to `echo`), which a naive rule would
false-positive on.

Run the whole thing offline — no Splunk needed:

```bash
pip install ./spl-lint ./synthlog ./spltest ./detval ./detcov ./sigma2splunk   # from the repo root
examples/end-to-end/run.sh
```

It produces `build/coverage.json` (an ATT&CK Navigator layer) and prints a PASS for the unit
test. Every step below is one command in [run.sh](run.sh).

## The files

| File | Used by | What it is |
|------|---------|------------|
| [sigma/](sigma/) | sigma2splunk | Two macOS Sigma rules (osascript→shell, LaunchAgent persistence) |
| [mapping.yml](mapping.yml) | sigma2splunk | macOS logsources → this env's `edr` index and CIM field names |
| [inventory.yml](inventory.yml) | sigma2splunk, detcov | The index/sourcetype this env collects |
| [dataset.yml](dataset.yml) | synthlog, spltest | A macOS EDR dataset with the attack + a benign look-alike |
| [tests/](tests/) | spltest | The unit test: fires on the attack, not on the look-alike |
| [cases/](cases/) | detval | The live validation case (Atomic Red Team on a canary) |
| [health.yml](health.yml) | detcov | Data-source freshness (`edr:file` is stale on purpose) |
| [recorded/](recorded/) | spltest, detcov | Splunk results and a detval report, recorded so the demo runs offline |

## The steps

**1. Import — sigma2splunk.** Convert the Sigma rules to SPL + detection-as-code, mapped to
the `edr` index and this env's field names, keeping only rules whose data is in
`inventory.yml`:

```bash
sigma2splunk convert sigma --mapping mapping.yml --inventory inventory.yml --only-available -o build/detections
```

**2. Lint — spl-lint.** Gate the generated SPL. Here it's clean apart from info-level leading
wildcards (`contains`/`endswith` produce them — expected):

```bash
spl-lint --fail-on warning build/detections
```

**3. Data — synthlog.** A macOS dataset where the malicious and benign events share the same
process tree (`osascript → /bin/sh`) and differ only in the command line — so the test proves
the rule keys on the right thing:

```bash
synthlog spl dataset.yml --no-background --source edr_process > build/dataset.spl
```

**4. Test offline — spltest.** Score the detection against the dataset's ground truth. The
`recorded/results.json` was captured by running the composed search on a real Splunk; scoring
is offline:

```bash
spltest score tests/osascript_shell.test.yml --results recorded/results.json
```

> Live instead: `spltest run tests/ --splunk-url https://splunk:8089`

**5. Validate live — detval.** How the technique gets proven on a canary. Execution is gated
(the case is `authorized: false` and needs `--allow-execution`), so `list` just shows the
plan:

```bash
detval list cases
```

> Live instead, on a canary you own: `detval run cases/ --splunk-url https://splunk:8089 --allow-execution`

**6. Measure — detcov.** Combine rule presence, data health, and the detval result into one
coverage map:

```bash
detcov report build/detections --health health.yml --detval recorded/detval-results.json --layer build/coverage.json -v
```

You get:

```text
Coverage over 3 technique(s):
  proven                          1   T1059.002  (rule on healthy data, validated firing)
  covered                         1   T1059.004  (rule on healthy data, not yet validated)
  at risk (stale data)            1   T1543.001  (rule exists, but edr:file is stale)
```

That last line is the payoff: the LaunchAgent rule looks fine in the repo, but its data
source went stale, so it isn't actually protecting anything — the kind of gap a rule-count
heat map hides.

## Making it real

Swap the recorded fixtures for your environment:

- Point `--splunk-url` at your Splunk in steps 4–6 instead of the recorded files.
- Fill the real Atomic Red Team test into [cases/T1059.002_osascript.case.yml](cases/), set
  `authorized: true`, and run detval on a macOS canary.
- Replace `sigma/` with a clone of the [Sigma repo](https://github.com/SigmaHQ/sigma) and
  your own `mapping.yml`/`inventory.yml` to import at scale.

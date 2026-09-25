# Detection Engineering

Open-source tools for detection-as-code teams, mostly Splunk-focused.

| Project | What it does |
|---------|--------------|
| [detections/](detections/) | A generic catalog of detection-as-code converted from public Sigma rules, plus an `import.sh` to bring in more at scale (mapped to your indexes, filtered to the data you collect). |
| [sigma2splunk](sigma2splunk/) | Converts Sigma rules to Splunk SPL and detection-as-code, mapped to your indexes/CIM fields and filtered to the data you actually collect. Every emitted query is validated with spl-lint, so nothing broken ships. |
| [spl-lint](spl-lint/) | Linter for Splunk SPL that catches queries which run fine but silently return wrong results, and queries that are slow or truncated at scale. Works as a CLI, a GitHub Action (PR annotations and SARIF) or a pre-commit hook. |
| [synthlog](synthlog/) | Synthetic security logs with injected attack scenarios and ground truth. Describe users, hosts and log sources in YAML, script attacks and benign look-alikes, and get files, Splunk HEC events or a self-contained `makeresults` search for testing detections. |
| [spltest](spltest/) | Unit tests for Splunk detections. Runs a detection's own SPL against a synthlog dataset inline (no indexing) and scores it against the ground truth: attacks caught, attacks missed, false positives on benign look-alikes. JUnit output for CI, and spl-lint hints on failures. |
| [detval](detval/) | Continuous detection validation (purple team as code). Runs an ATT&CK technique on a canary, then polls Splunk to confirm the expected telemetry/notable/risk event fired. Gated execution (Atomic Red Team by GUID, or your own command), detection latency, JUnit output, and an ATT&CK Navigator coverage layer proven by real executions. |
| [detsim](detsim/) | Generates a hit for every detection: synthesizes an event that trips the rule (self-verified), or, for ones it can’t, a simulation guide pointing at the matching Atomic Red Team test. Turns "does this rule even fire?" into one command. |
| [detcov](detcov/) | An honest ATT&CK coverage map. Combines rule presence, data-source health, and detval validation results into one Navigator layer, so a green square means detection actually works — not just that a rule exists. Surfaces rules sitting on dead data and rules that failed validation. |

## Try it end to end

[`examples/end-to-end/`](examples/end-to-end/) drives all six tools on one macOS technique (osascript spawning a shell to fetch a payload). It runs offline — no Splunk needed:

```bash
pip install ./spl-lint ./synthlog ./spltest ./detval ./detcov ./sigma2splunk
examples/end-to-end/run.sh
```

It imports a Sigma rule, lints it, unit-tests it against synthetic data, shows the live validation plan, and writes an ATT&CK Navigator coverage layer.

## License

MIT

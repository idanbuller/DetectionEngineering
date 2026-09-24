# Detection Engineering

Open-source tools for detection-as-code teams, mostly Splunk-focused.

| Project | What it does |
|---------|--------------|
| [spl-lint](spl-lint/) | Linter for Splunk SPL that catches queries which run fine but silently return wrong results, and queries that are slow or truncated at scale. Works as a CLI, a GitHub Action (PR annotations and SARIF) or a pre-commit hook. |
| [synthlog](synthlog/) | Synthetic security logs with injected attack scenarios and ground truth. Describe users, hosts and log sources in YAML, script attacks and benign look-alikes, and get files, Splunk HEC events or a self-contained `makeresults` search for testing detections. |

## Roadmap

- **Detection test runner:** run a detection's SPL against a synthlog dataset and score it
  against `truth.json`, catching both misses and false positives.
- **Coverage graph:** ATT&CK Navigator layers built from a detection repository and weighted
  by whether the underlying data is actually healthy, not just by whether a rule exists.

## License

MIT

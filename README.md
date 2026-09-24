# Detection Engineering

Open-source tools for detection-as-code teams, mostly Splunk-focused.

| Project | What it does |
|---------|--------------|
| [spl-lint](spl-lint/) | Linter for Splunk SPL that catches queries which run fine but silently return wrong results, and queries that are slow or truncated at scale. Works as a CLI, a GitHub Action (PR annotations and SARIF) or a pre-commit hook. |

## Roadmap

- **Synthetic log generator:** produce realistic benign events plus injected attack events
  from field schemas, so every detection gets offline true-positive and false-positive tests.
- **Coverage graph:** ATT&CK Navigator layers built from a detection repository and weighted
  by whether the underlying data is actually healthy, not just by whether a rule exists.

## License

MIT

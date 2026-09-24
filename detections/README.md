# Detections catalog

Detection-as-code, in the format the tools in this repo consume (a `search`, `mitre` tags,
and `provenance`). This directory is the demonstrable, generic catalog — not internal content.

- **`library/`** — a curated, reviewed sample (~16 detections across macOS, Linux, Windows,
  proxy and DNS) converted from the public [Sigma](https://github.com/SigmaHQ/sigma) repo with
  [sigma2splunk](../sigma2splunk/). Committed, and kept passing spl-lint in CI.
- **`import.sh`** — regenerate/expand at scale from the full Sigma repo into `imported/`
  (gitignored). This is how you bring in more.
- **`mapping.yml`** / **`inventory.yml`** — the two files *you* maintain: how Sigma logsources
  map to your indexes and CIM fields, and which index/sourcetype you actually collect.

## Bring in more detections

```bash
pip install ./sigma2splunk ./spl-lint       # from the repo root, once
detections/import.sh                        # clones Sigma, converts into detections/imported/
```

`import.sh` clones SigmaHQ into `detections/.sigma/` (gitignored), runs sigma2splunk with your
`mapping.yml` + `inventory.yml`, and `--only-available` so it keeps only rules whose data you
collect. On the full Sigma repo (~3,100 rules) that yields ~3,000 SPL detections; the ~400
whose logsource isn't in your mapping are emitted without an index — extend `mapping.yml` to
cover them, or ignore them.

Then run the rest of the loop over the result:

```bash
spl-lint imported/                          # gate the generated SPL
detcov report imported/ --health health.yml # see coverage (rule x data health x validation)
```

To promote a converted detection into the tracked `library/`, review it and move the file in.

## Tuning it to your environment

The rules are generic; the two knobs that make them yours are:

- **`mapping.yml`** — set the real index/sourcetype per Sigma logsource and rename Sigma fields
  (`Image`, `CommandLine`, …) to your CIM field names. The most specific `match` wins.
- **`inventory.yml`** — list the index/sourcetype you ingest. `--only-available` uses it to
  skip rules for data you don't have. It's the same file shape as detcov's health file.

## Where this goes in production

In a real program, converted detections are proposed into your **detection repository of
record** (where review, CI, and deployment live) as pull requests — not committed straight to
a catalog. This `library/` is the portfolio/demonstration version of that flow.

## Attribution

These detections are derived from SigmaHQ under the Detection Rule License; each file records
its `provenance` (original `sigma_id` and author). See [NOTICE](NOTICE).

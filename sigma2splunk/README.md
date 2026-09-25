# sigma2splunk

Convert [Sigma](https://github.com/SigmaHQ/sigma) rules to Splunk SPL and detection-as-code
— but only for the data you actually collect, and only when the result is clean SPL.

There are already good Sigma→SPL converters. Two things make this one useful in a real shop:

- **It's data-aware.** Give it an inventory of the index/sourcetype you collect and it skips
  rules whose data you don't have. The public Sigma repo has thousands of rules; most target
  telemetry you may not ingest. This turns a firehose into a this-week backlog.
- **It won't ship broken SPL.** Every converted query is run through
  [spl-lint](../spl-lint/). A rule that would produce an error (or a Sigma feature that
  doesn't translate cleanly) is reported and skipped, not emitted wrong.

```text
$ sigma2splunk convert rules/ --inventory inventory.yml --only-available
filtered (no data)   Traffic To Suspicious CIDR       - data source proxy/proxy is not in the inventory
filtered (no data)   Encoded PowerShell Command Line  - data source windows/XmlWinEventLog is not in the inventory

2 converted, 2 filtered (no data) (4 rule(s)).
```

## What it produces

For each rule it emits Splunk SPL and a detection-as-code skeleton that
[spltest](../spltest/) and [detcov](../detcov/) can consume directly:

```yaml
name: Encoded PowerShell Command Line
search: |
  index=windows sourcetype="XmlWinEventLog" EventCode=4688 ((Image="*\\powershell.exe" AND (CommandLine="* -enc *" OR CommandLine="* -EncodedCommand *")) AND NOT (ParentImage="*\\explorer.exe"))
description: Detects PowerShell launched with an encoded command.
mitre: [T1059.001]
severity: high
references: [https://attack.mitre.org/techniques/T1059/001/]
provenance:
  source: sigma
  sigma_id: 3c73d728-0c8e-4b6e-9d0a-2f0f4f9f7a11
```

MITRE techniques carry over from the rule's `attack.` tags, so the output drops straight into
the coverage map.

## Usage

```bash
sigma2splunk convert rules/                         # print SPL to stdout
sigma2splunk convert rules/ -f yaml                 # detection-as-code YAML instead
sigma2splunk convert rules/ -o detections/          # one detection file per rule
sigma2splunk convert rules/ --inventory inv.yml --only-available   # skip data you don't have
sigma2splunk convert rules/ --mapping map.yml       # your indexes and field names
sigma2splunk convert rule.yml -f json               # full detail incl. lint findings and notes
```

Exit code is 0 normally, 1 with `--fail-on-unsupported` if any rule couldn't be converted,
and 2 on a usage error. Conversion status per rule:

| Status | Meaning |
|--------|---------|
| `converted` | Clean SPL produced, passed spl-lint. |
| `filtered (no data)` | With `--only-available`: the rule's data source isn't in your inventory. |
| `unsupported` | The rule uses a Sigma feature that doesn't translate cleanly (see below). |
| `lint failed` | The SPL parsed but spl-lint found an error; not emitted (override with `--no-strict-lint`). |

## Mapping

The built-in mapping covers common logsources (Windows process creation, Sysmon, Windows
Security, Linux, proxy/DNS/firewall). Point `--mapping` at your own to set indexes,
sourcetypes, extra base-search terms, and field renames to your CIM:

```yaml
defaults:
  field_map: {User: user, ComputerName: dest}
logsources:
  - match: {product: windows, category: process_creation}
    index: edr
    sourcetype: "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
    base: "EventCode=1"
    field_map: {Image: process_path, CommandLine: process, ParentImage: parent_process_path}
  - match: {product: linux}
    index: os
    sourcetype: linux
```

The most specific `match` that fits a rule's logsource wins; field maps stack (defaults, then
the winning logsource).

## The inventory

`--inventory` accepts the same file shape as [detcov](../detcov/)'s health file, so one file
serves both tools:

```yaml
- {index: edr, sourcetype: "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"}
- {index: os}
```

A plain list of index names, or a `{"index::sourcetype": {...}}` mapping, also works.

## Dotted JSON sources (SentinelOne, etc.)

Some sources store events as nested JSON where a field like `tgt.process.image.path` can't be
matched directly — it has to be pulled out with `spath` first. Add an `extract:` table to the
mapping (alias → dotted path) and sigma2splunk emits the `| spath` stages automatically, for
exactly the fields each rule uses:

```yaml
defaults:
  field_map: {Image: process, CommandLine: cmdline, ParentImage: parent_process}
  extract:
    process: tgt.process.image.path
    cmdline: tgt.process.cmdline
    parent_process: src.process.image.path
logsources:
  - {match: {product: windows, category: process_creation}, index: edr, sourcetype: "sentinelone:process"}
```

A converted rule then looks like:

```spl
index=edr sourcetype="sentinelone:process"
| spath input=_raw path=tgt.process.cmdline output=cmdline
| spath input=_raw path=tgt.process.image.path output=process
| search ((process="*\certutil.exe") AND cmdline="*http*")
```

so it runs on the raw JSON with no hand-editing. `extract:` stacks like `field_map` (defaults,
then the matching logsource), and a field a rule uses that has no extract path is reported as a
note.

## What translates

Supported: field matches with `contains` / `startswith` / `endswith`, value lists (OR, or AND
with `|all`), numeric `lt`/`lte`/`gt`/`gte`, `null` (field absent), keyword/full-text
selections, Sigma wildcards, and conditions with `and` / `or` / `not` / parentheses /
`1 of …` / `all of …` (including `them` and `selection_*` patterns).

Not translated cleanly, so skipped as `unsupported` with a reason: `re`, `cidr`, `base64`*,
`utf16`/`wide`, `fieldref`, `expand`, and `N of …` where N > 1. These don't map to Splunk
search syntax without changing the query's shape, and a silently-different detection is worse
than a skipped one. `?` (single-char wildcard) is approximated as `*` with a note, because
Splunk search has no single-char wildcard.

`contains`/`endswith` produce leading wildcards, which spl-lint reports as info (`SPL203`) —
expected for this class of rule.

## Where it fits

sigma2splunk is the front door to the detection-as-code loop: pull public content, convert
what your data supports, then [spltest](../spltest/) it offline, [detval](../detval/) it live,
and roll it into [detcov](../detcov/)'s coverage map.

## Install

```bash
pip install \
  "git+https://github.com/idanbuller/DetectionEngineering#subdirectory=spl-lint" \
  "git+https://github.com/idanbuller/DetectionEngineering#subdirectory=sigma2splunk"
```

Python 3.9+, PyYAML and spl-lint only.

## License

MIT

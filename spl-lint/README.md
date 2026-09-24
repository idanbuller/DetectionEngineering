# spl-lint

A linter for Splunk SPL. It catches queries that **run without error but return the wrong
results**, and queries that are slow or silently truncated at scale, before they reach
production.

```text
$ spl-lint detections/
detections/encoded_powershell.yml:6:11: SPL104 [error] `parent.name` is evaluated as parent . name (concatenation). Quote it as 'parent.name' if it is one field, or write parent . name if you meant concatenation. (Encoded PowerShell from Office parent)
    | where parent.name="winword.exe" or parent.name="excel.exe"
            ^^^^^^^^^^^
detections/encoded_powershell.yml:7:33: SPL103 [error] like() pattern "*-enc*" uses `*`; like() wildcards are `%` and `_`. (Encoded PowerShell from Office parent)
    | where like(process.cmdline, "*-enc*")
                                  ^^^^^^^^
detections/savedsearches.conf:3:47: SPL101 [warning] "or" is searched as a literal word, not an operator; write OR. (Brute force against admin accounts)
    index=auth action=failure user=admin or user=root
                                         ^^

Found 12 issue(s) (5 error, 5 warning, 2 info) in 3 queries across 3 file(s).
```

## Why

A broken detection rarely fails loudly. SPL accepts all of these and runs them fine. Each
one then quietly returns nothing, or far less than it should:

| Query | What Splunk actually does |
|-------|---------------------------|
| `where process.name="cmd.exe"` | `.` is eval's concatenation operator: this compares `process` joined to `name`, not the field `process.name` |
| `user=admin or user=root` | Lowercase `or` is a literal search term, not an operator |
| `where like(cmd, "*-enc*")` | `like()` uses `%`, so `*` only matches a literal asterisk |
| `where user="svc_*"` | No wildcards in `where`/`eval`; it compares with the literal string `svc_*` |
| `sort -count \| ...` | `sort` keeps only the first 10,000 results unless you give it a count |
| `join user [search ...]` | The subsearch stops at 50,000 rows / 60 s and drops the rest without an error |

The first five were verified against a live Splunk instance with `makeresults`, for example:

```spl
| makeresults | eval "p.name"="cmd.exe", p="P", name="N"
| eval unquoted=p.name, quoted='p.name'
```

This returns `unquoted=PN` and `quoted=cmd.exe`. The two `or` queries returned 0 and 2 rows
over the same three events, and `sort -n` on 15,000 events returned 10,000.

Code review catches some of these some of the time. A linter catches them on every pull
request.

## Tested on real detections

Against the 2,176 detections in [splunk/security_content](https://github.com/splunk/security_content)
(commit `64acde7`), spl-lint runs in about 10 seconds and reports 35 correctness findings in
25 files. On review, 33 are real bugs, mostly in drilldown searches:

- `| search dest="$dest$" and src="$src$"`: lowercase `and`, so the drilldown matches nothing
- `| search "$user = "$user$"`: broken quoting
- `| search normalized_risk_object IN ("$user$", | stats ...`: `IN (` is never closed
- `| where Processes.process=Processes.process_path` after `tstats`: unquoted dotted fields

The other 2 are intentional concatenation written without spaces (`eval x=a.b`). spl-lint
flags that pattern on purpose, because it can't tell it apart from a missing quote. Writing
`a . b` makes the intent clear.

## Install

```bash
pip install "git+https://github.com/idanbuller/DetectionEngineering#subdirectory=spl-lint"
```

It needs Python 3.9+. The only dependency is PyYAML.

## Usage

```bash
spl-lint detections/                     # every .spl, .yml/.yaml and savedsearches.conf under it
spl-lint query.spl
spl-lint savedsearches.conf
cat query.spl | spl-lint -               # stdin
spl-lint --explain SPL104                # what a rule checks, and why
spl-lint --list-rules
```

**Inputs**

| File | What is linted |
|------|----------------|
| `*.spl` | The whole file is one query |
| `*.yml`, `*.yaml` | Every string under a `search`, `spl` or `query` key, at any depth (change with `--yaml-keys`). A sibling `name` or `title` is used to label findings. |
| `savedsearches.conf` | The `search =` setting of every stanza, including `\` line continuations |

Findings point at the exact line and column in the original file, including inside YAML
block scalars and multi-line `.conf` values.

**Output formats:** `--format text` (default), `json`, `sarif` (GitHub code scanning and
other SARIF viewers), and `github` (inline pull-request annotations).

**Exit codes:** `0` means no findings at or above `--fail-on` (default `warning`), `1` means
there were findings, and `2` means a usage, config or file error.

## Rules

| ID | Name | Default | What it catches |
|----|------|---------|-----------------|
| SPL000 | syntax-error | error | Unterminated strings, unclosed `(` `[` or comments, empty pipes |
| SPL101 | lowercase-boolean-operator | warning | `and`/`or`/`not`/`in` in a search are literal terms |
| SPL102 | wildcard-in-eval-comparison | error | `where x="abc*"`: `*` is literal in eval/where |
| SPL103 | like-with-asterisk | error | `like(x, "*abc*")`: like() uses `%` |
| SPL104 | unquoted-dotted-field | error | `where a.b=...`: `.` is concatenation in eval |
| SPL105 | single-quoted-literal | warning | `where path='C:\Temp'`: single quotes name a field |
| SPL106 | sort-default-limit | warning | `sort` without a count truncates to 10,000 |
| SPL107 | not-equal-excludes-null | info | `x!=y` also drops events without `x` |
| SPL201 | missing-index | warning | Base search without `index=` |
| SPL202 | index-wildcard | warning | `index=*` |
| SPL203 | leading-wildcard | info | `*term` in the base search can't use the index |
| SPL204 | join | warning | join's subsearch is silently truncated |
| SPL205 | transaction | warning | transaction is memory-heavy and can evict sessions |
| SPL206 | subsearch-truncation | info | Subsearch output is silently cut at 10,000 results |
| SPL207 | late-search-filter | info | `\| search` right after the base search |
| SPL208 | bare-spath | info | `spath` without a path extracts everything |
| SPL209 | table-before-processing | info | `table` mid-pipeline moves work to the search head |
| SPL301 | uppercase-keyword | style, off by default | `STATS ... BY` instead of `stats ... by` |

Each rule has an explanation and bad/good examples in [docs/rules.md](docs/rules.md) and via
`spl-lint --explain <rule>`.

## Configuration

Put a `.spl-lint.yml` in your repository root (spl-lint looks in the current directory and its
parents):

```yaml
select: [SPL1, SPL2]          # ids, id prefixes, names or categories (correctness, performance, style)
ignore: [SPL207]
fail_on: warning              # error | warning | info | style
severity:
  SPL204: error               # join is banned here
  SPL301: warning             # enforce lowercase keywords
yaml_keys: [search, spl]
exclude: ["*/deprecated/*"]
```

Command-line flags (`--select`, `--ignore`, `--fail-on`, `--yaml-keys`) override the file.

**Suppressing a finding in one query.** Use an SPL comment, which Splunk ignores:

```spl
index=auth action=success
| join type=inner user [| inputlookup small_allowlist.csv]
``` spl-lint: disable=SPL204 -- the lookup has 40 rows ```
```

`spl-lint: disable` with no list disables every rule for that query.

## CI

**GitHub Actions.** Findings show up as annotations on the pull-request diff:

```yaml
- uses: actions/checkout@v4
- uses: idanbuller/DetectionEngineering/spl-lint@main
  with:
    paths: detections
    fail-on: warning
```

To also send findings to GitHub code scanning, add `sarif-file: spl-lint.sarif` and upload
it with `github/codeql-action/upload-sarif`.

**pre-commit**

```yaml
repos:
  - repo: local
    hooks:
      - id: spl-lint
        name: spl-lint
        language: python
        additional_dependencies:
          - "git+https://github.com/idanbuller/DetectionEngineering#subdirectory=spl-lint"
        entry: spl-lint
        files: '(\.spl|\.ya?ml|savedsearches\.conf)$'
```

## How it works

SPL has no published grammar, so spl-lint does not try to be a full parser. It splits a query
into pipelines and commands, and it understands:

- quoting and escapes (including `\"` outside strings)
- ```` ``` comments ``` ````
- `` `macros` ``
- `%template%` and `$token$` placeholders
- nested `[subsearches]`, including `appendpipe`/`foreach` blocks, which run on the current
  results

Commands whose arguments are eval expressions (`eval`, `where`, `fieldformat`) are tokenized
differently from search-syntax commands, because the same characters mean different things
in each. Anything it cannot make sense of becomes an SPL000 finding rather than a crash.

A base search that starts with a macro or template placeholder is assumed to get its index
from there.

## Development

```bash
cd spl-lint
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest
python -m spl_lint.docs > docs/rules.md     # after changing rule metadata
```

To add a rule, subclass `Rule` in `src/spl_lint/rules/`, decorate it with `@register`, and
fill in `bad` and `good` examples. The test suite automatically checks that `bad` triggers
the rule and that `good` is clean.

## License

MIT

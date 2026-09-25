# detsim

Generate a **hit for every detection** — no matter what it is. detsim reads a detection's SPL,
works out what an event that trips it must look like, and produces one. For the detections it
can't synthesize automatically, it writes a **simulation guide** pointing at the matching
[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) test so you can run it for
real.

```text
$ detsim simulate detections/library
hit   T1105                File Download Via Nscurl - MacOS
hit   T1027.001            Binary Padding - MacOS
hit   T1071.004            Cobalt Strike DNS Beaconing
...
16/16 detection(s) auto-simulatable; 0 need manual simulation (see the guides).
```

Across the full converted SigmaHQ set (~3,000 rules), detsim auto-generates a hit for **~97%**;
the rest get an Atomic Red Team guide.

## How it works

1. **Parse.** It parses the detection's SPL with [spl-lint](../spl-lint/)'s tokenizer into a
   boolean AST of its match conditions (`AND`/`OR`/`NOT`, field comparisons, wildcards,
   numeric bounds, `IN (...)`, full-text keywords). `| spath` stages are ignored — detsim
   synthesizes the extracted aliases directly.
2. **Solve.** It walks the AST and builds an event that satisfies it: every `AND`, one branch
   of each `OR`, numeric bounds picked past the threshold, and `NOT` fields left unset so the
   exclusions stay false. Wildcards become concrete values (`"*/nscurl"` → `.../nscurl`,
   `"*--download *"` → `...--download ...`).
3. **Self-verify.** It re-checks the synthesized event against the AST with a matcher. If it
   can't build a satisfying event (a contradiction, or a construct it doesn't model), the
   detection is reported as **manual** with a guide, rather than emitting a wrong event.

## Output

```bash
detsim simulate detections/library                 # summary
detsim simulate detections/library -v              # print each hit search
detsim simulate detections/library -o sims/        # a .spl hit + .md guide per detection
detsim simulate rule.yml -f json                   # event, verification search, techniques
```

For an auto-simulatable detection you get a self-contained search that returns a hit — run it
in Splunk to confirm the logic fires:

```spl
| makeresults format=json data="[{\"index\":\"edr\",\"sourcetype\":\"edr:process\",\"process\":\"/truncate\",\"cmdline\":\"-s +\"}]"
| search index=edr sourcetype="edr:process" ((process="*/truncate" AND cmdline="*-s +*") OR ...)
```

(Verified: that search returns a hit on a live Splunk.)

For a **manual** one, the guide names the technique, links its Atomic Red Team test and ATT&CK
page, and tells you to run it on a canary and confirm with [detval](../detval/).

## Mapping each rule to a specific Atomic Red Team GUID

Pass `--atomics <path-to-atomic-red-team-clone>` and detsim maps each rule to the specific
Atomic test(s) most likely to trip it — not just the technique folder. It scores every test in
the rule's technique by how many of the rule's own match-literals (`nscurl`, `certutil`,
`/priv`, …) appear in the test's name and command, weighting the name higher:

```text
$ detsim simulate detections/library --atomics ~/atomic-red-team
hit   T1105   File Download Via Nscurl - MacOS  [atomic 5bcefe5f-... File download via nscurl]
```

The guide then gives the exact `Invoke-AtomicTest T#### -TestGuids <guid>` command and a
ready-to-paste detval case (`execute: {executor: atomic, atomic_guid: <guid>}`), so the hit
you simulate synthetically is the same one you validate for real. Rules with no literal overlap
fall back to a technique-only match.

## Three ways to actually make it fire

detsim's synthetic hit proves the **logic**. To exercise the **pipeline**, pick by risk:

| Method | What it proves | Tool |
|--------|----------------|------|
| Paste the generated `.spl` | The search matches a crafted event | detsim → Splunk |
| Inject the event into a test index | Ingestion + parsing + the search | `synthlog hec` |
| Run the real technique on a canary | The whole chain end to end | Atomic Red Team → [detval](../detval/) |

## Where it fits

detsim closes the loop: after [sigma2splunk](../sigma2splunk/) imports rules that fit your
data and [spl-lint](../spl-lint/) gates them, detsim gives you a guaranteed hit (or a guide)
for each, so you can confirm every detection actually triggers before it ships.

## Install

```bash
pip install \
  "git+https://github.com/idanbuller/DetectionEngineering#subdirectory=spl-lint" \
  "git+https://github.com/idanbuller/DetectionEngineering#subdirectory=detsim"
```

Python 3.9+, PyYAML and spl-lint only.

## License

MIT

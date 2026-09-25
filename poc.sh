#!/usr/bin/env bash
# A team-facing proof of concept: the full detection-as-code pipeline, end to end.
#
#   Install once (from this directory):
#     python3 -m venv .venv
#     .venv/bin/pip install ./spl-lint ./synthlog ./spltest ./detval ./detcov ./sigma2splunk ./detsim
#     export PATH="$PWD/.venv/bin:$PATH"
#
#   Then:  ./poc.sh
#
# Act 1 runs fully offline (no Splunk). Act 2 (import at scale) clones SigmaHQ and
# Atomic Red Team the first time; skip it with SKIP_SCALE=1.
set -euo pipefail
cd "$(dirname "$0")"

bold() { printf "\n\033[1m== %s ==\033[0m\n" "$*"; }
note() { printf "   \033[2m%s\033[0m\n" "$*"; }

for t in sigma2splunk spl-lint synthlog spltest detval detcov detsim; do
  command -v "$t" >/dev/null || { echo "missing '$t' — see the install lines at the top of poc.sh"; exit 1; }
done

WORK=poc-workspace
mkdir -p "$WORK"

########################################################################
bold "ACT 1 — the full pipeline on one macOS detection (offline)"
########################################################################
note "Import a Sigma rule scoped to our data, lint it, generate synthetic data with a known"
note "attack + benign twin, unit-test the detection, show the live-validation plan, map coverage."
examples/end-to-end/run.sh

########################################################################
bold "ACT 2 — the same pipeline at scale, from the public Sigma repo"
########################################################################
if [ "${SKIP_SCALE:-0}" = "1" ]; then
  note "SKIP_SCALE=1 set; skipping the at-scale import."
  exit 0
fi

SIGMA_DIR="${SIGMA_DIR:-$WORK/sigma}"
ART_DIR="${ART_DIR:-$WORK/atomic-red-team}"
[ -d "$SIGMA_DIR/rules" ] || { note "cloning SigmaHQ (first run only)…"; git clone --depth 1 -q https://github.com/SigmaHQ/sigma "$SIGMA_DIR"; }
[ -d "$ART_DIR/atomics" ] || { note "cloning Atomic Red Team (first run only)…"; git clone --depth 1 -q https://github.com/redcanaryco/atomic-red-team "$ART_DIR"; }

bold "1. Review SigmaHQ, keep only what our data supports"
note "$(find "$SIGMA_DIR/rules" -name '*.yml' | wc -l | tr -d ' ') Sigma rules on disk; converting the ones our inventory collects…"
sigma2splunk convert "$SIGMA_DIR/rules" \
  --mapping detections/mapping.yml --inventory detections/inventory.yml --only-available \
  -o "$WORK/imported" 2>&1 | tail -1

bold "2. Lint every converted detection"
lint_summary=$(spl-lint "$WORK/imported" 2>/dev/null | tail -1 || true)
note "$lint_summary"

bold "3. Generate a hit for each, mapped to its Atomic Red Team test GUID"
detsim simulate "$WORK/imported" --atomics "$ART_DIR" 2>/dev/null > "$WORK/sim.txt" || true
tail -1 "$WORK/sim.txt"
note "examples of rules mapped to a specific Atomic Red Team GUID:"
grep "\[atomic [0-9a-f]" "$WORK/sim.txt" | head -5 | sed 's/^/   /' || true

echo
note "Everything above is repeatable and gated by CI. The only stage left to wire to your"
note "environment is deploying vetted detections to Splunk as scheduled/correlation searches."

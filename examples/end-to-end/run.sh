#!/usr/bin/env bash
# End-to-end demo: import a macOS Sigma rule, lint it, test it offline, show the live
# validation plan, and roll it into a coverage map. Runs fully offline (no Splunk).
#
# Install the tools first (from the repo root):
#   pip install ./spl-lint ./synthlog ./spltest ./detval ./detcov ./sigma2splunk
set -euo pipefail
cd "$(dirname "$0")"

for tool in sigma2splunk spl-lint synthlog spltest detval detcov; do
  command -v "$tool" >/dev/null || { echo "missing $tool -- see the install line at the top of run.sh"; exit 1; }
done

rm -rf build && mkdir -p build/detections

echo "== 1. sigma2splunk: import Sigma -> detections, only for data we collect =="
sigma2splunk convert sigma --mapping mapping.yml --inventory inventory.yml --only-available -o build/detections

echo; echo "== 2. spl-lint: the generated SPL must be clean (info-level wildcards are fine) =="
spl-lint --fail-on warning build/detections

echo; echo "== 3. synthlog: a macOS dataset with the attack and a benign look-alike =="
synthlog validate dataset.yml
synthlog spl dataset.yml --no-background --source edr_process > build/dataset.spl
echo "wrote build/dataset.spl (a self-contained | makeresults search you can paste into Splunk)"

echo; echo "== 4. spltest: unit-test the detection offline against recorded Splunk results =="
echo "   (live: spltest run tests/ --splunk-url https://splunk:8089)"
spltest score tests/osascript_shell.test.yml --results recorded/results.json

echo; echo "== 5. detval: how the technique would be validated live on a canary =="
echo "   (live: detval run cases/ --splunk-url https://splunk:8089 --allow-execution)"
detval list cases

echo; echo "== 6. detcov: coverage = rule x data-health x validation =="
echo "   (live: swap --health for --splunk-url https://splunk:8089)"
detcov report build/detections --health health.yml --detval recorded/detval-results.json --layer build/coverage.json -v

echo; echo "Done. build/coverage.json loads into the ATT&CK Navigator."

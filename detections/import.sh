#!/usr/bin/env bash
# Import detections at scale from the public Sigma repo into imported/ (gitignored).
# The curated, reviewed sample lives in library/. Regenerate/expand with this script.
#
#   detections/import.sh            # clones Sigma into detections/.sigma and converts
#   detections/import.sh /path/sigma
set -euo pipefail
cd "$(dirname "$0")"
command -v sigma2splunk >/dev/null || { echo "pip install ../sigma2splunk ../spl-lint first"; exit 1; }
SIGMA=${1:-.sigma}
[ -d "$SIGMA/rules" ] || git clone --depth 1 https://github.com/SigmaHQ/sigma "$SIGMA"
sigma2splunk convert "$SIGMA/rules" --mapping mapping.yml --inventory inventory.yml --only-available -o imported
echo
echo "wrote detections to imported/ (gitignored). Next:"
echo "  spl-lint imported/                 # gate the generated SPL"
echo "  detcov report imported/ --health health.yml   # see coverage"

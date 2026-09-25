#!/usr/bin/env bash
# Generate a hit (or a simulation guide) for every detection in the catalog.
#   detections/simulate.sh            # library/ -> sims/
#   detections/simulate.sh imported   # imported/ -> sims-imported/
set -euo pipefail
cd "$(dirname "$0")"
command -v detsim >/dev/null || { echo "pip install ../detsim ../spl-lint first"; exit 1; }
SRC=${1:-library}
OUT=${2:-sims}
detsim simulate "$SRC" -o "$OUT"
echo "guides + hit searches in $OUT/ (see $OUT/SIMULATE.md)"

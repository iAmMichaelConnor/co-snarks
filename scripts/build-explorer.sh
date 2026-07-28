#!/usr/bin/env bash
# Build the co-SNARK UltraHonk performance explorer: one self-contained HTML file
# (publishable as a Claude Artifact) from the in-repo bench data + page template.
#
#   scripts/build-explorer.sh [OUT_HTML]        # default: site/explorer.html
#
# The whole pipeline is in-repo (was previously only in ephemeral session scratchpad):
#   scripts/bench-explorer-data.py   data ingest: bench-results/<dirs> -> site-data.json
#   scripts/explorer.template.html   the page (HTML/CSS/JS) with a `/*__DATA__*/ null` slot
#   bench-results/<...>              the measured datasets (override the dirs via env vars)
#
# Output lands next to the bench data it renders, in bench-results/site/
# (a generated-artifact dir, gitignored):
#   bench-results/site/site-data.json   the ingested data
#   bench-results/site/explorer.html    the single self-contained page with that data inlined
# Publish bench-results/site/explorer.html to the SAME artifact URL
# (90d4bf98-8b70-4f9e-814b-5d07b20daefa) so the link Mike has stays stable.
#
# Point it at a newer run by exporting FULL / NETEM / KSWEEP before calling.
set -euo pipefail
cd "$(dirname "$0")/.."

FULL=${FULL:-bench-results/2026-07-27-v3.2-full}
NETEM=${NETEM:-bench-results/2026-07-27-v3.2-netem}
KSWEEP=${KSWEEP:-bench-results/2026-07-28-k-sweep/k-sweep.csv}   # a CSV file, not the dir
OUTDIR=${OUTDIR:-bench-results/site}
OUT=${1:-$OUTDIR/explorer.html}
DATA="$OUTDIR/site-data.json"
mkdir -p "$OUTDIR" "$(dirname "$OUT")"

python3 scripts/bench-explorer-data.py \
  --full "$FULL" \
  --netem "v32=$NETEM" \
  --ksweep "$KSWEEP" \
  -o "$DATA"

python3 - "$DATA" "$OUT" <<'PY'
import sys
data = open(sys.argv[1]).read()
tmpl = open("scripts/explorer.template.html").read()
tok = "/*__DATA__*/ null"
assert tok in tmpl, "placeholder not found in scripts/explorer.template.html"
open(sys.argv[2], "w").write(tmpl.replace(tok, "/*__DATA__*/ " + data))
print("wrote", sys.argv[2])
PY

echo "Publish via the Artifact tool with file_path=$OUT and url=https://claude.ai/code/artifact/90d4bf98-8b70-4f9e-814b-5d07b20daefa to keep the same link."

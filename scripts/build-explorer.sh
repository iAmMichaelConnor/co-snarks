#!/usr/bin/env bash
# Build the co-SNARK UltraHonk performance explorer: one self-contained HTML file
# (publishable as a Claude Artifact) from the in-repo bench data + page template.
#
#   scripts/build-explorer.sh [OUT_HTML]        # default: <run>/site/explorer.html
#
# The whole pipeline is in-repo (was previously only in ephemeral session scratchpad):
#   scripts/bench-explorer-data.py   data ingest: run subdirs -> site-data.json
#   scripts/explorer.template.html   the page (HTML/CSS/JS) with a `/*__DATA__*/ null` slot
#
# A benchmark "run" is one directory holding every measurement type as subdirs:
#   <run>/loopback-matrix/      the full loopback prover x circuit x zk matrix
#   <run>/network-emulation/    the distance-tier sweep (tc network-emulation shaping)
#   <run>/batch-size-sweep/     the batch-size-K sweep (k-sweep.csv)
#   <run>/site/                 GENERATED explorer output (gitignored) — lives with its data
# Point it at a different run by exporting RUN=... before calling.
#
# Publish <run>/site/explorer.html to the SAME artifact URL
# (90d4bf98-8b70-4f9e-814b-5d07b20daefa) so the link Mike has stays stable.
set -euo pipefail
cd "$(dirname "$0")/.."

RUN=${RUN:-bench-results/2026-07-27-v3.2}
LOOPBACK=${LOOPBACK:-$RUN/loopback-matrix}
NETWORK_EMULATION=${NETWORK_EMULATION:-$RUN/network-emulation}
BATCH_SWEEP=${BATCH_SWEEP:-$RUN/batch-size-sweep/k-sweep.csv}   # a CSV file, not the dir
OUTDIR=${OUTDIR:-$RUN/site}
OUT=${1:-$OUTDIR/explorer.html}
DATA="$OUTDIR/site-data.json"
mkdir -p "$OUTDIR" "$(dirname "$OUT")"

python3 scripts/bench-explorer-data.py \
  --full "$LOOPBACK" \
  --network-emulation "v32=$NETWORK_EMULATION" \
  --ksweep "$BATCH_SWEEP" \
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

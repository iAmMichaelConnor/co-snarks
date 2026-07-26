#!/usr/bin/env bash
# Detached launcher for bench-0_5.sh: runs the matrix serially, then
# aggregates for the explorer and drops a BENCH_DONE sentinel line.
#
# There is deliberately NO quiet-gate: this box is a sysbox on a shared
# mainframe, so /proc/loadavg is HOST-wide (other tenants included) and a
# "wait for load < N" gate can starve forever chasing neighbours' load
# (it did, 2026-07-24). Instead: run when convenient; every CSV row is
# stamped with host_load1m so each absolute number carries its own noise
# context; use medians + same-window ratios for fine comparisons.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# v2 (2026-07-24, Mike): results live INSIDE the repo so runs are visible in
# git status and committable alongside the code that produced them.
OUT="${BENCH_OUT:-$ROOT/bench-results/$(date +%Y-%m-%d)}"
mkdir -p "$OUT"
LOG="$OUT/launcher.log"

echo "$(date -Is) launcher started (host load1m=$(awk '{print $1}' /proc/loadavg) — HOST-wide, incl. other tenants)" >>"$LOG"
BENCH_OUT="$OUT" bash "$ROOT/scripts/bench-0_5.sh" >>"$LOG" 2>&1
rc=$?
echo "$(date -Is) bench finished rc=$rc" >>"$LOG"
# Aggregate into the explorer's data shape (medians, loopback only, nulls
# where unmeasured) so the next session bakes it in + redeploys the same
# artifact URL (ch. 22 §5/V7). Never fabricates: absent cells stay modeled.
python3 "$ROOT/scripts/bench-to-site.py" "$OUT/results.csv" "$OUT/site-anchors.json" >>"$LOG" 2>&1 \
  && echo "$(date -Is) site-anchors.json + RESULTS.md written" >>"$LOG"
# v2.1: pk-gen/prove phase split is now produced with every run (the v2 run
# needed this recovered retroactively — bench methodology fix, ch. 24 §3a).
python3 "$ROOT/scripts/bench-retro-phase-split.py" "$OUT" >>"$LOG" 2>&1 \
  && echo "$(date -Is) phase-split.csv written" >>"$LOG"
echo "BENCH_DONE rc=$rc out=$OUT   (bake: read $OUT/site-anchors.json into the explorer's ANCHOR block, then redeploy)" >>"$LOG"
exit $rc

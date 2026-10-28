#!/usr/bin/env bash
# Run the serial matrix and derive report, phase, and transfer-model outputs.
# host_load1m is host-wide and may include other tenants; it is recorded rather
# than used as a load gate. Compare repeated runs from the same time window.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${BENCH_OUT:-$ROOT/bench-results/$(date +%Y-%m-%d)}"
if [[ -z "${BENCH_OUT:-}" && -s "$OUT/results.csv" ]]; then
  OUT="$OUT-$(date +%H%M%S)"
fi
mkdir -p "$OUT"
LOG="$OUT/launcher.log"
echo "$(date -Is) launcher started (host load1m=$(awk '{print $1}' /proc/loadavg))" >>"$LOG"
BENCH_OUT="$OUT" bash "$ROOT/scripts/bench-0_5.sh" >>"$LOG" 2>&1
rc=$?
echo "$(date -Is) bench finished rc=$rc" >>"$LOG"
if [[ $rc -eq 0 ]]; then
  python3 "$ROOT/scripts/bench-to-site.py" "$OUT/results.csv" "$OUT/site-anchors.json" >>"$LOG" 2>&1 || rc=$?
  python3 "$ROOT/scripts/bench-phase-split.py" "$OUT" >>"$LOG" 2>&1 || rc=$?
  python3 "$ROOT/scripts/bench-tier-model.py" "$OUT" >>"$LOG" 2>&1 || rc=$?
fi
echo "BENCH_DONE rc=$rc out=$OUT" >>"$LOG"
exit "$rc"

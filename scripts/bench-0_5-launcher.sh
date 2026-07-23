#!/usr/bin/env bash
# Overnight launcher for bench-0_5.sh: waits until the box is genuinely
# quiet (benchmark numbers under contention are worthless), then runs the
# matrix serially. Quiet = 2 consecutive checks (5 min apart) with 1-min
# loadavg < 25 AND no heavy project processes. Hard cap: if the box never
# quiets within 10 h, run anyway and stamp the results as CONTENDED.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${BENCH_OUT:-$HOME/bench-0_5-results/$(date +%Y-%m-%d)}"
mkdir -p "$OUT"
LOG="$OUT/launcher.log"
echo "launcher armed $(date -Is); waiting for idle" >>"$LOG"

quiet_checks=0
waited=0
contended=""
while [[ $quiet_checks -lt 2 ]]; do
  load=$(awk '{print int($1)}' /proc/loadavg)
  heavy=$(pgrep -c -f '[c]ompare|[f]ast-check|[a]ztec |[m]pc-node|[p]laindriver|[b]b prove|[c]argo (test|build|run)' || true)
  if [[ $load -lt 25 && ${heavy:-0} -eq 0 ]]; then
    quiet_checks=$((quiet_checks + 1))
    echo "$(date -Is) quiet check $quiet_checks/2 (load=$load)" >>"$LOG"
  else
    quiet_checks=0
    echo "$(date -Is) busy (load=$load heavy=$heavy), waiting" >>"$LOG"
  fi
  sleep 300
  waited=$((waited + 300))
  if [[ $waited -ge 36000 ]]; then
    contended="CONTENDED-"
    echo "$(date -Is) 10h cap reached — running anyway (results flagged CONTENDED)" >>"$LOG"
    break
  fi
done

echo "$(date -Is) starting bench (flag: ${contended:-clean})" >>"$LOG"
BENCH_OUT="$OUT" bash "$ROOT/scripts/bench-0_5.sh" >>"$LOG" 2>&1
rc=$?
[[ -n $contended ]] && mv "$OUT/results.csv" "$OUT/${contended}results.csv" 2>/dev/null
echo "$(date -Is) bench finished rc=$rc" >>"$LOG"
# Aggregate into the explorer's data shape (medians, loopback only, nulls
# where unmeasured) so the next session bakes it in + redeploys the same
# artifact URL (ch. 22 §5/V7). Never fabricates: absent cells stay modeled.
csv="$OUT/${contended}results.csv"; [[ -f $csv ]] || csv="$OUT/results.csv"
python3 "$ROOT/scripts/bench-to-site.py" "$csv" "$OUT/site-anchors.json" >>"$LOG" 2>&1 \
  && echo "$(date -Is) site-anchors.json written" >>"$LOG"
echo "BENCH_DONE rc=$rc out=$OUT   (bake: read $OUT/site-anchors.json into the explorer's ANCHOR block, then redeploy)" >>"$LOG"
exit $rc

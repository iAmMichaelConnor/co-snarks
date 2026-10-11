#!/usr/bin/env bash
# Parallel acceptance sweep (ch. 15 §4.9a): the full compare.sh +
# compare_mpc.sh matrix, sharded over disjoint circuit subsets that run
# CONCURRENTLY. Within a shard, compare.sh (plain) runs before
# compare_mpc.sh (REP3) because both write the same per-circuit artifact
# paths; across shards the circuit sets are disjoint so nothing collides
# (per-circuit artifacts + scoped cleanup_circuit; per-shard CONFIG_DIR
# gives each shard its own REP3 mesh ports).
#
# Meticulousness guarantees:
#  - circuit lists are extracted from the compare scripts themselves, so a
#    circuit added upstream is automatically included;
#  - the shard partition is ASSERTED to cover the full union exactly
#    (hard failure otherwise);
#  - CIRCUIT_FILTER inside the scripts hard-errors on unknown names.
#
# Usage: scripts/acceptance-parallel.sh [num_shards]   (default 4)
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/co-noir/co-noir/examples"

K=${1:-4}
LOGDIR=$(mktemp -d)
CFGROOT=$(mktemp -d)
echo "== parallel acceptance: $K shards; logs in $LOGDIR"

# --- canonical circuit lists, extracted from the scripts themselves ---
get_array() { # file varname -> prints space-separated values
  bash -c "$(grep -m1 "^$2=" "$1"); printf '%s ' \"\${$2[@]}\""
}
PLAIN_ALL=$(get_array compare.sh test_cases)
MPC_BASE=$(get_array compare_mpc.sh test_cases)
MPC_SLOW=$(get_array compare_mpc.sh slow_test_cases)
MPC_ALL="$MPC_BASE $MPC_SLOW"
UNION=$(tr ' ' '\n' <<<"$PLAIN_ALL $MPC_ALL" | grep -v '^$' | sort -u | tr '\n' ' ')

# --- weight-balanced greedy partition (heaviest first) ---
weight() {
  case $1 in
    recursion_zk) echo 20 ;;
    aes128) echo 10 ;;
    bb_sha256_compression) echo 8 ;;
    recursion) echo 6 ;;
    blake3|blake2s) echo 3 ;;
    pedersen_commitment|pedersen_hash|embedded_curve_add) echo 2 ;;
    *) echo 1 ;;
  esac
}
declare -a SHARD_SET SHARD_W
for ((k=0; k<K; k++)); do SHARD_SET[k]=""; SHARD_W[k]=0; done
# sort circuits by descending weight
sorted=$(for c in $UNION; do echo "$(weight "$c") $c"; done | sort -rn | awk '{print $2}')
for c in $sorted; do
  best=0
  for ((k=1; k<K; k++)); do
    [[ ${SHARD_W[k]} -lt ${SHARD_W[best]} ]] && best=$k
  done
  SHARD_SET[best]+="$c "
  SHARD_W[best]=$(( SHARD_W[best] + $(weight "$c") ))
done

# --- coverage assertion: union of shards == full union, exactly ---
recombined=$(tr ' ' '\n' <<<"${SHARD_SET[*]}" | sort -u | grep -v '^$' | tr '\n' ' ')
if [[ "$recombined" != "$UNION" ]]; then
  echo "::error:: shard partition does not cover the circuit union exactly"
  echo "union:      $UNION"
  echo "recombined: $recombined"
  exit 2
fi
n_union=$(wc -w <<<"$UNION")
echo "== covering $n_union circuits (plain: $(wc -w <<<"$PLAIN_ALL"), mpc: $(wc -w <<<"$MPC_ALL"))"

# --- per-shard thread budget: 80% of cores / (K shards x 3 parties) ---
PER_PARTY=$(( $(nproc --all) * 8 / (30 * K) ))
[[ $PER_PARTY -lt 4 ]] && PER_PARTY=4

# --- prebuild both binaries once so shards never race the cargo lock ---
echo "== prebuild plaindriver + co-noir"
cargo build --release --bin plaindriver --bin co-noir || exit 1

# --- per-shard mesh configs (disjoint port triples, away from 10000-2) ---
for ((k=0; k<K; k++)); do
  mkdir -p "$CFGROOT/cfg$k"
  base=$((10100 + k * 10))
  for n in 1 2 3; do
    sed -e "s/10000/$base/g" -e "s/10001/$((base + 1))/g" \
        -e "s/10002/$((base + 2))/g" \
      "configs/party$n.toml" >"$CFGROOT/cfg$k/party$n.toml"
  done
done

# --- run shards ---
run_shard() { # k
  local k=$1 rc=0
  local plain="" mpc=""
  for c in ${SHARD_SET[k]}; do
    [[ " $PLAIN_ALL " == *" $c "* ]] && plain+="$c "
    [[ " $MPC_ALL "   == *" $c "* ]] && mpc+="$c "
  done
  if [[ -n "$plain" ]]; then
    RAYON_NUM_THREADS=$PER_PARTY CIRCUIT_FILTER="$plain" \
      bash compare.sh || rc=1
  fi
  if [[ -n "$mpc" ]]; then
    RAYON_NUM_THREADS=$PER_PARTY CIRCUIT_FILTER="$mpc" \
      CONFIG_DIR="$CFGROOT/cfg$k" TEST_SLOWER_CIRCUITS=1 \
      bash compare_mpc.sh || rc=1
  fi
  return $rc
}
declare -a PIDS
for ((k=0; k<K; k++)); do
  echo "== shard $k (weight ${SHARD_W[k]}): ${SHARD_SET[k]}"
  run_shard "$k" >"$LOGDIR/shard$k.log" 2>&1 &
  PIDS[k]=$!
done

rc=0
for ((k=0; k<K; k++)); do
  if wait "${PIDS[k]}"; then
    echo "shard $k: PASS"
  else
    echo "shard $k: FAIL — errors:"
    grep '::error::' "$LOGDIR/shard$k.log" | head -20
    rc=1
  fi
done

if [[ $rc -eq 0 ]]; then
  echo "acceptance-parallel: PASS ($n_union circuits, $K shards; logs: $LOGDIR)"
else
  echo "acceptance-parallel: FAIL (logs: $LOGDIR)"
fi
exit $rc

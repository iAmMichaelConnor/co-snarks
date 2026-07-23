#!/usr/bin/env bash
# PLAN 0.5 benchmark matrix (first real execution, 2026-07-23 overnight).
# Measures, per cell, wall-clock for each MPC phase — share-split, witness
# extension (3 parties, parallel), prove (3 parties, parallel), verify —
# against single-prover baselines (bb, plaindriver), so we can answer:
#   * absolute cost of co-proving vs plain proving at several circuit sizes
#   * ZK overhead
#   * REP3 vs Shamir (Shamir cells are best-effort: SKIP+continue on error)
# Matrix: circuits {poseidon (small), bb_sha256_compression (medium),
# recursion_zk (large)} x protocol {REP3, SHAMIR} x {nonzk, zk}, 3 reps.
# Results: CSV (one row per timed phase per rep) + raw logs in BENCH_OUT.
#
# MUST run on a QUIET box (numbers are worthless under contention) — use
# scripts/bench-0_5-launcher.sh, which waits for idle. Serial by design.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/co-noir/co-noir/examples"
source "$ROOT/versions.env"
BB="${BARRETENBERG_BINARY:-${BARRETENBERG_BINARY_DEFAULT/#\$HOME/$HOME}}"
BENCH_OUT="${BENCH_OUT:?set BENCH_OUT to a results dir}"
mkdir -p "$BENCH_OUT"
CSV="$BENCH_OUT/results.csv"
echo "circuit,protocol,zk,rep,phase,seconds,rc" >"$CSV"
# Fixed thread cap = measured small-circuit optimum (ch. 14 §6.3); keeps
# cells comparable. One large-circuit all-cores probe at the end.
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-16}"

CIRCUITS=(poseidon bb_sha256_compression recursion_zk)
REPS=3
BIN="$ROOT/target/release/co-noir"
PLAINDRIVER="$ROOT/target/release/plaindriver"
cargo build --release --bin co-noir --bin plaindriver >/dev/null 2>&1

declare -a pids
now_ms() { date +%s%3N; }
row() { echo "$1,$2,$3,$4,$5,$6,$7" >>"$CSV"; }
timed() { # circuit proto zk rep phase cmd...
  local c=$1 p=$2 z=$3 r=$4 ph=$5; shift 5
  local t0 t1 rc
  t0=$(now_ms); "$@" >>"$BENCH_OUT/${c}_${p}_${z}_r${r}.log" 2>&1; rc=$?
  t1=$(now_ms)
  row "$c" "$p" "$z" "$r" "$ph" "$(awk "BEGIN{printf \"%.3f\", ($t1-$t0)/1000}")" "$rc"
  return $rc
}

for c in "${CIRCUITS[@]}"; do
  (cd "test_vectors/$c" && nargo execute >/dev/null 2>&1)
  # --- single-prover baselines ---
  for r in $(seq 1 $REPS); do
    timed "$c" bb nonzk "$r" prove \
      "$BB" prove --scheme ultra_honk --oracle_hash poseidon2 --disable_zk \
        -b "test_vectors/$c/target/$c.json" -w "test_vectors/$c/target/$c.gz" \
        --write_vk -o "test_vectors/$c/"
    timed "$c" bb zk "$r" prove \
      "$BB" prove --scheme ultra_honk --oracle_hash poseidon2 \
        -b "test_vectors/$c/target/$c.json" -w "test_vectors/$c/target/$c.gz" \
        --write_vk -o "test_vectors/$c/"
    timed "$c" plaindriver zk "$r" prove \
      "$PLAINDRIVER" --prover-crs ../../co-noir-common/src/crs/bn254_g1.dat \
        --verifier-crs ../../co-noir-common/src/crs/bn254_g2.dat \
        --input "test_vectors/$c/Prover.toml" --circuit "test_vectors/$c/target/$c.json" \
        --hasher poseidon2 --out-dir "test_vectors/$c" --zk
  done
  # --- MPC cells ---
  for proto in REP3 SHAMIR; do
    for r in $(seq 1 $REPS); do
      ok=1
      timed "$c" "$proto" - "$r" split \
        "$BIN" split-input --circuit "test_vectors/$c/target/$c.json" \
          --input "test_vectors/$c/Prover.toml" --protocol "$proto" \
          --out-dir "test_vectors/$c" || ok=0
      if [[ $ok -eq 1 ]]; then
        t0=$(now_ms)
        for i in 0 1 2; do
          "$BIN" generate-witness --input "test_vectors/$c/Prover.toml.$i.shared" \
            --circuit "test_vectors/$c/target/$c.json" --protocol "$proto" \
            --config "configs/party$((i + 1)).toml" \
            --out "test_vectors/$c/$c.gz.$i.shared" \
            >>"$BENCH_OUT/${c}_${proto}_wit_r${r}.log" 2>&1 &
          pids[$i]=$!
        done
        rc=0; for i in 0 1 2; do wait "${pids[$i]}" || rc=1; done
        row "$c" "$proto" - "$r" witext "$(awk "BEGIN{printf \"%.3f\", ($(now_ms)-$t0)/1000}")" "$rc"
        [[ $rc -ne 0 ]] && ok=0
      fi
      if [[ $ok -eq 1 ]]; then
        "$BIN" create-vk --circuit "test_vectors/$c/target/$c.json" \
          --crs ../../co-noir-common/src/crs/bn254_g1.dat --hasher poseidon2 \
          --vk "test_vectors/$c/cosnark_vk" >/dev/null 2>&1
        for z in nonzk zk; do
          zflag=""; vflag=""
          [[ $z == zk ]] && { zflag="--zk"; vflag="--has-zk"; }
          t0=$(now_ms)
          for i in 0 1 2; do
            out="test_vectors/$c/cosnark_proof"; pubflag="--public-input test_vectors/$c/cosnark_public_input"
            [[ $i -ne 0 ]] && { out="test_vectors/$c/cosnark_proof.$i.proof"; pubflag=""; }
            # shellcheck disable=SC2086
            "$BIN" build-and-generate-proof --witness "test_vectors/$c/$c.gz.$i.shared" \
              --circuit "test_vectors/$c/target/$c.json" \
              --crs ../../co-noir-common/src/crs/bn254_g1.dat --protocol "$proto" \
              --hasher poseidon2 --config "configs/party$((i + 1)).toml" \
              --out "$out" $pubflag $zflag --vk "test_vectors/$c/cosnark_vk" \
              >>"$BENCH_OUT/${c}_${proto}_${z}_prove_r${r}.log" 2>&1 &
            pids[$i]=$!
          done
          rc=0; for i in 0 1 2; do wait "${pids[$i]}" || rc=1; done
          row "$c" "$proto" "$z" "$r" prove "$(awk "BEGIN{printf \"%.3f\", ($(now_ms)-$t0)/1000}")" "$rc"
          timed "$c" "$proto" "$z" "$r" verify \
            "$BIN" verify --proof "test_vectors/$c/cosnark_proof" \
              --vk "test_vectors/$c/cosnark_vk" \
              --public-input "test_vectors/$c/cosnark_public_input" \
              --hasher poseidon2 --crs ../../co-noir-common/src/crs/bn254_g2.dat $vflag
        done
      else
        row "$c" "$proto" - "$r" SKIPPED 0 1
      fi
    done
  done
  # scoped cleanup between circuits (same patterns as compare*.sh)
  find "test_vectors/$c" -maxdepth 1 \( -name "*.shared" -o -name "cosnark_*" \
    -o -name "vk" -o -name "proof" -o -name "public_inputs" \) -type f -delete
done

echo "bench-0_5: done — results in $CSV"

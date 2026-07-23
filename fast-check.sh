#!/usr/bin/env bash
# fast-check.sh — tiered test runner for the co-noir ⇄ barretenberg UH sync.
#
# WHY THIS EXISTS: the full validation suite (compare_mpc.sh + `cargo test -p
# tests`) takes ~60 min. That is an ACCEPTANCE gate, not an iteration cost. For
# day-to-day edits use the cheap tiers below — the plain KAT byte-parity check
# is the tightest correctness oracle we have and runs in seconds.
#
# ⛔⛔ NEVER run the circom test binary as part of this project. Bare
#    `cargo test -p tests [--release]` pulls in `circom` (~13 min, ~755 s for a
#    single batched-witness test) which is COMPLETELY IRRELEVANT to the
#    UltraHonk/Noir work. ALWAYS scope with `--test noir`. This script only ever
#    runs the `noir` test binary. Do not add `-p tests` without `--test noir`.
#
# Usage:
#   ./fast-check.sh              # inner loop: plain poseidon KAT byte-parity (~5-10s + build)
#   ./fast-check.sh --sec        # + verifier/deserialization security regressions
#   ./fast-check.sh --mpc        # + REP3 + Shamir poseidon (co-mirror parity)
#   ./fast-check.sh --bb         # + single-circuit bb byte cross-verify (poseidon, non-ZK)
#   ./fast-check.sh --all-fast   # --sec --mpc --bb together (still no circom, no full sweep)
#   ./fast-check.sh --full       # the ~60-min acceptance gate (asks for confirmation)
#
# Flags combine, e.g. `./fast-check.sh --sec --bb`.
set -uo pipefail

# Resolve repo root (dir containing this script).
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

# THE bb oracle: source-built at the target tag. NOT ~/.bb-target/bb (rc.2, wrong).
# Source versions.env for the default rather than hardcoding it a second time here —
# this script's own copy of the path went stale across the v5.0.1 pin flip (it still
# pointed at the old ~/.bb-target-src/bb oracle after versions.env moved on) until
# this fix; see project-docs ch. 19 §4.
source "$ROOT/versions.env"
BB="${BB_TARGET:-$BARRETENBERG_BINARY_DEFAULT}"
CRS_G1="$ROOT/co-noir/co-noir-common/src/crs/bn254_g1.dat"
CRS_G2="$ROOT/co-noir/co-noir-common/src/crs/bn254_g2.dat"
# Cap MPC threads so parallel work / other agents aren't starved (see mainframe policy).
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-$(( $(nproc --all) * 8 / 30 ))}"

want_sec=0 want_mpc=0 want_bb=0 want_full=0
for a in "$@"; do
  case "$a" in
    --sec) want_sec=1 ;;
    --mpc) want_mpc=1 ;;
    --bb)  want_bb=1 ;;
    --all-fast) want_sec=1; want_mpc=1; want_bb=1 ;;
    --full) want_full=1 ;;
    *) echo "unknown flag: $a" >&2; exit 2 ;;
  esac
done

rc=0
run() { echo; echo ">>> $*"; "$@" || rc=1; }

if [[ $want_full -eq 1 ]]; then
  echo "⚠  --full runs the ~60-min acceptance gate (compare_mpc.sh + full noir suite + slow set)."
  echo "   This is for MILESTONES / end-of-phase only. It still must NOT run circom."
  read -r -p "   Proceed? [y/N] " ans
  [[ "$ans" == "y" || "$ans" == "Y" ]] || { echo "aborted."; exit 0; }
  # noir binary only — never -p tests without --test noir.
  run cargo test -p tests --release --test noir
  ( cd co-noir/co-noir/examples && TEST_SLOWER_CIRCUITS=1 BARRETENBERG_BINARY="$BB" bash compare_mpc.sh )
  echo; echo "fast-check --full done (rc=$rc)"; exit $rc
fi

# ---- Tier 1 (default): plain poseidon KAT byte-parity — the tightest oracle ----
run cargo test -p tests --release --test noir -- plain::poseidon

# ---- Tier 2 (--sec): verifier / deserialization security regressions ----
[[ $want_sec -eq 1 ]] && run cargo test -p tests --release --test noir -- security_regression

# ---- Tier 3 (--mpc): co-mirror parity (REP3 + Shamir) ----
[[ $want_mpc -eq 1 ]] && run cargo test -p tests --release --test noir -- rep3::poseidon shamir::poseidon

# ---- Tier 4 (--bb): single-circuit byte cross-verify vs the source-built oracle ----
if [[ $want_bb -eq 1 ]]; then
  if [[ ! -x "$BB" ]]; then
    echo "!! bb oracle not found/executable at $BB (set BB_TARGET) — skipping --bb" >&2
    rc=1
  else
    cargo build --release --bin plaindriver >/dev/null 2>&1 || rc=1
    TV="$ROOT/test_vectors/noir/poseidon/kat"
    OUT="$(mktemp -d)"
    echo; echo ">>> single-circuit bb cross-verify: poseidon (poseidon2, non-ZK)"
    "$ROOT/target/release/plaindriver" --prover-crs "$CRS_G1" --verifier-crs "$CRS_G2" \
      --circuit "$TV/poseidon.json" --input "$TV/poseidon.gz" --witness "$TV/poseidon.gz" \
      --hasher poseidon2 --out-dir "$OUT" >"$OUT/pd.log" 2>&1 || { echo "plaindriver FAILED (see $OUT/pd.log)"; rc=1; }
    "$BB" write_vk --scheme ultra_honk --oracle_hash poseidon2 --disable_zk -b "$TV/poseidon.json" -o "$OUT" >>"$OUT/bb.log" 2>&1
    "$BB" prove --scheme ultra_honk --oracle_hash poseidon2 --disable_zk -b "$TV/poseidon.json" -w "$TV/poseidon.gz" -k "$OUT/vk" -o "$OUT" >>"$OUT/bb.log" 2>&1
    if [[ -f "$OUT/proof" && -f "$OUT/proof_plaindriver" ]] && cmp -s "$OUT/proof" "$OUT/proof_plaindriver" && cmp -s "$OUT/vk" "$OUT/vk_plaindriver"; then
      echo "    VK + PROOF byte-identical to $BB ✓"
    else
      echo "    MISMATCH or missing artifact (see $OUT) ✗"; rc=1
    fi
    rm -rf "$OUT"
  fi
fi

echo; [[ $rc -eq 0 ]] && echo "fast-check: PASS" || echo "fast-check: FAIL (rc=$rc)"
exit $rc

#!/usr/bin/env bash
# Tiered UltraHonk validation. Flags combine:
#   default     plain Poseidon parity and fast crate-local regressions
#   --sec       verifier and deserialization regressions
#   --mpc       REP3/Shamir parity and communication regressions
#   --bb        plain arithmetic/SHA proof parity and recursive VK checks
#   --bb-mpc    MPC proofs verified by the external BB oracle, with tamper checks
#   --all-fast  --sec --mpc --bb; add --bb-mpc separately
#   --full      complete Noir suite and sharded plain/MPC comparison matrix
# BARRETENBERG_BINARY selects the oracle; BB_TARGET is a compatibility alias.
# Scope the integration tests with --test noir to avoid the unrelated Circom suite.
set -uo pipefail

# Resolve repo root (dir containing this script).
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

source "$ROOT/versions.env"
BB="${BARRETENBERG_BINARY:-${BB_TARGET:-$BARRETENBERG_BINARY_DEFAULT}}"
CRS_G1="$ROOT/co-noir/co-noir-common/src/crs/bn254_g1.dat"
CRS_G2="$ROOT/co-noir/co-noir-common/src/crs/bn254_g2.dat"
# Cap MPC threads so parallel work / other agents aren't starved (see mainframe policy).
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-$(( $(nproc --all) * 8 / 30 ))}"

want_sec=0 want_mpc=0 want_bb=0 want_bbmpc=0 want_allfast=0 want_full=0
for a in "$@"; do
  case "$a" in
    --sec) want_sec=1 ;;
    --mpc) want_mpc=1 ;;
    --bb)  want_bb=1 ;;
    --bb-mpc) want_bbmpc=1 ;;
    --all-fast) want_sec=1; want_mpc=1; want_bb=1; want_allfast=1 ;;
    --full) want_full=1 ;;
    *) echo "unknown flag: $a" >&2; exit 2 ;;
  esac
done

rc=0
run() { echo; echo ">>> $*"; "$@" || rc=1; }

if [[ $want_full -eq 1 ]]; then
  echo "⚠  --full runs the acceptance gate (full noir suite + the sharded"
  echo "   compare.sh/compare_mpc.sh matrix incl. the slow set — wall time"
  echo "   ≈ the heaviest shard, ~10-15 min on a quiet box; serial fallback:"
  echo "   run the compare scripts directly). MILESTONES / end-of-phase only."
  echo "   It still must NOT run circom."
  read -r -p "   Proceed? [y/N] " ans
  [[ "$ans" == "y" || "$ans" == "Y" ]] || { echo "aborted."; exit 0; }
  # noir binary only — never -p tests without --test noir.
  run cargo test -p tests --release --test noir
  # Disjoint circuit shards enforce full comparison-matrix coverage.
  run env BARRETENBERG_BINARY="$BB" bash scripts/acceptance-parallel.sh
  echo; echo "fast-check --full done (rc=$rc)"; exit $rc
fi

# ---- Tier 1 (default): plain poseidon KAT byte-parity — the tightest oracle ----
run cargo test -p tests --release --test noir -- plain::poseidon
# Crate-local fast unit tests (NOT reachable via `-p tests`): the batched-inversion
# serial-reference check (co-noir-common), the seedable-ZK-blinding per-site
# stream distinctness pin (co-noir-common zk_masking), and the artifact-parse
# regression (noir-types). All sub-0.1 s once built.
run cargo test -p co-noir-common --release --lib -- mpc::plain::tests zk_masking
run cargo test -p noir-types --release -- tests::parses_program_artifact

# ---- Tier 2 (--sec): verifier / deserialization security regressions ----
[[ $want_sec -eq 1 ]] && run cargo test -p tests --release --test noir -- security_regression

# ---- Tier 3 (--mpc): co-mirror parity (REP3 + Shamir) ----
# Include deterministic blinding parity and representative communication fences.
[[ $want_mpc -eq 1 ]] && run cargo test -p tests --release --test noir -- rep3::poseidon shamir::poseidon rep3::blackbox_and_prove_comms_message_fence rep3::add3u64_prove_comms_message_fence rep3::zk_blinding

# ---- Tier 4 (--bb): single-circuit byte cross-verify vs the source-built oracle ----
if [[ $want_bb -eq 1 ]]; then
  if [[ ! -x "$BB" ]]; then
    echo "!! bb oracle not found/executable at $BB (set BARRETENBERG_BINARY) — skipping --bb" >&2
    rc=1
  else
    cargo build --release --bin plaindriver >/dev/null 2>&1 || rc=1
    # Compare proof bytes for arithmetic and lookup-bearing circuits. Recursive
    # proofs use random masking, so their deterministic VKs are checked instead.
    for CV in "poseidon|$ROOT/test_vectors/noir/poseidon/kat/poseidon" \
              "bb_sha256_compression|$ROOT/test_vectors/noir/bb_sha256_compression/kat/bb_sha256_compression"; do
      NAME="${CV%%|*}"; BASE="${CV#*|}"
      OUT="$(mktemp -d)"
      echo; echo ">>> single-circuit bb cross-verify: $NAME (poseidon2, non-ZK)"
      "$ROOT/target/release/plaindriver" --prover-crs "$CRS_G1" --verifier-crs "$CRS_G2" \
        --circuit "$BASE.json" --input "$BASE.gz" --witness "$BASE.gz" \
        --hasher poseidon2 --out-dir "$OUT" >"$OUT/pd.log" 2>&1 || { echo "plaindriver FAILED (see $OUT/pd.log)"; rc=1; }
      "$BB" write_vk --scheme ultra_honk --oracle_hash poseidon2 --disable_zk -b "$BASE.json" -o "$OUT" >>"$OUT/bb.log" 2>&1
      "$BB" prove --scheme ultra_honk --oracle_hash poseidon2 --disable_zk -b "$BASE.json" -w "$BASE.gz" -k "$OUT/vk" -o "$OUT" >>"$OUT/bb.log" 2>&1
      if [[ -f "$OUT/proof" && -f "$OUT/proof_plaindriver" ]] && cmp -s "$OUT/proof" "$OUT/proof_plaindriver" && cmp -s "$OUT/vk" "$OUT/vk_plaindriver"; then
        echo "    VK + PROOF byte-identical to $BB ✓"
      else
        echo "    MISMATCH or missing artifact (see $OUT) ✗"; rc=1
      fi
      rm -rf "$OUT"
    done
    # recursion parity fence: VK byte-KATs (proof bytes prover-specific by design)
    run cargo test -p tests --release --test noir -- recursion_vk_kat recursion_zk_vk_kat
  fi
fi

# External verification checks agreement between independent implementations.
# The standing suite uses its own temporary artifacts and network mesh.
if [[ $want_bbmpc -eq 1 ]]; then
  run env BARRETENBERG_BINARY="$BB" bash "$ROOT/co-noir/co-noir/examples/bb_verify_standing.sh"
fi

if [[ $want_allfast -eq 1 && $want_bbmpc -eq 0 ]]; then
  echo
  echo "ℹ  --bb-mpc (MPC-generated proofs verified by bb) is" \
       "available but not included above -- run it separately: ./fast-check.sh --bb-mpc"
fi

echo; [[ $rc -eq 0 ]] && echo "fast-check: PASS" || echo "fast-check: FAIL (rc=$rc)"
exit $rc

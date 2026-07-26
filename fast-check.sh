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
  echo "⚠  --full runs the acceptance gate (full noir suite + the sharded"
  echo "   compare.sh/compare_mpc.sh matrix incl. the slow set — wall time"
  echo "   ≈ the heaviest shard, ~10-15 min on a quiet box; serial fallback:"
  echo "   run the compare scripts directly). MILESTONES / end-of-phase only."
  echo "   It still must NOT run circom."
  read -r -p "   Proceed? [y/N] " ans
  [[ "$ans" == "y" || "$ans" == "Y" ]] || { echo "aborted."; exit 0; }
  # noir binary only — never -p tests without --test noir.
  run cargo test -p tests --release --test noir
  # Sharded parallel sweep (ch. 15 §4.9a): covers compare.sh AND
  # compare_mpc.sh over the full circuit matrix with a hard coverage
  # assertion — strictly more than the old serial compare_mpc-only step.
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
# rep3::poseidon also picks up the T2/T2-lite comms-fence tests (fence test
# names are prefixed with their circuit, e.g.
# poseidon_prove_comms_message_fence_poseidon2sponge / *_zk_poseidon2sponge)
# for free. The two extra filters below add the newer per-circuit comms
# fences on different (non-poseidon) small circuits -- targeted to just the
# fence tests, not the whole blackbox_and/add3u64 suites, to keep this tier's
# added wall time near-zero (ch. 24 §5 T2-proper).
# rep3::zk_blinding is the seedable-ZK-blinding byte-parity fence (plaindriver
# vs all 3 REP3 parties, ZK mode, injected deterministic masking; ~1.2 s).
[[ $want_mpc -eq 1 ]] && run cargo test -p tests --release --test noir -- rep3::poseidon shamir::poseidon rep3::blackbox_and_prove_comms_message_fence rep3::add3u64_prove_comms_message_fence rep3::zk_blinding

# ---- Tier 4 (--bb): single-circuit byte cross-verify vs the source-built oracle ----
if [[ $want_bb -eq 1 ]]; then
  if [[ ! -x "$BB" ]]; then
    echo "!! bb oracle not found/executable at $BB (set BB_TARGET) — skipping --bb" >&2
    rc=1
  else
    cargo build --release --bin plaindriver >/dev/null 2>&1 || rc=1
    # poseidon = pure arithmetic; bb_sha256_compression = lookup tables + sha
    # gadget (Mike 2026-07-25: byte cross-verify must cover a lookup-bearing
    # circuit, not just poseidon). Recursion proof BYTES are legitimately
    # prover-specific (random masking offset generator, PLAN item 2.9) — its
    # parity fence is the always-on recursion{,_zk}_vk_kat VK-byte tests run
    # in the tier below, not a proof cmp here.
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

echo; [[ $rc -eq 0 ]] && echo "fast-check: PASS" || echo "fast-check: FAIL (rc=$rc)"
exit $rc

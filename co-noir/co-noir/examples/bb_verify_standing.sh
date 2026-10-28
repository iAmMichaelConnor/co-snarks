#!/usr/bin/env bash
# Verify co-noir MPC proofs with the independent BB oracle.
# Default: REP3 Poseidon, ZK/non-ZK, co-noir/BB keys, and proof/public-input
# tamper rejection by both verifiers. --full adds public recursion and SHAMIR.
# Recursive proof bytes can differ due to masking; acceptance by the external
# verifier checks protocol agreement without requiring identical proof bytes.
#
# Runs in a private temporary directory with a separate mesh (ports 12000-12002).
# Overrides: BARRETENBERG_BINARY, CONFIG_DIR, RAYON_NUM_THREADS, KEEP_WORKDIR=1.
set -uo pipefail  # no -e: we accumulate pass/fail across many checks

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Version pins + default bb oracle path live in versions.env (single source
# of truth; never hardcode the oracle path here).
source "$REPO_ROOT/versions.env"
BB="${BARRETENBERG_BINARY:-$BARRETENBERG_BINARY_DEFAULT}"

CO="$REPO_ROOT/target/release/co-noir"
CRS_G1="$REPO_ROOT/co-noir/co-noir-common/src/crs/bn254_g1.dat"
CRS_G2="$REPO_ROOT/co-noir/co-noir-common/src/crs/bn254_g2.dat"
TEST_VECTORS_DIR="$SCRIPT_DIR/test_vectors"
DATA_DIR="$SCRIPT_DIR/data"

# Same 80%-of-cores-over-3-parties budget as compare_mpc.sh / fast-check.sh
# (shared-mainframe policy: leave ~20% of host cores free).
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-$(( $(nproc --all) * 8 / 30 ))}"

want_full=0
for a in "$@"; do
  case "$a" in
    --full) want_full=1 ;;
    *) echo "bb_verify_standing.sh: unknown flag: $a" >&2; exit 2 ;;
  esac
done

if [[ ! -x "$BB" ]]; then
  echo "!! bb oracle not found/executable at $BB (set BARRETENBERG_BINARY) -- aborting" >&2
  exit 2
fi

t_start=$(date +%s)

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/bb-verify-standing.XXXXXX")"
LOGDIR="$WORKDIR/logs"
mkdir -p "$LOGDIR" "$WORKDIR/circuits"

rc=0
pass_n=0
fail_n=0

cleanup() {
  if [[ -n "${KEEP_WORKDIR:-}" || $rc -ne 0 ]]; then
    echo "bb_verify_standing: workdir kept for inspection: $WORKDIR"
  else
    rm -rf "$WORKDIR"
  fi
}
trap cleanup EXIT

echo "bb_verify_standing: tier=$([[ $want_full -eq 1 ]] && echo FULL || echo FAST) bb=$BB workdir=$WORKDIR"
echo "bb_verify_standing: RAYON_NUM_THREADS=$RAYON_NUM_THREADS"

# ---------------------------------------------------------------------
# Private 3-party mesh config: ports 12000-12002, absolute TLS key/cert
# paths (so this is independent of CWD -- unlike examples/configs/*.toml,
# whose "data/keyN.der" is read relative to the *process* CWD, not the
# config file's location).
# ---------------------------------------------------------------------
CONFIG_DIR="${CONFIG_DIR:-$WORKDIR/configs}"
if [[ ! -d "$CONFIG_DIR" ]]; then
  mkdir -p "$CONFIG_DIR"
  for i in 0 1 2; do
    party=$((i + 1))
    port=$((12000 + i))
    cat >"$CONFIG_DIR/party$party.toml" <<EOF
[network]
my_id = $i
bind_addr = "0.0.0.0:$port"
max_frame_length = 469_762_056

[[network.parties]]
id = 0
dns_name = "127.0.0.1:12000"

[[network.parties]]
id = 1
dns_name = "127.0.0.1:12001"

[[network.parties]]
id = 2
dns_name = "127.0.0.1:12002"

[network.tls]
key = "$DATA_DIR/key$i.der"
certs = ["$DATA_DIR/cert0.der", "$DATA_DIR/cert1.der", "$DATA_DIR/cert2.der"]
EOF
  done
fi

# ---------------------------------------------------------------------
# Reporting helpers -- every check prints exactly one PASS/FAIL line.
# ---------------------------------------------------------------------
report() { # report <label> <status: 0 = ok>
  local label=$1 status=$2
  if [[ $status -eq 0 ]]; then
    echo "[PASS] $label"
    pass_n=$((pass_n + 1))
  else
    echo "[FAIL] $label"
    fail_n=$((fail_n + 1))
    rc=1
  fi
}

# run_step <label> <logfile> <cmd...> — PASS iff cmd exits 0.
run_step() {
  local label=$1 logf=$2
  shift 2
  "$@" >"$logf" 2>&1
  local st=$?
  report "$label" "$st"
  [[ $st -ne 0 ]] && echo "    (see $logf)"
  return $st
}

# run_step_expect_reject <label> <logfile> <cmd...> — PASS iff cmd exits
# NONZERO (used for negative/tamper checks: rejection is success).
run_step_expect_reject() {
  local label=$1 logf=$2
  shift 2
  "$@" >"$logf" 2>&1
  local st=$?
  if [[ $st -ne 0 ]]; then
    report "$label" 0
  else
    report "$label" 1
    echo "    (cmd unexpectedly SUCCEEDED -- see $logf)"
  fi
}

# require_artifact <path> <label> — a guard for negative/tamper checks
# specifically: run_step_expect_reject treats ANY nonzero exit as a PASS,
# so if its prerequisite artifact is missing (an earlier positive step
# failed), the verifier command fails for the WRONG reason ("no such
# file") and would be misreported as a correct rejection -- a false
# positive that would hide the real (upstream) failure. Found the hard
# way (2026-07-27): a REP3 build-and-generate-proof failure on the
# `recursion` circuit left no cosnark_proof to tamper with, and the
# unguarded tamper block below it silently printed [PASS] for both
# "REJECTS byte-flipped proof" checks. Call this before any tamper setup;
# on failure it reports one clear [FAIL] and the caller should skip the
# dependent checks (print [SKIP], do not attempt them).
require_artifact() {
  local path=$1 label=$2
  if [[ ! -s "$path" ]]; then
    report "$label" 1
    echo "    (prerequisite artifact missing or empty: $path -- an earlier step must have failed)"
    return 1
  fi
  return 0
}

# run3party <label> <logprefix> <arrayname0> <arrayname1> <arrayname2>
# Launches the three parties' commands in parallel, waits on each PID
# individually (not `wait $(jobs -p)` -- that pattern silently drops
# failures from backgrounded `cmd || flag=1` compounds, since the `|| ...`
# runs inside the backgrounded subshell and never reaches the caller's
# variable) and aggregates a single PASS/FAIL line for the stage.
run3party() {
  local label=$1 logprefix=$2
  local -n _p0=$3
  local -n _p1=$4
  local -n _p2=$5
  local pids=() fail=0 pid
  "${_p0[@]}" >"$LOGDIR/${logprefix}_party0.log" 2>&1 & pids+=($!)
  "${_p1[@]}" >"$LOGDIR/${logprefix}_party1.log" 2>&1 & pids+=($!)
  "${_p2[@]}" >"$LOGDIR/${logprefix}_party2.log" 2>&1 & pids+=($!)
  for pid in "${pids[@]}"; do
    wait "$pid" || fail=1
  done
  report "$label" "$fail"
  [[ $fail -ne 0 ]] && echo "    (see $LOGDIR/${logprefix}_party{0,1,2}.log)"
  return $fail
}

# Tamper helpers. Both flip a byte with XOR 0xFF, which is guaranteed to
# change the byte (x^0xFF == x has no solution) so the tamper always takes
# effect, never a no-op.
#
# flip_word_low_byte: flips the LAST (least-significant, big-endian) byte
# of the 32-byte field element straddling the file's midpoint. Low-order
# bytes can never push a field element >= the BN254 modulus, so this is
# guaranteed to exercise a genuine cryptographic/relation-check rejection
# rather than a cheaper "non-canonical field element" decode-level bail
# (confirmed empirically: flipping a HIGH-order byte instead produced
# "Non-canonical proof element: value >= field modulus" from bb -- a real
# rejection either way, but a less interesting one to pin as the standing
# negative check).
flip_word_low_byte() {
  python3 - "$1" <<'PY'
import sys
path = sys.argv[1]
with open(path, "r+b") as f:
    f.seek(0, 2)
    size = f.tell()
    word = (size // 2) // 32
    off = word * 32 + 31
    f.seek(off)
    b = f.read(1)
    f.seek(off)
    f.write(bytes([b[0] ^ 0xFF]))
PY
}

# flip_last_byte: flips the last byte of the file (the low-order byte of
# the last public input word for a public_inputs file).
flip_last_byte() {
  python3 - "$1" <<'PY'
import sys
path = sys.argv[1]
with open(path, "r+b") as f:
    f.seek(0, 2)
    size = f.tell()
    off = size - 1
    f.seek(off)
    b = f.read(1)
    f.seek(off)
    f.write(bytes([b[0] ^ 0xFF]))
PY
}

# copy_circuit <name> -- private copy under $WORKDIR/circuits/<name>;
# examples/test_vectors/<name>/ is only ever read, never written.
copy_circuit() {
  local name=$1
  rm -rf "$WORKDIR/circuits/$name"
  cp -r "$TEST_VECTORS_DIR/$name" "$WORKDIR/circuits/$name"
}

# ---------------------------------------------------------------------
# Build co-noir once. Run from $REPO_ROOT specifically: rustup resolves
# rust-toolchain.toml from the process CWD, not from --manifest-path, so
# building from an arbitrary CWD can silently pick up the wrong toolchain
# (observed: "requires rustc 1.90" errors when built from /tmp). May block
# on the target/ lock if another agent is building concurrently -- that's
# expected on this shared box; wait, don't kill.
# ---------------------------------------------------------------------
(cd "$REPO_ROOT" && cargo build --release --bin co-noir --bin plaindriver) >"$LOGDIR/build_co-noir.log" 2>&1
st=$?
report "cargo build --release --bin co-noir" "$st"
if [[ $st -ne 0 ]]; then
  echo "    (see $LOGDIR/build_co-noir.log)"
  echo "bb_verify_standing: ABORT (co-noir failed to build)"
  echo; echo "bb_verify_standing: FAIL ($pass_n passed, $fail_n failed, rc=1)"
  exit 1
fi

# =======================================================================
# FAST tier: poseidon, REP3, non-ZK + ZK.
# =======================================================================
CIRC="$WORKDIR/circuits/poseidon"
copy_circuit poseidon

(cd "$CIRC" && nargo execute) >"$LOGDIR/nargo_poseidon.log" 2>&1
report "nargo execute (poseidon)" $?

run_step "split-input REP3 (poseidon)" "$LOGDIR/split_input_poseidon.log" \
  "$CO" split-input --circuit "$CIRC/target/poseidon.json" --input "$CIRC/Prover.toml" \
    --protocol REP3 --out-dir "$CIRC"

GENWIT0=("$CO" generate-witness --input "$CIRC/Prover.toml.0.shared" --circuit "$CIRC/target/poseidon.json" --protocol REP3 --config "$CONFIG_DIR/party1.toml" --out "$CIRC/poseidon.gz.0.shared")
GENWIT1=("$CO" generate-witness --input "$CIRC/Prover.toml.1.shared" --circuit "$CIRC/target/poseidon.json" --protocol REP3 --config "$CONFIG_DIR/party2.toml" --out "$CIRC/poseidon.gz.1.shared")
GENWIT2=("$CO" generate-witness --input "$CIRC/Prover.toml.2.shared" --circuit "$CIRC/target/poseidon.json" --protocol REP3 --config "$CONFIG_DIR/party3.toml" --out "$CIRC/poseidon.gz.2.shared")
run3party "generate-witness REP3 x3 (poseidon)" "genwit_poseidon" GENWIT0 GENWIT1 GENWIT2

run_step "co-noir create-vk poseidon2 (poseidon)" "$LOGDIR/create_vk_poseidon.log" \
  "$CO" create-vk --circuit "$CIRC/target/poseidon.json" --crs "$CRS_G1" --hasher poseidon2 --vk "$CIRC/cosnark_vk"

mkdir -p "$CIRC/bb_vk_nonzk" "$CIRC/bb_vk_zk"
run_step "bb write_vk non-ZK (poseidon)" "$LOGDIR/bb_write_vk_nonzk_poseidon.log" \
  "$BB" write_vk --scheme ultra_honk --oracle_hash poseidon2 --disable_zk -b "$CIRC/target/poseidon.json" -o "$CIRC/bb_vk_nonzk/"
run_step "bb write_vk ZK (poseidon)" "$LOGDIR/bb_write_vk_zk_poseidon.log" \
  "$BB" write_vk --scheme ultra_honk --oracle_hash poseidon2 -b "$CIRC/target/poseidon.json" -o "$CIRC/bb_vk_zk/"

PROVE_NONZK0=("$CO" build-and-generate-proof --witness "$CIRC/poseidon.gz.0.shared" --circuit "$CIRC/target/poseidon.json" --crs "$CRS_G1" --protocol REP3 --hasher poseidon2 --config "$CONFIG_DIR/party1.toml" --out "$CIRC/cosnark_proof" --public-input "$CIRC/cosnark_public_input" --vk "$CIRC/cosnark_vk")
PROVE_NONZK1=("$CO" build-and-generate-proof --witness "$CIRC/poseidon.gz.1.shared" --circuit "$CIRC/target/poseidon.json" --crs "$CRS_G1" --protocol REP3 --hasher poseidon2 --config "$CONFIG_DIR/party2.toml" --vk "$CIRC/cosnark_vk")
PROVE_NONZK2=("$CO" build-and-generate-proof --witness "$CIRC/poseidon.gz.2.shared" --circuit "$CIRC/target/poseidon.json" --crs "$CRS_G1" --protocol REP3 --hasher poseidon2 --config "$CONFIG_DIR/party3.toml" --vk "$CIRC/cosnark_vk")
run3party "build-and-generate-proof REP3 non-ZK (poseidon)" "prove_nonzk_poseidon" PROVE_NONZK0 PROVE_NONZK1 PROVE_NONZK2

PROVE_ZK0=("$CO" build-and-generate-proof --witness "$CIRC/poseidon.gz.0.shared" --circuit "$CIRC/target/poseidon.json" --crs "$CRS_G1" --protocol REP3 --hasher poseidon2 --config "$CONFIG_DIR/party1.toml" --out "$CIRC/cosnark_proof_zk" --public-input "$CIRC/cosnark_public_input_zk" --vk "$CIRC/cosnark_vk" --zk)
PROVE_ZK1=("$CO" build-and-generate-proof --witness "$CIRC/poseidon.gz.1.shared" --circuit "$CIRC/target/poseidon.json" --crs "$CRS_G1" --protocol REP3 --hasher poseidon2 --config "$CONFIG_DIR/party2.toml" --vk "$CIRC/cosnark_vk" --zk)
PROVE_ZK2=("$CO" build-and-generate-proof --witness "$CIRC/poseidon.gz.2.shared" --circuit "$CIRC/target/poseidon.json" --crs "$CRS_G1" --protocol REP3 --hasher poseidon2 --config "$CONFIG_DIR/party3.toml" --vk "$CIRC/cosnark_vk" --zk)
run3party "build-and-generate-proof REP3 ZK (poseidon)" "prove_zk_poseidon" PROVE_ZK0 PROVE_ZK1 PROVE_ZK2

# ---- positive: bb must verify our MPC-generated proof, with EITHER VK ----
run_step "bb verify: poseidon non-ZK proof + our VK" "$LOGDIR/bbverify_nonzk_ourvk.log" \
  "$BB" verify --scheme ultra_honk --oracle_hash poseidon2 --disable_zk -p "$CIRC/cosnark_proof" -i "$CIRC/cosnark_public_input" -k "$CIRC/cosnark_vk"
run_step "bb verify: poseidon non-ZK proof + bb-written VK" "$LOGDIR/bbverify_nonzk_bbvk.log" \
  "$BB" verify --scheme ultra_honk --oracle_hash poseidon2 --disable_zk -p "$CIRC/cosnark_proof" -i "$CIRC/cosnark_public_input" -k "$CIRC/bb_vk_nonzk/vk"
run_step "bb verify: poseidon ZK proof + our VK" "$LOGDIR/bbverify_zk_ourvk.log" \
  "$BB" verify --scheme ultra_honk --oracle_hash poseidon2 -p "$CIRC/cosnark_proof_zk" -i "$CIRC/cosnark_public_input_zk" -k "$CIRC/cosnark_vk"
run_step "bb verify: poseidon ZK proof + bb-written VK" "$LOGDIR/bbverify_zk_bbvk.log" \
  "$BB" verify --scheme ultra_honk --oracle_hash poseidon2 -p "$CIRC/cosnark_proof_zk" -i "$CIRC/cosnark_public_input_zk" -k "$CIRC/bb_vk_zk/vk"

# ---- positive sanity: co-noir's own verifier agrees (cheap; establishes
# the baseline the negative checks below are contrasted against) ----
run_step "co-noir verify: poseidon non-ZK proof (sanity)" "$LOGDIR/coverify_nonzk.log" \
  "$CO" verify --proof "$CIRC/cosnark_proof" --public-input "$CIRC/cosnark_public_input" --vk "$CIRC/cosnark_vk" --hasher poseidon2 --crs "$CRS_G2"
run_step "co-noir verify: poseidon ZK proof (sanity)" "$LOGDIR/coverify_zk.log" \
  "$CO" verify --proof "$CIRC/cosnark_proof_zk" --public-input "$CIRC/cosnark_public_input_zk" --vk "$CIRC/cosnark_vk" --hasher poseidon2 --crs "$CRS_G2" --has-zk

# ---- negative: tamper the non-ZK proof / public input; both bb and
# co-noir MUST reject. (Note: tampered-file basenames deliberately carry
# NO dot-extension -- co-noir verify's JSON-vs-binary format sniffing keys
# off Path::extension(), so e.g. "foo.tampered" is misread as a foreign
# "tampered" format and bails with an unrelated "mixed formats" error
# instead of exercising the real verifier. Found and fixed during harness
# development -- see REPORT.md.) ----
if require_artifact "$CIRC/cosnark_proof" "tamper setup (poseidon): cosnark_proof missing" \
   && require_artifact "$CIRC/cosnark_public_input" "tamper setup (poseidon): cosnark_public_input missing"; then
  cp "$CIRC/cosnark_proof" "$CIRC/cosnark_proof_tampered"
  flip_word_low_byte "$CIRC/cosnark_proof_tampered"
  cp "$CIRC/cosnark_public_input" "$CIRC/cosnark_public_input_tampered"
  flip_last_byte "$CIRC/cosnark_public_input_tampered"

  run_step_expect_reject "bb verify REJECTS byte-flipped proof (poseidon non-ZK)" "$LOGDIR/bbverify_reject_proof.log" \
    "$BB" verify --scheme ultra_honk --oracle_hash poseidon2 --disable_zk -p "$CIRC/cosnark_proof_tampered" -i "$CIRC/cosnark_public_input" -k "$CIRC/cosnark_vk"
  run_step_expect_reject "bb verify REJECTS tampered public input (poseidon non-ZK)" "$LOGDIR/bbverify_reject_pi.log" \
    "$BB" verify --scheme ultra_honk --oracle_hash poseidon2 --disable_zk -p "$CIRC/cosnark_proof" -i "$CIRC/cosnark_public_input_tampered" -k "$CIRC/cosnark_vk"
  run_step_expect_reject "co-noir verify REJECTS byte-flipped proof (poseidon non-ZK)" "$LOGDIR/coverify_reject_proof.log" \
    "$CO" verify --proof "$CIRC/cosnark_proof_tampered" --public-input "$CIRC/cosnark_public_input" --vk "$CIRC/cosnark_vk" --hasher poseidon2 --crs "$CRS_G2"
  run_step_expect_reject "co-noir verify REJECTS tampered public input (poseidon non-ZK)" "$LOGDIR/coverify_reject_pi.log" \
    "$CO" verify --proof "$CIRC/cosnark_proof" --public-input "$CIRC/cosnark_public_input_tampered" --vk "$CIRC/cosnark_vk" --hasher poseidon2 --crs "$CRS_G2"
else
  echo "[SKIP] poseidon tamper checks (bb+co-noir REJECTS byte-flipped-proof/tampered-public-input) -- prerequisite missing"
fi

# =======================================================================
# FULL tier additions: recursion, recursion_zk, Shamir poseidon.
# =======================================================================
if [[ $want_full -eq 1 ]]; then
  # ---- Native recursion and REP3 recursion_zk, both with non-ZK outer proofs.
  # Exercise native proving and the explicit disclosure profile here. Dedicated
  # private-recursion tests cover both inner flavors with all inner inputs shared.
  # Their Prover.toml already bakes in a fixed inner HONK proof/vk/vk_hash
  # (std::verify_proof_with_type) -- no separate inner-proving step needed.
  # Random masking makes proof bytes prover-specific even for non-ZK outer
  # proofs. Check acceptance with the independent verifier.
  for rname in recursion recursion_zk; do
    RCIRC="$WORKDIR/circuits/$rname"
    copy_circuit "$rname"

    (cd "$RCIRC" && nargo execute) >"$LOGDIR/nargo_$rname.log" 2>&1
    report "nargo execute ($rname)" $?

    if [[ "$rname" == recursion ]]; then
      # The recursive plain driver needs a larger stack than the shell default.
      (
        ulimit -s unlimited
        "$REPO_ROOT/target/release/plaindriver" --prover-crs "$CRS_G1" --verifier-crs "$CRS_G2" \
          --input "$RCIRC/Prover.toml" --circuit "$RCIRC/target/$rname.json" \
          --hasher poseidon2 --reveal-recursion-inputs --out-dir "$RCIRC"
      ) >"$LOGDIR/prove_$rname.log" 2>&1
      report "plain-driver recursive proof ($rname)" $?
      for pair in "proof_plaindriver cosnark_proof" "public_inputs_plaindriver cosnark_public_input" "vk_plaindriver cosnark_vk"; do
        read -r source destination <<<"$pair"
        if require_artifact "$RCIRC/$source" "$rname generated $source"; then
          cp "$RCIRC/$source" "$RCIRC/$destination"
        fi
      done
    else
      run_step "split-input REP3 ($rname)" "$LOGDIR/split_input_$rname.log" \
        "$CO" split-input --circuit "$RCIRC/target/$rname.json" --input "$RCIRC/Prover.toml" \
          --protocol REP3 --out-dir "$RCIRC"

      RGW0=("$CO" generate-witness --input "$RCIRC/Prover.toml.0.shared" --circuit "$RCIRC/target/$rname.json" --protocol REP3 --config "$CONFIG_DIR/party1.toml" --out "$RCIRC/$rname.gz.0.shared")
      RGW1=("$CO" generate-witness --input "$RCIRC/Prover.toml.1.shared" --circuit "$RCIRC/target/$rname.json" --protocol REP3 --config "$CONFIG_DIR/party2.toml" --out "$RCIRC/$rname.gz.1.shared")
      RGW2=("$CO" generate-witness --input "$RCIRC/Prover.toml.2.shared" --circuit "$RCIRC/target/$rname.json" --protocol REP3 --config "$CONFIG_DIR/party3.toml" --out "$RCIRC/$rname.gz.2.shared")
      run3party "generate-witness REP3 x3 ($rname)" "genwit_$rname" RGW0 RGW1 RGW2

      run_step "co-noir create-vk poseidon2 ($rname)" "$LOGDIR/create_vk_$rname.log" \
        "$CO" create-vk --circuit "$RCIRC/target/$rname.json" --crs "$CRS_G1" --hasher poseidon2 --reveal-recursion-inputs --vk "$RCIRC/cosnark_vk"

      RP0=("$CO" build-and-generate-proof --witness "$RCIRC/$rname.gz.0.shared" --circuit "$RCIRC/target/$rname.json" --crs "$CRS_G1" --protocol REP3 --hasher poseidon2 --config "$CONFIG_DIR/party1.toml" --out "$RCIRC/cosnark_proof" --public-input "$RCIRC/cosnark_public_input" --vk "$RCIRC/cosnark_vk")
      RP1=("$CO" build-and-generate-proof --witness "$RCIRC/$rname.gz.1.shared" --circuit "$RCIRC/target/$rname.json" --crs "$CRS_G1" --protocol REP3 --hasher poseidon2 --config "$CONFIG_DIR/party2.toml" --vk "$RCIRC/cosnark_vk")
      RP2=("$CO" build-and-generate-proof --witness "$RCIRC/$rname.gz.2.shared" --circuit "$RCIRC/target/$rname.json" --crs "$CRS_G1" --protocol REP3 --hasher poseidon2 --config "$CONFIG_DIR/party3.toml" --vk "$RCIRC/cosnark_vk")

      # This fixture intentionally reveals the inner proof, public inputs, VK,
      # key hash and predicate to the three provers. Unrelated witness values
      # remain shared; the outer proof's ZK mode does not provide this consent.
      RP0+=(--reveal-recursion-inputs)
      RP1+=(--reveal-recursion-inputs)
      RP2+=(--reveal-recursion-inputs)
      run3party "build-and-generate-proof REP3 non-ZK ($rname)" "prove_$rname" RP0 RP1 RP2
    fi

    run_step "bb verify: $rname non-ZK proof + our VK" "$LOGDIR/bbverify_$rname.log" \
      "$BB" verify --scheme ultra_honk --oracle_hash poseidon2 --disable_zk -p "$RCIRC/cosnark_proof" -i "$RCIRC/cosnark_public_input" -k "$RCIRC/cosnark_vk"

    if require_artifact "$RCIRC/cosnark_proof" "tamper setup ($rname): cosnark_proof missing"; then
      cp "$RCIRC/cosnark_proof" "$RCIRC/cosnark_proof_tampered"
      flip_word_low_byte "$RCIRC/cosnark_proof_tampered"
      run_step_expect_reject "bb verify REJECTS byte-flipped proof ($rname)" "$LOGDIR/bbverify_reject_$rname.log" \
        "$BB" verify --scheme ultra_honk --oracle_hash poseidon2 --disable_zk -p "$RCIRC/cosnark_proof_tampered" -i "$RCIRC/cosnark_public_input" -k "$RCIRC/cosnark_vk"
      run_step_expect_reject "co-noir verify REJECTS byte-flipped proof ($rname)" "$LOGDIR/coverify_reject_$rname.log" \
        "$CO" verify --proof "$RCIRC/cosnark_proof_tampered" --public-input "$RCIRC/cosnark_public_input" --vk "$RCIRC/cosnark_vk" --hasher poseidon2 --crs "$CRS_G2"
    else
      echo "[SKIP] $rname tamper checks (bb+co-noir REJECTS byte-flipped proof) -- prerequisite missing"
    fi
  done

  # ---- Shamir: REP3-split then translate-witness (SHAMIR is not a
  # split-input target protocol -- see examples/run_full_poseidon_with_
  # shamir.sh), reusing the poseidon REP3 witness shares + cosnark_vk
  # already produced by the FAST section above. ----
  SGW0=("$CO" translate-witness --witness "$CIRC/poseidon.gz.0.shared" --src-protocol REP3 --target-protocol SHAMIR --config "$CONFIG_DIR/party1.toml" --out "$CIRC/shamir_poseidon.gz.0.shared")
  SGW1=("$CO" translate-witness --witness "$CIRC/poseidon.gz.1.shared" --src-protocol REP3 --target-protocol SHAMIR --config "$CONFIG_DIR/party2.toml" --out "$CIRC/shamir_poseidon.gz.1.shared")
  SGW2=("$CO" translate-witness --witness "$CIRC/poseidon.gz.2.shared" --src-protocol REP3 --target-protocol SHAMIR --config "$CONFIG_DIR/party3.toml" --out "$CIRC/shamir_poseidon.gz.2.shared")
  run3party "translate-witness REP3->SHAMIR x3 (poseidon)" "translate_poseidon" SGW0 SGW1 SGW2

  SP0=("$CO" build-and-generate-proof --witness "$CIRC/shamir_poseidon.gz.0.shared" --circuit "$CIRC/target/poseidon.json" --crs "$CRS_G1" --protocol SHAMIR --hasher poseidon2 --config "$CONFIG_DIR/party1.toml" --out "$CIRC/shamir_cosnark_proof" --public-input "$CIRC/shamir_cosnark_public_input" --vk "$CIRC/cosnark_vk")
  SP1=("$CO" build-and-generate-proof --witness "$CIRC/shamir_poseidon.gz.1.shared" --circuit "$CIRC/target/poseidon.json" --crs "$CRS_G1" --protocol SHAMIR --hasher poseidon2 --config "$CONFIG_DIR/party2.toml" --vk "$CIRC/cosnark_vk")
  SP2=("$CO" build-and-generate-proof --witness "$CIRC/shamir_poseidon.gz.2.shared" --circuit "$CIRC/target/poseidon.json" --crs "$CRS_G1" --protocol SHAMIR --hasher poseidon2 --config "$CONFIG_DIR/party3.toml" --vk "$CIRC/cosnark_vk")
  run3party "build-and-generate-proof SHAMIR non-ZK (poseidon)" "prove_shamir_poseidon" SP0 SP1 SP2

  run_step "bb verify: Shamir poseidon proof + our VK" "$LOGDIR/bbverify_shamir.log" \
    "$BB" verify --scheme ultra_honk --oracle_hash poseidon2 --disable_zk -p "$CIRC/shamir_cosnark_proof" -i "$CIRC/shamir_cosnark_public_input" -k "$CIRC/cosnark_vk"
fi

t_end=$(date +%s)
echo
echo "bb_verify_standing: $pass_n passed, $fail_n failed, elapsed $((t_end - t_start))s"
if [[ $rc -eq 0 ]]; then
  echo "bb_verify_standing: PASS"
else
  echo "bb_verify_standing: FAIL (rc=$rc)"
fi
exit $rc

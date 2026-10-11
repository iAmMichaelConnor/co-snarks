export CARGO_TERM_QUIET=true
set -uo pipefail  # no -e: the loop deliberately accumulates per-case failures in exit_code

# Version pins + default oracle live in versions.env at the repo root
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/versions.env"
BARRETENBERG_BINARY=${BARRETENBERG_BINARY:-$BARRETENBERG_BINARY_DEFAULT}  ## env-overridable

PLAINDRIVER="../../../target/release/plaindriver"
exit_code=0
case_failed=0
failed_tests=()

REMOVE_OUTPUT=1
PIPE=""
if [[ $REMOVE_OUTPUT -eq 1 ]];
then
    PIPE=" > /dev/null 2>&1"
fi

# build the plaindriver binary
cargo build --release --bin plaindriver

## install noirup: curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
r=$(bash -c "nargo --version")
if  [[ $r != "nargo version = $NARGO_VERSION"* ]];
then
    echo "nargo version mismatch (got: '$r', expected: 'nargo version = $NARGO_VERSION...')." >&2
    exit 1
fi

## use one of these two methods
## install bbup: curl -L bbup.dev | bash
# bash -c "bbup -nv 0.${NARGO_VERSION}.0"
# If bb is causing problems, run this:
# curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/next/barretenberg/bbup/install | bash
# bbup
r=$(bash -c "$BARRETENBERG_BINARY --version 2> /dev/null")
if  [[ $r != "$BARRETENBERG_VERSION" ]];
then
    echo "WARNING: bb version mismatch (got: '$r', expected: '$BARRETENBERG_VERSION'). Not auto-installing; continuing anyway (source-built bb may report a placeholder version)."
fi

echo "Using nargo version $NARGO_VERSION"
echo "Using bb version $BARRETENBERG_VERSION"
echo ""

test_cases=("add3u64" "mul3u64" "assert" "get_bytes" "if_then" "negative" "poseidon_assert" "quantized" "add3" "add3_assert" "poseidon" "poseidon_input2" "approx_sigmoid" "addition_multiplication" "unconstrained_fn" "unconstrained_fn_field" "blackbox_not" "blackbox_and" "blackbox_xor" "ram" "rom_shared" "poseidon2" "blackbox_poseidon2" "assert_max_bit_size" "pedersen_hash" "pedersen_commitment" "bb_sha256_compression" "blake2s" "blake3" "embedded_curve_add" "aes128" "recursion" "recursion_zk")


run_proof_verification() {
  local name=$1
  local algorithm=$2

  if [[ "$algorithm" == "poseidon" ]]; then
    prove_command="prove --scheme ultra_honk --oracle_hash poseidon2 --disable_zk"
    write_command="write_vk --scheme ultra_honk --oracle_hash poseidon2 --disable_zk"
    verify_command="verify --scheme ultra_honk --oracle_hash poseidon2 --disable_zk"
  elif [[ "$algorithm" == "keccak" ]]; then
    prove_command="prove --scheme ultra_honk --oracle_hash keccak --disable_zk"
    write_command="write_vk --scheme ultra_honk --oracle_hash keccak --disable_zk"
    verify_command="verify --scheme ultra_honk --oracle_hash keccak --disable_zk"
  elif [[ "$algorithm" == "poseidon_zk" ]]; then
    prove_command="prove --scheme ultra_honk --oracle_hash poseidon2"
    write_command="write_vk --scheme ultra_honk --oracle_hash poseidon2"
    verify_command="verify --scheme ultra_honk --oracle_hash poseidon2"
  else
    prove_command="prove --scheme ultra_honk --oracle_hash keccak"
    write_command="write_vk --scheme ultra_honk --oracle_hash keccak"
    verify_command="verify --scheme ultra_honk --oracle_hash keccak"
  fi

  echo "comparing" $name "with bb and $algorithm transcript"

  # Remove any stale oracle artifacts so a silently-failing bb invocation cannot
  # produce a comparison against a previous run's output.
  rm -f test_vectors/${name}/vk test_vectors/${name}/proof test_vectors/${name}/public_inputs

  bash -c "$BARRETENBERG_BINARY $write_command -b test_vectors/${name}/target/${name}.json -o test_vectors/${name}/ $PIPE"
  if [[ $? -ne 0 || ! -s test_vectors/${name}/vk ]]; then
    exit_code=1
    echo "::error::$name bb write_vk failed or produced no vk (with: $algorithm)"
    return $exit_code
  fi

  bash -c "$BARRETENBERG_BINARY $prove_command -b test_vectors/${name}/target/${name}.json -w test_vectors/${name}/target/${name}.gz -k test_vectors/${name}/vk -o test_vectors/${name}/ $PIPE"
  if [[ $? -ne 0 || ! -s test_vectors/${name}/proof || ! -f test_vectors/${name}/public_inputs ]]; then
    exit_code=1
    echo "::error::$name bb prove failed or produced no proof/public_inputs (with: $algorithm)"
    return $exit_code
  fi


  # VK bytes must match for EVERY circuit, recursion included: the VK pins the full gate
  # layout, and (unlike recursion proof bytes, which are prover-specific) it is deterministic.
  # This diff is the tripwire that was missing when the recursion builder divergence went
  # undetected — do not exclude circuits from it.
  diff test_vectors/${name}/vk test_vectors/${name}/vk_plaindriver
  if [[ $? -ne 0 ]]; then
    exit_code=1
    echo "::error::$name diff check of VKs failed (with: $algorithm)"
  fi

  if [[ ( "$algorithm" == "poseidon" || "$algorithm" == "keccak" ) && "$name" != "recursion" && "$name" != "recursion_zk" ]]; then
    # recursion/recursion_zk excluded from PROOF byte-diff only: mask_points samples a random
    # offset generator (free witness), so honest provers legitimately emit different proof
    # bytes. Parity for them = VK diff above + the 4-way cross-verification below.
    diff test_vectors/${name}/proof test_vectors/${name}/proof_plaindriver
    if [[ $? -ne 0 ]]; then
      exit_code=1
      case_failed=1
      echo "::error::$name diff check of proofs failed (with: $algorithm)"
    fi
  fi

  diff test_vectors/${name}/public_inputs test_vectors/${name}/public_inputs_plaindriver
    if [[ $? -ne 0 ]]; then
      exit_code=1
      case_failed=1
      echo "::error::$name diff check of public_inputs failed (with: $algorithm)"
    fi


  bash -c "$BARRETENBERG_BINARY $verify_command -p test_vectors/${name}/proof_plaindriver -i test_vectors/${name}/public_inputs -k test_vectors/${name}/vk_plaindriver $PIPE"
  if [[ $? -ne 0 ]]; then
    exit_code=1
    case_failed=1
    echo "::error::$name verifying with bb, our proof and our key failed (with: $algorithm)"
  fi

  bash -c "$BARRETENBERG_BINARY $verify_command -p test_vectors/${name}/proof_plaindriver -i test_vectors/${name}/public_inputs -k test_vectors/${name}/vk $PIPE"
  if [[ $? -ne 0 ]]; then
    exit_code=1
    case_failed=1
    echo "::error::$name verifying with bb, our proof and their key failed (with: $algorithm)"
  fi

  bash -c "$BARRETENBERG_BINARY $verify_command -p test_vectors/${name}/proof -i test_vectors/${name}/public_inputs -k test_vectors/${name}/vk_plaindriver $PIPE"
  if [[ $? -ne 0 ]]; then
    exit_code=1
    case_failed=1
    echo "::error::$name verifying with bb, their proof and our key failed (with: $algorithm)"
  fi

  bash -c "$BARRETENBERG_BINARY $verify_command -p test_vectors/${name}/proof -i test_vectors/${name}/public_inputs -k test_vectors/${name}/vk $PIPE"
  if [[ $? -ne 0 ]]; then
    exit_code=1
    case_failed=1
    echo "::error::$name verifying with bb, their proof and their key failed (with: $algorithm)"
  fi
  return $exit_code
}

# CIRCUIT_FILTER (optional, space-separated): run exactly this subset —
# lets a wrapper shard the matrix across concurrent instances on DISJOINT
# circuit sets (all per-circuit artifacts live under test_vectors/<name>/).
# Unknown names are a hard ERROR so a shard typo can never silently skip
# a circuit. Same scheme as compare_mpc.sh.
if [[ -n "${CIRCUIT_FILTER:-}" ]]; then
  filtered=()
  for want in $CIRCUIT_FILTER; do
    found=0
    for have in "${test_cases[@]}"; do [[ $have == "$want" ]] && found=1; done
    if [[ $found -ne 1 ]]; then
      echo "::error::CIRCUIT_FILTER contains unknown circuit '$want'"
      exit 2
    fi
    filtered+=("$want")
  done
  test_cases=("${filtered[@]}")
fi

# Scoped equivalent of cleanup.sh for one circuit (same patterns, that
# circuit's dir only) — concurrent disjoint shards can't wipe each other.
cleanup_circuit() {
  local d=test_vectors/$1
  find "$d" -maxdepth 1 -name "*.proof" -type f -delete
  find "$d" -maxdepth 1 -name "*.shared" -type f -delete
  find "$d" -maxdepth 1 -name "public_input*" -type f -delete
  find "$d" -maxdepth 1 -name "verification_key" -type f -delete
  find "$d" -maxdepth 1 -name "proof.bb*" -type f -delete
  find "$d" -maxdepth 1 -name "vk.bb*" -type f -delete
  find "$d" -maxdepth 1 -name "vk*" -type f -delete
  find "$d" -maxdepth 1 -name "proof*" -type f -delete
  find "$d" -maxdepth 1 -name "zk_proof" -type f -delete
  find "$d" -maxdepth 1 -name "cosnark_vk*" -type f -delete
  find "$d" -maxdepth 1 -name "cosnark_proof*" -type f -delete
  find "$d" -maxdepth 1 -name "cosnark_public_input*" -type f -delete
}

# comparing works with all test scripts where "run_full_" is followed by the precise test case name
for f in "${test_cases[@]}"; do
  echo "running ultrahonk example" $f

  failed=0
  case_failed=0

  # compile witnesses and bytecode with specified nargo version
  echo "computing witnesses with nargo"
  bash -c "(cd test_vectors/${f} && nargo execute) $PIPE"

  # -e to exit on first error
  bash -c "${PLAINDRIVER} --prover-crs ../../co-noir-common/src/crs/bn254_g1.dat --verifier-crs ../../co-noir-common/src/crs/bn254_g2.dat --input test_vectors/${f}/Prover.toml --circuit test_vectors/${f}/target/${f}.json --hasher poseidon2 --out-dir test_vectors/${f} $PIPE" || failed=1

  if [ "$failed" -ne 0 ]
  then
    exit_code=1
    case_failed=1
    echo "::error::" $f "failed"
  fi
  run_proof_verification "$f" "poseidon"

  # Run with ZK:

  bash -c "${PLAINDRIVER} --prover-crs ../../co-noir-common/src/crs/bn254_g1.dat --verifier-crs ../../co-noir-common/src/crs/bn254_g2.dat --input test_vectors/${f}/Prover.toml --circuit test_vectors/${f}/target/${f}.json --hasher poseidon2 --out-dir test_vectors/${f} --zk $PIPE" || failed=1

  if [ "$failed" -ne 0 ]
  then
    exit_code=1
    case_failed=1
    echo "::error::" $f "failed with ZK"
  fi
  run_proof_verification "$f" "poseidon_zk"
  cleanup_circuit "$f"

   # -e to exit on first error
  bash -c "${PLAINDRIVER} --prover-crs ../../co-noir-common/src/crs/bn254_g1.dat --verifier-crs ../../co-noir-common/src/crs/bn254_g2.dat --input test_vectors/${f}/Prover.toml --circuit test_vectors/${f}/target/${f}.json --hasher keccak --out-dir test_vectors/${f} $PIPE"  || failed=1

  if [ "$failed" -ne 0 ]
  then
    exit_code=1
    case_failed=1
    echo "::error::" $f "failed"
  fi
  run_proof_verification "$f" "keccak"
  cleanup_circuit "$f"
  # Run with ZK:
  bash -c "${PLAINDRIVER} --prover-crs ../../co-noir-common/src/crs/bn254_g1.dat --verifier-crs ../../co-noir-common/src/crs/bn254_g2.dat --input test_vectors/${f}/Prover.toml --circuit test_vectors/${f}/target/${f}.json --hasher keccak --out-dir test_vectors/${f} --zk $PIPE" || failed=1
  if [ "$failed" -ne 0 ]
  then
    exit_code=1
    case_failed=1
    echo "::error::" $f "failed with ZK"
  fi
  run_proof_verification "$f" "keccak_zk"
  cleanup_circuit "$f"
  echo ""
done

echo "===================="
if [ "$exit_code" -eq 0 ]
then
  echo "Summary: all ${#test_cases[@]} test cases succeeded"
else
  echo "Summary: ${#failed_tests[@]}/${#test_cases[@]} test cases failed:"
  for f in "${failed_tests[@]}"; do
    echo "  - $f"
  done
fi

exit "$exit_code"

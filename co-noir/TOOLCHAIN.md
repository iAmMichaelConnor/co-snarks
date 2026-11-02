# Aztec v6 toolchain

This workspace targets the UltraHonk proof system in
[Aztec v6.0.0](https://github.com/AztecProtocol/aztec-packages/releases/tag/v6.0.0).
The exact pairing is recorded in the repository-root `versions.env`:

| Tool | Version | Source commit |
| --- | --- | --- |
| Aztec / Barretenberg | v6.0.0 | `0219f11d8133970df3974fe5ae65e006bf8c193a` |
| Noir / Nargo | v1.0.0 | `275d3ab1a5c916c6ea73e8d6b943f685f574500c` |

Aztec v6.0.0 itself pins the Noir submodule at v1.0.0-rc.3
(`5a7ee9bf5ed8973076df7bb0d2b723024db09ae7`). This workspace uses the final
Noir v1.0.0 release instead, for both the Rust Noir dependencies and Nargo.
Between rc.3 and v1.0.0 the ACIR and Brillig formats are unchanged; the
releases fix the compiler frontend and SSA passes, and the ACVM's ECDSA
solver now reduces `R.x` modulo the curve order. Recompiling every tracked
test vector with v1.0.0 leaves its ACIR bytecode, ABI and witness byte-identical,
so official bb v6.0.0 proves and verifies v1.0.0 artifacts unchanged.
Compile application artifacts with Nargo v1.0.0.
Compatibility here covers UltraHonk; it does not add Chonk, AVM or rollup proving.

## Independent Barretenberg oracle

With a full Aztec checkout containing the release tag:

```sh
scripts/build-bb-oracle.sh v6.0.0 /tmp/bb-v6-oracle /path/to/aztec-packages
```

The example comparison scripts use relative paths and must run from
`co-noir/co-noir/examples`. For example:

```sh
cd co-noir/co-noir/examples
BARRETENBERG_BINARY=/tmp/bb-v6-oracle/bb bash compare.sh
```

The build helper exports both `barretenberg/cpp` and the final release's
`ipc-runtime` dependency, constants generator and Noir constants input. The
final-release build also needs a Node version that can execute TypeScript
(such as Node 24) and `clang-format-20`. Its provenance record identifies the full source
commit and the Noir commit from `versions.env`. Source builds can report a placeholder version;
use the provenance record to identify them. The final BB CLI also accepts named
verifier targets: `noir-recursive[-no-zk]` for Poseidon2 and `evm[-no-zk]` for
Keccak. The older explicit scheme/hash options remain available.

## Verification and circuit requirements

Verification-key decoding rejects non-canonical field words and integer headers
that exceed 64 bits, matching the final release codecs. The native verifier
rejects trailing proof data and non-padded ZK keys with
fewer than three sumcheck rounds, matching final BB. Finite PCS points,
mixed-infinity accumulator rejection, short scalar recursive aggregation and
the five SmallSubgroupIPA opening claims follow the final release protocol.

Grumpkin multi-scalar multiplication checks arbitrary constant bases against
Straus offset collisions. Only the standard generator and fixed lookup-table
bases, including their negatives, retain the unchecked path. An arbitrary
constant contribution also requires complete offset removal, even when all
variable-scalar bases are trusted. Regenerate proving and verification keys
for circuits affected by these additional constraints.

The original generation provenance of retained fixtures remains recorded beside
them. Byte equality with newly generated final-release proofs and keys is checked
separately; changing a tool pin does not relabel old artifacts as newly generated.

## Local validation

```sh
cargo test --locked -p tests --test noir
cargo test --locked -p co-builder --lib cycle_msm_release_tests
cargo test --locked -p co-noir-common --test transcript_encoding
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

The MSM regression constructs a circuit-author-selected constant equal to the
difference of two Straus offset generators. Its collision proof is rejected;
a non-colliding arbitrary-point proof remains accepted. The ordinary proof
matrix also rejects an appended field element for both hashers and ZK modes.

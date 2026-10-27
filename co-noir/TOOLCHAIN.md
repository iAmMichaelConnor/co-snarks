# Aztec v6 toolchain

This workspace targets the UltraHonk proof system in
[Aztec v6.0.0](https://github.com/AztecProtocol/aztec-packages/releases/tag/v6.0.0).
The exact pairing is recorded in the repository-root `versions.env`:

| Tool | Version | Source commit |
| --- | --- | --- |
| Aztec / Barretenberg | v6.0.0 | `0219f11d8133970df3974fe5ae65e006bf8c193a` |
| Noir / Nargo | v1.0.0-rc.3 | `5a7ee9bf5ed8973076df7bb0d2b723024db09ae7` |

The final Aztec release retains the same Noir submodule as v6.0.0-rc.6.
The Rust Noir dependencies therefore remain on rc.3 even though TACEO's v5
branch uses rc.5. Compile application artifacts with the paired Nargo.
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
BB_TARGET=/tmp/bb-v6-oracle/bb bash compare.sh
```

The build helper exports both `barretenberg/cpp` and the final release's
`ipc-runtime` dependency, constants generator and Noir constants input. The
final-release build also needs a Node version that can execute TypeScript
(such as Node 24) and `clang-format-20`. Its provenance record identifies the full source
commit and paired Noir commit. Source builds can report a placeholder version;
use the provenance record to identify them. The final BB CLI also accepts named
verifier targets: `noir-recursive[-no-zk]` for Poseidon2 and `evm[-no-zk]` for
Keccak. The older explicit scheme/hash options remain available.

## Changes from rc.6

Verification-key decoding rejects non-canonical field words and integer headers
that exceed 64 bits, matching the final release codecs. The native verifier
rejects trailing proof data and non-padded ZK keys with
fewer than three sumcheck rounds, matching final BB. Finite PCS points,
mixed-infinity accumulator rejection, short scalar recursive aggregation and
the five SmallSubgroupIPA opening claims were already implemented.

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

# UltraHonk

This crate implements Aztec's UltraHonk prover and verifier in Rust. The integration targets Barretenberg **v6.0.0** (commit `0219f11d8133970df3974fe5ae65e006bf8c193a`) and its Noir submodule **v1.0.0-rc.3** (commit `5a7ee9bf5ed8973076df7bb0d2b723024db09ae7`). Tool pins live in [`versions.env`](../../../versions.env).

Build the independent Barretenberg oracle from the exact source checkout:

```bash
git clone https://github.com/AztecProtocol/aztec-packages.git
cd aztec-packages
git checkout --detach 0219f11d8133970df3974fe5ae65e006bf8c193a
cd barretenberg/cpp
cmake --preset default -DAVM=OFF -DBB_LITE=OFF
cmake --build build --target bb -j 8
```

Source builds report a placeholder version. Record the source commit and build options beside the binary; the version string alone does not identify a proof-compatible oracle.

Existing v5 proofs, verification keys, and serialized proving-key shares are not compatible with this protocol. Regenerate them with the paired compiler and prover. Saved co-proving keys include a mandatory version and privacy header. Keys without the current header must be regenerated; old caches must not be passed to the v6 CLI.

## Building this workspace

- Requires **Rust ≥ 1.90** — pinned by `rust-toolchain.toml` at the repo root, so rustup selects (and if needed installs) the right toolchain automatically.
- The scripts in `examples/` (`run_full_poseidon.sh`, `compare.sh`, `compare_mpc.sh`, …) must be run **from the `examples/` directory** — all their relative paths (`test_vectors/`, `configs/`, `../../co-noir-common/…`) assume it.
- Warning: `compare.sh`/`compare_mpc.sh` run `cleanup.sh` after every test case, which deletes proof/witness artifacts in `examples/` and `test_vectors/` — don't keep hand-made artifacts there while they run.

The prover in this repository, ``UltraHonk::prove`` in `src/prover.rs`, is compatible with `UltraProver_<UltraFlavor>/UltraProver_<UltraZKFlavor>/UltraProver_<UltraKeccakFlavor>/UltraProver_<UltraKeccakZKFlavor>` (depending on the used transcript hasher) in Barretenberg. Similar, the ``Ultrahonk::verify`` verifier in `src/verifier.rs` is compatible with `UltraVerifier_<UltraFlavor>/UltraVerifier_<UltraZKFlavor>/UltraVerifier_<UltraKeccakFlavor>/UltraVerifier_<UltraKeccakZKFlavor>` in Barretenberg.

## Usage

First, one needs to create the circuit file from a Noir source code. Your Noir project should have the following files/folders:

- `src/main.nr`: Contains the code which should be executed in MPC and/or proven.
- `Nargo.toml`: Similar to Cargo.toml, just for Noir projects.
- `Prover.toml`: The inputs for the main function in `src/main.nr` used in proof generation.

To create the circuit file used in Co-Noir, one needs to install Nargo following the instructions in [https://noir-lang.org/docs/getting_started/noir_installation/](https://noir-lang.org/docs/getting_started/noir_installation/). Our prover is compatible with Nargo version v1.0.0-rc.3.
Then you can just execute the following command:

```bash
nargo compile
```

The resulting circuit file (*.json) is then located in the `target` folder.

Alternatively, if you want to create the extended witness from the input in `Prover.toml`, use

```bash
nargo execute witness
```

This command then stores the resulting circuit file (*.json), alongside the extended witness (`witness.gz`) in the `target` folder.

### Co-Noir Commands

Currently the Co-Noir binary allows the following commands, which we illustrate on the Noir example of proving a Poseidon Hash computation. See the Nargo source code in `examples/test_vectors/poseidon/src/main.nr`.

The following commands are all executed from the `examples` folder, just like the .sh examples.

#### SplitInput

If you want to calculate the extended witness and the prove from the input file `test_vectors/poseidon/Prover.toml` (i.e., if you want to hash the input ["0", "1", "2", "3", "4", "5", "6", "7"] in MPC and prove the computation), you first have to secret share this input file. This can be done using the SplitInput command:

```bash
cargo run --release --bin co-noir -- split-input --circuit test_vectors/poseidon/poseidon.json --input test_vectors/poseidon/Prover.toml --protocol REP3 --out-dir test_vectors/poseidon
```

This command uses the *REP3* MPC protocol and produces the shares for 3 MPC in the `test_vectors/poseidon` folder. As input it takes the circuit file `poseidon.json` and the `Prover.toml` file which contains the preimage of the hash which we want to share.

#### GenerateWitness

After the SplitInput command, the computing parties engage in executing the circuit (in our case Poseidon) on the shared input in MPC. Each party thus executes the following command:

```bash
cargo run --release --bin co-noir -- generate-witness --input test_vectors/poseidon/Prover.toml.shared --circuit test_vectors/poseidon/poseidon.json --protocol REP3 --config configs/party.toml --out test_vectors/poseidon/poseidon.gz.shared
```

Again, `poseidon.json` is the circuit file from Noir, while `Prover.toml.shared` is one output of SplitWitness and `party.toml` is a network configuration. As MPC protocol we currently only support *REP3* for the Witness extension.

#### SplitWitness

Instead of performing the witness extension in MPC, one can also secret share the .gz witness file computed by Noir. The command is the following:

```bash
cargo run --release --bin co-noir -- split-witness --witness test_vectors/poseidon/poseidon.gz --circuit test_vectors/poseidon/poseidon.json --protocol REP3 --out-dir test_vectors/poseidon
```

Here, `poseidon.json` is the circuit file from Noir, `poseidon.gz` the extended witness from noir, and the output shares are stored in `test_vectors/poseidon`. The output shares are therebey indistinguishable from the output shares produced by the GenerateWitness command.
For SplitWitness, both REP3 and Shamir are supported.

#### TranslateWitness

This command can be used to translate extended witnesses (outputs of GenerateWitness or SplitWitness) from REP3 to 3-party Shamir secret sharing:

```bash
cargo run --release --bin co-noir -- translate-witness --witness test_vectors/poseidon/poseidon.gz.shared --src-protocol REP3 --target-protocol SHAMIR --config configs/party.toml --out test_vectors/poseidon/shamir_poseidon.gz.shared
```

Here, `poseidon.gz.shared` is the REP3 input share, `shamir_poseidon.gz.shared` the Shamir output share, and `party.toml` is a network configuration.

#### GenerateProof

To create a proof in MPC, one needs the extended witness (from GenerateWitness, SplitWitness, or TranslateWitness):

```bash
cargo run --release --bin co-noir -- build-and-generate-proof --witness test_vectors/poseidon/poseidon.gz.shared --circuit test_vectors/poseidon/poseidon.json --crs test_vectors/bn254_g1.dat --protocol REP3 --hasher keccak --config configs/party.toml --out proof.proof --public-input public_input
```

Here, `poseidon.gz.shared` is the share of the witness, `poseidon.json` is the circuit file from Noir, `bn254_g1.dat` is the file storing the prover CRS and `party.toml` is the network configuration. As output, one creates the UltraHonk proof `proof.proof` and the output of the circuit `public_input.json`. The parameter `--hasher poseidon2` defines that Poseidon2 is used as the transcript hasher, the other implemented option would be Keccak256.

The corresponding Barretenberg command (from `barretenberg/cpp/build/bin`) is:

```bash
./bb prove_ultra_honk -b poseidon.json -w poseidon.gz -o proof.proof
```

where poseidon.gz is the witness file created by Noir (which is equivalent to a non-secret-shared variant of `poseidon.gz.shared`). The generated proof key is the same, regardless of using Co-Noir or Barretenberg.
Note: Barretenberg does not require the file for storing the CRS, since Barretenberg automatically downloads it if it is not present.

#### Recursive input visibility

`build-proving-key` and `build-and-generate-proof` keep shared recursive
inputs secret by default. If the circuit needs a recursive operation whose
private implementation is unavailable, proving-key construction returns an
error before opening those inputs.

Private recursive witness construction supports BN254 REP3 and plain execution;
Shamir rejects this profile. The private profile blinds the final pairing
accumulator and requires a zero-knowledge outer proof (`--zk`). Predictable
seeded masking is rejected for private-recursion proving keys.

The added blinding constraints produce a different verification key from the
canonical Barretenberg circuit. Key generation and proving must select the same
profile and CRS. Proofs retain the v6 format and verify using the key for their
profile. Saved co-proving keys carry mandatory privacy metadata; older saved
keys must be regenerated.

For a computation where every participating prover may learn the recursive
inputs, explicitly pass `--reveal-recursion-inputs`. This permits disclosure of
the **inner proof, its public inputs, verification key, key hash, and predicate**
to the MPC participants. It does not permit disclosure of unrelated witness
values. All participants should select the same setting. The outer proof's
`--zk` flag does not grant this permission and does not prevent participants
from seeing inputs opened during witness extension.

The equivalent configuration setting is `reveal_recursion_inputs = true`
(or `CONOIR_REVEAL_RECURSION_INPUTS=true`). The default is false;
`--reveal-recursion-inputs=false` overrides an opt-in from configuration.
The `generate-proof` command operates on an already constructed proving key and
does not perform this recursive-input opening or accept the disclosure flag.
The standing recursive parity fixture opts in explicitly; this checks proof
compatibility with public-to-participants recursive inputs, not private
recursive witness extension.

#### CreateVK

To verify the created proof, we first need to create a verification key. This can be done with:

```bash
cargo run --release --bin co-noir -- create-vk --circuit test_vectors/poseidon/poseidon.json --crs test_vectors/bn254_g1.dat --hasher poseidon2 --vk test_vectors/poseidon/verification_key
```

Here, `poseidon.json` is the circuit file from Noir, `bn254_g1.dat` is the file storing the prover CRS, and the output is written to `verification_key`. Again, `--hasher poseidon2` defines that Poseidon2 is used as the transcript hasher.

The corresponding Barretenberg command (from `barretenberg/cpp/build/bin`) is:

```bash
./bb write_vk_ultra_honk -b poseidon.json -o verification_key
```

Here, `poseidon.json` is the circuit file from Noir. The output verification key is the same, regardless of using Co-Noir or Barretenberg.
Note: Barretenberg does not require the file for storing the CRS, since Barretenberg automatically downloads it if it is not present.

#### Verify

To verify the proof, just use:

```bash
cargo run --release --bin co-noir -- verify --proof proof.proof --public-input public_input --vk test_vectors/poseidon/verification_key --hasher poseidon2 --crs test_vectors/bn254_g2.dat
```

Here, `proof.proof` is the proof we want to verify, `verification_key` is the output of CreateVK, and `bn254_g2.dat` is the verifier CRS. Again, `--hasher poseidon2` defines that Poseidon2 is used as the transcript hasher.

The corresponding Barretenberg command (from `barretenberg/cpp/build/bin`) is:

```bash
./bb verify_ultra_honk -k verification_key -p proof.proof
```

Note: Barretenberg does not require the file for storing the CRS, since Barretenberg automatically downloads it if it is not present.

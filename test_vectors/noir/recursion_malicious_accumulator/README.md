# Recursive proof with an invalid inner proof

The `recursion` circuit (`co-noir/co-noir/examples/test_vectors/recursion`) verifies an inner
UltraHonk proof in-circuit. The in-circuit verifier does not perform the final pairing check of the
inner proof: it outputs a pairing point accumulator as public inputs and leaves the check to the
verifier of the outer proof.

`Prover.toml` is the `recursion` example's `Prover.toml` with the y-coordinate of the inner proof's
last commitment (KZG:W, the last two limbs of `proof`) negated. The witness still solves and the
outer proof is valid for the outer circuit, but the accumulator it carries fails the pairing check.

Files in `kat/` (Poseidon2 transcript, no ZK):

- `recursion_malicious_accumulator.json`, `.gz`: `nargo execute` with nargo 1.0.0.
- `vk`: verification key (identical to `bb write_vk` with bb 6.0.0).
- `honest_proof`, `honest_public_inputs`: outer proof for the example's unmodified `Prover.toml`.
  bb 6.0.0 accepts it.
- `malicious_proof`, `malicious_public_inputs`: outer proof for this directory's `Prover.toml`.
  bb 6.0.0 rejects it ("verification failed at pairing check").

Generated with the plain prover (proofs of this circuit are randomized, so regenerated proofs differ
byte-wise but behave the same). The prover may need a larger stack (`ulimit -s unlimited`), and the
plain driver's own verification of the malicious proof fails after it has written the files:

```sh
CRS="--prover-crs co-noir/co-noir-common/src/crs/bn254_g1.dat --verifier-crs co-noir/co-noir-common/src/crs/bn254_g2.dat"
CIRCUIT=test_vectors/noir/recursion_malicious_accumulator/kat/recursion_malicious_accumulator.json
cargo run --release --bin plaindriver -- $CRS --circuit $CIRCUIT --hasher poseidon2 \
  --input co-noir/co-noir/examples/test_vectors/recursion/Prover.toml --out-dir /tmp/honest
cargo run --release --bin plaindriver -- $CRS --circuit $CIRCUIT --hasher poseidon2 \
  --input test_vectors/noir/recursion_malicious_accumulator/Prover.toml --out-dir /tmp/malicious
# copy {proof,public_inputs,vk}_plaindriver from each directory to kat/

bb verify --scheme ultra_honk --oracle_hash poseidon2 --disable_zk \
  -p kat/honest_proof -i kat/honest_public_inputs -k kat/vk       # verifies
bb verify --scheme ultra_honk --oracle_hash poseidon2 --disable_zk \
  -p kat/malicious_proof -i kat/malicious_public_inputs -k kat/vk # fails at the pairing check
```

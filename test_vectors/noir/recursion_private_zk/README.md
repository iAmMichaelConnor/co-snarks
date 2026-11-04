# Recursion with private inputs and a predicate

Verifies the inner proof of the `recursion_zk` example (`co-noir/co-noir/examples/test_vectors/recursion_zk`) if
`enabled` is true. All arguments are private: the verification key, the proof, the key hash, the inner public input
and the predicate.

`Prover.toml` is the example's `Prover.toml` plus `enabled = true`. `kat/recursion_private_zk.json` and `kat/recursion_private_zk.gz` are the
output of `nargo execute` with nargo 1.0.0.

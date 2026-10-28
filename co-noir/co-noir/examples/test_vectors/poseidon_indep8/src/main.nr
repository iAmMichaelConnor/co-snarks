use poseidon::bn254::permutation;

// K independent t8 permutations over DISJOINT inputs (no chaining). Each
// permutation's inputs are level-0 witnesses, so the witext DAG holds all K
// hashes at the same levels: depth stays that of a single hash while the
// per-level width and serial round count scale by K. The final sum is a linear
// (local, zero-round) combination, so it does not chain the hashes.
global K: u32 = 8;

fn main(plains: [[Field; 8]; K]) -> pub Field {
    let mut acc = 0;
    for i in 0..K {
        acc += permutation::t8(plains[i])[0];
    }
    acc
}

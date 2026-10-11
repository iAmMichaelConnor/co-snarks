use poseidon::bn254::permutation;

global K: u32 = 5;

fn main(plains: [Field; 8]) -> pub Field {
    let mut s = plains;
    for _ in 0..K {
        s = permutation::t8(s);
    }
    s[0]
}

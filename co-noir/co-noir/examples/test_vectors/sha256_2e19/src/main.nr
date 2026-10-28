global K: u32 = 132;

fn main(input: [u32; 16], state: [u32; 8]) -> pub [u32; 8] {
    let mut s = state;
    for _ in 0..K {
        s = std::hash::sha256_compression(input, s);
    }
    s
}

// A secp256r1 signature with r = s, i.e. u2 = r / s = 1. The ACVM accepts it, and so does the
// solver. Barretenberg 6.0.0 makes its ECDSA verification return false when u2 is 1 or -1 (its
// secp256r1 scalar multiplication does not support these values), so this circuit cannot be
// proven with it.
fn main(
    hashed_message: [u8; 32],
    pub_key_x: [u8; 32],
    pub_key_y: [u8; 32],
    signature: [u8; 64],
) -> pub bool {
    std::ecdsa_secp256r1::verify_signature(pub_key_x, pub_key_y, signature, hashed_message)
}

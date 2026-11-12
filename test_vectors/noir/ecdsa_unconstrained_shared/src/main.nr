// ECDSA verification in Brillig on private inputs. With secret-shared inputs, co-brillig rejects
// it with an error.
unconstrained fn verify(
    hashed_message: [u8; 32],
    pub_key_x: [u8; 32],
    pub_key_y: [u8; 32],
    signature: [u8; 64],
) -> bool {
    std::ecdsa_secp256k1::verify_signature(pub_key_x, pub_key_y, signature, hashed_message)
}

fn main(
    hashed_message: [u8; 32],
    pub_key_x: [u8; 32],
    pub_key_y: [u8; 32],
    signature: [u8; 64],
) -> pub bool {
    // Safety: the result is only returned, not relied upon.
    unsafe {
        verify(hashed_message, pub_key_x, pub_key_y, signature)
    }
}

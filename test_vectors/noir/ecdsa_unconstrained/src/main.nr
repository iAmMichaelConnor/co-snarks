// ECDSA verification in Brillig. The inputs are public, as Brillig only verifies signatures on
// public inputs.
unconstrained fn verify(
    hashed_message: [u8; 32],
    k1_pub_key_x: [u8; 32],
    k1_pub_key_y: [u8; 32],
    k1_signature: [u8; 64],
    r1_hashed_message: [u8; 32],
    r1_pub_key_x: [u8; 32],
    r1_pub_key_y: [u8; 32],
    r1_signature: [u8; 64],
) -> [bool; 4] {
    [
        std::ecdsa_secp256k1::verify_signature(
            k1_pub_key_x,
            k1_pub_key_y,
            k1_signature,
            hashed_message,
        ),
        std::ecdsa_secp256k1::verify_signature(
            k1_pub_key_x,
            k1_pub_key_y,
            k1_signature,
            r1_hashed_message,
        ),
        std::ecdsa_secp256r1::verify_signature(
            r1_pub_key_x,
            r1_pub_key_y,
            r1_signature,
            r1_hashed_message,
        ),
        std::ecdsa_secp256r1::verify_signature(
            r1_pub_key_x,
            r1_pub_key_y,
            r1_signature,
            hashed_message,
        ),
    ]
}

fn main(
    hashed_message: pub [u8; 32],
    k1_pub_key_x: pub [u8; 32],
    k1_pub_key_y: pub [u8; 32],
    k1_signature: pub [u8; 64],
    r1_hashed_message: pub [u8; 32],
    r1_pub_key_x: pub [u8; 32],
    r1_pub_key_y: pub [u8; 32],
    r1_signature: pub [u8; 64],
) -> pub [bool; 4] {
    // Safety: the result is only returned, not relied upon.
    unsafe {
        verify(
            hashed_message,
            k1_pub_key_x,
            k1_pub_key_y,
            k1_signature,
            r1_hashed_message,
            r1_pub_key_x,
            r1_pub_key_y,
            r1_signature,
        )
    }
}

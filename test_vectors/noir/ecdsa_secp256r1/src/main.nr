// Same as `ecdsa_secp256k1` over secp256r1. The public key is a public input, so the
// verifications mix public and secret-shared inputs; the last one has only public inputs.
fn main(
    hashed_message: [u8; 32],
    pub_key_x: pub [u8; 32],
    pub_key_y: pub [u8; 32],
    signature: [u8; 64],
    bad_hashed_message: [u8; 32],
    high_s_signature: [u8; 64],
    bad_pub_key_y: pub [u8; 32],
    zero_r_signature: [u8; 64],
    zero_s_signature: [u8; 64],
    r_equal_n_signature: [u8; 64],
    pub_key_x_equal_q: pub [u8; 32],
    enable: bool,
    r_plus_n_hashed_message: [u8; 32],
    r_plus_n_pub_key_x: [u8; 32],
    r_plus_n_pub_key_y: [u8; 32],
    r_plus_n_signature: [u8; 64],
    r_plus_n_plus_one_signature: [u8; 64],
    public_hashed_message: pub [u8; 32],
    public_signature: pub [u8; 64],
) -> pub [bool; 13] {
    let verify = std::ecdsa_secp256r1::verify_signature;
    let mut result = [false; 13];
    result[0] = verify(pub_key_x, pub_key_y, signature, hashed_message);
    result[1] = verify(pub_key_x, pub_key_y, signature, bad_hashed_message);
    result[2] = verify(pub_key_x, pub_key_y, high_s_signature, hashed_message);
    result[3] = verify(pub_key_x, bad_pub_key_y, signature, hashed_message);
    result[4] = verify(pub_key_x, pub_key_y, zero_r_signature, hashed_message);
    result[5] = verify(pub_key_x, pub_key_y, zero_s_signature, hashed_message);
    result[6] = verify(pub_key_x, pub_key_y, r_equal_n_signature, hashed_message);
    result[7] = verify(pub_key_x_equal_q, pub_key_y, signature, hashed_message);
    if enable {
        result[8] = verify(pub_key_x, pub_key_y, signature, hashed_message);
    }
    if !enable {
        result[9] = verify(
            pub_key_x,
            bad_pub_key_y,
            high_s_signature,
            bad_hashed_message,
        );
    }
    result[10] = verify(
        pub_key_x,
        pub_key_y,
        public_signature,
        public_hashed_message,
    );
    // R.x >= n: the signature is valid because R.x == r + n; r + 1 is not.
    result[11] = verify(
        r_plus_n_pub_key_x,
        r_plus_n_pub_key_y,
        r_plus_n_signature,
        r_plus_n_hashed_message,
    );
    result[12] = verify(
        r_plus_n_pub_key_x,
        r_plus_n_pub_key_y,
        r_plus_n_plus_one_signature,
        r_plus_n_hashed_message,
    );
    result
}

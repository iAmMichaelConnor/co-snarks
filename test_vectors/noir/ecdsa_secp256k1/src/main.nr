// Verifies one valid and several invalid secp256k1 signatures. Invalid signatures make the
// verification return false rather than fail. A verification under a condition carries the
// condition as its predicate: when it is false the black box returns true without checking its
// inputs.
fn main(
    hashed_message: [u8; 32],
    pub_key_x: [u8; 32],
    pub_key_y: [u8; 32],
    signature: [u8; 64],
    bad_hashed_message: [u8; 32],
    high_s_signature: [u8; 64],
    bad_pub_key_y: [u8; 32],
    zero_r_signature: [u8; 64],
    zero_s_signature: [u8; 64],
    r_equal_n_signature: [u8; 64],
    pub_key_x_equal_q: [u8; 32],
    enable: bool,
    r_plus_n_hashed_message: [u8; 32],
    r_plus_n_pub_key_x: [u8; 32],
    r_plus_n_pub_key_y: [u8; 32],
    r_plus_n_signature: [u8; 64],
    r_plus_n_plus_one_signature: [u8; 64],
) -> pub [bool; 12] {
    let verify = std::ecdsa_secp256k1::verify_signature;
    let mut result = [false; 12];
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
    // R.x >= n: the signature is valid because R.x == r + n; r + 1 is not.
    result[10] = verify(
        r_plus_n_pub_key_x,
        r_plus_n_pub_key_y,
        r_plus_n_signature,
        r_plus_n_hashed_message,
    );
    result[11] = verify(
        r_plus_n_pub_key_x,
        r_plus_n_pub_key_y,
        r_plus_n_plus_one_signature,
        r_plus_n_hashed_message,
    );
    result
}

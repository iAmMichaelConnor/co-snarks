use super::add_rep3_acvm_test;

add_rep3_acvm_test!("add3u64");
add_rep3_acvm_test!("addition_multiplication");
add_rep3_acvm_test!("approx_sigmoid");
add_rep3_acvm_test!("assert");
add_rep3_acvm_test!("get_bytes");
add_rep3_acvm_test!("if_then");
add_rep3_acvm_test!("negative");
add_rep3_acvm_test!("poseidon");
add_rep3_acvm_test!("poseidon2");
add_rep3_acvm_test!("poseidon_assert");
add_rep3_acvm_test!("poseidon_input2");
add_rep3_acvm_test!("poseidon_stdlib");
add_rep3_acvm_test!("quantized");
add_rep3_acvm_test!("random_access");
add_rep3_acvm_test!("slice");
add_rep3_acvm_test!("to_radix32");
add_rep3_acvm_test!("unconstrained_fn");
add_rep3_acvm_test!("unconstrained_fn_field");
add_rep3_acvm_test!("write_access");
add_rep3_acvm_test!("bb_sha256_compression");
add_rep3_acvm_test!("aes128");
add_rep3_acvm_test!("unconstrained_fn_not");
add_rep3_acvm_test!("blackbox_and");
add_rep3_acvm_test!("blackbox_xor");
add_rep3_acvm_test!("blackbox_poseidon2");
add_rep3_acvm_test!("pedersen_hash");
add_rep3_acvm_test!("pedersen_commitment");
add_rep3_acvm_test!("blake2s");
add_rep3_acvm_test!("blake3");
add_rep3_acvm_test!("embedded_curve_add");
add_rep3_acvm_test!("embedded_curve_predicate");
add_rep3_acvm_test!("ecdsa_secp256k1");
add_rep3_acvm_test!("ecdsa_secp256r1");
add_rep3_acvm_test!("ecdsa_secp256r1_u2_is_one");
add_rep3_acvm_test!("ecdsa_unconstrained");

/// co-brillig rejects ECDSA verification on secret-shared inputs with an error.
#[test]
fn test_rep3_ecdsa_unconstrained_shared_inputs_error() {
    let err = super::rep3_acvm_error("ecdsa_unconstrained_shared");
    assert!(
        err.contains("ecdsa_secp256k1 on secret-shared inputs is not supported in Brillig"),
        "{err}"
    );
}

use ark_bn254::{Fq, Fr, G1Projective};
use ark_ff::PrimeField;
use co_noir_common::{honk_proof::HonkProofError, transcript::Transcript};
use noir_types::{HonkProof, U256};
use num_bigint::BigUint;
use sha3::Keccak256;

fn word(value: BigUint) -> U256 {
    let raw = value.to_bytes_be();
    let mut bytes = vec![0u8; 32 - raw.len()];
    bytes.extend(raw);
    U256::from_buffer(&bytes).unwrap()[0]
}
fn transcript(words: Vec<U256>) -> Transcript<Fr, Keccak256> {
    Transcript::new_verifier(HonkProof::new(words))
}

#[test]
fn keccak_scalar_reads_reject_noncanonical_words() {
    let modulus: BigUint = Fr::MODULUS.into();
    for value in [&modulus - 1u64, BigUint::from(0u64)] {
        let raw = word(value);
        assert!(
            transcript(vec![raw])
                .receive_fr_from_prover::<G1Projective>("x".into())
                .is_ok()
        );
    }
    for value in [
        modulus.clone(),
        &modulus + 1u64,
        (BigUint::from(1u64) << 256) - 1u64,
    ] {
        let raw = word(value);
        assert!(matches!(
            transcript(vec![raw]).receive_fr_from_prover::<G1Projective>("x".into()),
            Err(HonkProofError::NonCanonicalFieldEncoding)
        ));
        assert!(matches!(
            transcript(vec![raw]).receive_fr_vec_from_prover::<G1Projective>("x".into(), 1),
            Err(HonkProofError::NonCanonicalFieldEncoding)
        ));
        assert!(matches!(
            transcript(vec![raw]).receive_fr_array_from_prover::<G1Projective, 1>("x".into()),
            Err(HonkProofError::NonCanonicalFieldEncoding)
        ));
    }
}

#[test]
fn keccak_points_reject_modulus_aliases_including_infinity() {
    let modulus: BigUint = Fq::MODULUS.into();
    // (1,2) is the BN254 generator; (0,0) encodes infinity.
    for (x, y) in [(1u64, 2u64), (0u64, 0u64)] {
        assert!(
            transcript(vec![word(x.into()), word(y.into())])
                .receive_point_from_prover::<G1Projective>("P".into())
                .is_ok()
        );
        for words in [
            vec![word(&modulus + x), word(y.into())],
            vec![word(x.into()), word(&modulus + y)],
        ] {
            assert!(matches!(
                transcript(words).receive_point_from_prover::<G1Projective>("P".into()),
                Err(HonkProofError::NonCanonicalFieldEncoding)
            ));
        }
    }
}

#[test]
fn oversized_transcript_read_is_rejected_without_overflow() {
    let mut reader = transcript(vec![U256::from(0u64)]);
    reader
        .receive_fr_from_prover::<G1Projective>("first".into())
        .unwrap();
    assert!(matches!(
        reader.receive_fr_vec_from_prover::<G1Projective>("oversized".into(), usize::MAX),
        Err(HonkProofError::ProofTooSmall)
    ));
}

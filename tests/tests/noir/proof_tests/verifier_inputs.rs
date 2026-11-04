//! The native verifier and the proof/VK decoders must reject malformed input with an error,
//! never accept it and never panic.

use crate::proof_tests::CRS_PATH_G1;
use crate::proof_tests::CRS_PATH_G2;
use ark_bn254::Bn254;
use ark_ff::PrimeField;
use co_acvm::PlainAcvmSolver;
use co_builder::prelude::constraint_system_from_reader;
use co_builder::prelude::HonkRecursion;
use co_builder::prelude::UltraCircuitBuilder;
use co_noir::UltraHonk;
use co_noir_common::crs::parse::CrsParser;
use co_noir_common::crs::ProverCrs;
use co_noir_common::honk_proof::{HonkProofError, TranscriptFieldType};
use co_noir_common::keys::verification_key::VerifyingKey;
use co_noir_common::transcript::{Poseidon2Sponge, TranscriptHasher};
use co_noir_common::types::Bn254G1;
use co_noir_common::types::ZeroKnowledge;
use noir_types::{HonkProof, U256};
use num_bigint::BigUint;
use sha3::Keccak256;
use std::fs::File;

const CIRCUIT_FILE: &str = "../test_vectors/noir/poseidon/kat/poseidon.json";
const WITNESS_FILE: &str = "../test_vectors/noir/poseidon/kat/poseidon.gz";

type Artifacts<H> = (
    HonkProof<<H as TranscriptHasher<TranscriptFieldType>>::DataType>,
    Vec<<H as TranscriptHasher<TranscriptFieldType>>::DataType>,
    VerifyingKey<Bn254>,
);

fn prove<H: TranscriptHasher<TranscriptFieldType>>(has_zk: ZeroKnowledge) -> Artifacts<H> {
    let constraint_system =
        constraint_system_from_reader(File::open(CIRCUIT_FILE).unwrap()).unwrap();
    let witness = noir_types::witness_from_reader(File::open(WITNESS_FILE).unwrap()).unwrap();
    let mut driver = PlainAcvmSolver::new();
    let builder = UltraCircuitBuilder::<Bn254G1>::create_circuit(
        &constraint_system,
        0,
        witness,
        HonkRecursion::UltraHonk,
        &ProverCrs::default(),
        &mut driver,
    )
    .unwrap();
    let crs_size = builder.compute_dyadic_size();
    let crs =
        CrsParser::<Bn254G1>::get_crs::<Bn254>(CRS_PATH_G1, CRS_PATH_G2, crs_size, has_zk).unwrap();
    let (prover_crs, verifier_crs) = crs.split();
    let (proving_key, verifying_key) = builder
        .create_keys::<Bn254>(prover_crs.into(), verifier_crs, &mut driver)
        .unwrap();
    let (proof, public_inputs) =
        UltraHonk::<_, H>::prove(proving_key, has_zk, &verifying_key.inner_vk).unwrap();
    (proof, public_inputs, verifying_key)
}

fn verify<H: TranscriptHasher<TranscriptFieldType>>(
    proof: HonkProof<H::DataType>,
    public_inputs: &[H::DataType],
    vk: &VerifyingKey<Bn254>,
    has_zk: ZeroKnowledge,
) -> eyre::Result<bool> {
    UltraHonk::<_, H>::verify(proof, public_inputs, vk, has_zk)
}

fn proof_error(result: eyre::Result<bool>) -> HonkProofError {
    match result {
        Err(err) => err
            .downcast::<HonkProofError>()
            .expect("expected a HonkProofError"),
        Ok(accepted) => panic!("expected an error, verifier returned {accepted}"),
    }
}

/// Adds `modulus` to the 32-byte big-endian word at `index`.
fn alias_word(buf: &mut [u8], index: usize, modulus: &BigUint) {
    let word = &mut buf[index * 32..(index + 1) * 32];
    let raw = (BigUint::from_bytes_be(word) + modulus).to_bytes_be();
    word.fill(0);
    word[32 - raw.len()..].copy_from_slice(&raw);
}

#[test]
fn proof_words_above_the_modulus_are_rejected() {
    let (proof, public_inputs, vk) = prove::<Poseidon2Sponge>(ZeroKnowledge::No);
    let modulus: BigUint = ark_bn254::Fr::MODULUS.into();
    let mut buf = proof.to_buffer();
    let last = buf.len() / 32 - 1;
    alias_word(&mut buf, last, &modulus);
    assert!(HonkProof::<ark_bn254::Fr>::from_buffer(&buf).is_err());
    // The canonical encoding still verifies.
    assert!(verify::<Poseidon2Sponge>(proof, &public_inputs, &vk, ZeroKnowledge::No).unwrap());
}

/// The final KZG commitment is not hashed into any later challenge, so a coordinate that is
/// reduced modulo q instead of rejected would give a second, byte-distinct accepting proof.
#[test]
fn keccak_final_commitment_aliases_are_rejected() {
    let modulus: BigUint = ark_bn254::Fq::MODULUS.into();
    for has_zk in [ZeroKnowledge::No, ZeroKnowledge::Yes] {
        let (proof, public_inputs, vk) = prove::<Keccak256>(has_zk);
        assert!(verify::<Keccak256>(proof.clone(), &public_inputs, &vk, has_zk).unwrap());
        for from_end in [1, 2] {
            let mut buf = proof.to_buffer();
            let index = buf.len() / 32 - from_end;
            alias_word(&mut buf, index, &modulus);
            let tampered = HonkProof::<U256>::from_buffer(&buf).unwrap();
            assert!(matches!(
                proof_error(verify::<Keccak256>(tampered, &public_inputs, &vk, has_zk)),
                HonkProofError::NonCanonicalFieldEncoding
            ));
        }
    }
}

#[test]
fn off_curve_proof_commitment_is_an_error() {
    let (proof, public_inputs, vk) = prove::<Poseidon2Sponge>(ZeroKnowledge::No);
    // Perturb the high limb of the final commitment's y-coordinate.
    let mut frs = proof.inner();
    *frs.last_mut().unwrap() += ark_bn254::Fr::from(1u64);
    assert!(matches!(
        proof_error(verify::<Poseidon2Sponge>(
            HonkProof::new(frs),
            &public_inputs,
            &vk,
            ZeroKnowledge::No
        )),
        HonkProofError::PointNotOnCurve
    ));
}

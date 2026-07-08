//! Security-regression tests (project-docs ch. 13 §3a).
//!
//! Each test pins a hardening fix at the verifier / deserialization boundary.
//! These are NEGATIVE tests: they assert the verifier REJECTS (cleanly, without
//! panicking) a malformed input that a previous version of co-noir mishandled.
//! They exercise the soundness/robustness surface, not the happy path.

use crate::proof_tests::CRS_PATH_G1;
use crate::proof_tests::CRS_PATH_G2;
use ark_bn254::Bn254;
use ark_ff::Zero;
use co_acvm::PlainAcvmSolver;
use co_builder::prelude::constraint_system_from_reader;
use co_builder::prelude::HonkRecursion;
use co_builder::prelude::UltraCircuitBuilder;
use co_noir::UltraHonk;
use co_noir_common::crs::parse::CrsParser;
use co_noir_common::crs::ProverCrs;
use co_noir_common::keys::verification_key::{VerifyingKey, VerifyingKeyBarretenberg};
use co_noir_common::transcript::Poseidon2Sponge;
use co_noir_common::types::Bn254G1;
use co_noir_common::types::ZeroKnowledge;
use noir_types::HonkProof;
use std::fs::File;

const CIRCUIT_FILE: &str = "../test_vectors/noir/poseidon/kat/poseidon.json";
const WITNESS_FILE: &str = "../test_vectors/noir/poseidon/kat/poseidon.gz";

/// Build a real poseidon2 non-ZK proof plus its verifying key, so each test can
/// tamper with a genuine artifact rather than a hand-rolled one.
fn build_artifacts() -> (
    HonkProof<ark_bn254::Fr>,
    Vec<ark_bn254::Fr>,
    VerifyingKey<Bn254>,
) {
    let has_zk = ZeroKnowledge::No;
    let constraint_system =
        constraint_system_from_reader(File::open(CIRCUIT_FILE).unwrap()).unwrap();
    let witness = noir_types::witness_from_reader(File::open(WITNESS_FILE).unwrap()).unwrap();
    let mut driver = PlainAcvmSolver::new();

    let recursion_crs_size = constraint_system.get_honk_recursion_public_inputs_size::<Bn254G1>();
    let recursion_crs = if recursion_crs_size > 0 {
        CrsParser::<Bn254G1>::get_crs_g1(CRS_PATH_G1, recursion_crs_size, has_zk).unwrap()
    } else {
        ProverCrs::default()
    };
    let builder = UltraCircuitBuilder::<Bn254G1>::create_circuit(
        &constraint_system,
        0,
        witness,
        HonkRecursion::UltraHonk,
        &recursion_crs,
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
        UltraHonk::<_, Poseidon2Sponge>::prove(proving_key, has_zk, &verifying_key.inner_vk)
            .unwrap();
    (proof, public_inputs, verifying_key)
}

/// Sanity: the untampered artifact verifies. Guards against the negative tests
/// silently passing because the whole flow is broken.
#[test]
fn baseline_valid_proof_accepts() {
    let (proof, public_inputs, vk) = build_artifacts();
    let ok = UltraHonk::<_, Poseidon2Sponge>::verify(proof, &public_inputs, &vk, ZeroKnowledge::No)
        .unwrap();
    assert!(ok, "untampered proof must verify");
}

/// §3a#10 (trailing data). A proof carrying extra field elements past the last
/// one the verifier reads must be REJECTED. Before the `assert_fully_consumed`
/// check, co-noir accepted such a proof (bb rejects it) — Phase 0 finding 1.
#[test]
fn trailing_proof_data_rejected() {
    let (proof, public_inputs, vk) = build_artifacts();

    // Append one junk field element after the genuine proof.
    let mut inner = proof.inner();
    inner.push(ark_bn254::Fr::zero());
    let tampered = HonkProof::new(inner);

    let res =
        UltraHonk::<_, Poseidon2Sponge>::verify(tampered, &public_inputs, &vk, ZeroKnowledge::No);
    // Must not accept: either a clean Err (proof-not-fully-consumed) or Ok(false).
    assert!(
        !matches!(res, Ok(true)),
        "verifier accepted a proof with trailing data: {res:?}"
    );
    assert!(res.is_err(), "trailing data should be a hard parse error");
}

/// §3a#10 (off-curve point, proof side). Corrupting a coordinate of the KZG `W`
/// commitment (the final point in the proof) must yield a clean rejection, not
/// the ark-ec `is_on_curve` panic — Phase 0 finding 2.
#[test]
fn offcurve_proof_point_rejected() {
    let (proof, public_inputs, vk) = build_artifacts();

    // The last transmitted point is KZG:W; perturbing one of its coordinate
    // limbs moves it off the curve with overwhelming probability.
    let mut inner = proof.inner();
    let n = inner.len();
    inner[n - 1] += ark_bn254::Fr::from(1u64);
    let tampered = HonkProof::new(inner);

    // A panic here fails the test — which is exactly the regression we guard.
    let res =
        UltraHonk::<_, Poseidon2Sponge>::verify(tampered, &public_inputs, &vk, ZeroKnowledge::No);
    assert!(
        !matches!(res, Ok(true)),
        "verifier accepted an off-curve proof point: {res:?}"
    );
}

/// §3a#10 (off-curve point, VK side). A verification key whose commitment bytes
/// decode to an off-curve point must be rejected by `from_buffer` with a clean
/// error, not a panic — Phase 0 finding 2.
#[test]
fn offcurve_vk_commitment_rejected() {
    let (_proof, _public_inputs, vk) = build_artifacts();

    // Round-trip the VK to its barretenberg byte layout, then corrupt a byte
    // inside the first precomputed commitment's coordinates. Layout: 3 header
    // field elements (32 B each) = 96 B, then commitments (128 B each: x0 x1
    // y0 y1). Offset 100 lands in the first commitment's x-coordinate.
    let mut buf = vk.inner_vk.to_buffer();
    buf[100] ^= 0x01;

    let res = VerifyingKeyBarretenberg::<Bn254G1>::from_buffer(&buf);
    assert!(
        res.is_err(),
        "VK parser accepted an off-curve commitment instead of erroring"
    );
}

//! Security-regression tests.
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
use co_noir_common::honk_proof::HonkProofError;
use co_noir_common::keys::verification_key::{VerifyingKey, VerifyingKeyBarretenberg};
use co_noir_common::transcript::Poseidon2Sponge;
use co_noir_common::types::Bn254G1;
use co_noir_common::types::ZeroKnowledge;
use noir_types::HonkProof;
use std::fs::File;

const CIRCUIT_FILE: &str = "../test_vectors/noir/poseidon/kat/poseidon.json";
const WITNESS_FILE: &str = "../test_vectors/noir/poseidon/kat/poseidon.gz";

/// Build a real poseidon2 proof (ZK or non-ZK) plus its verifying key, so each
/// test can tamper with a genuine artifact rather than a hand-rolled one.
fn build_artifacts_with(
    has_zk: ZeroKnowledge,
) -> (
    HonkProof<ark_bn254::Fr>,
    Vec<ark_bn254::Fr>,
    VerifyingKey<Bn254>,
) {
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

/// Non-ZK convenience wrapper.
fn build_artifacts() -> (
    HonkProof<ark_bn254::Fr>,
    Vec<ark_bn254::Fr>,
    VerifyingKey<Bn254>,
) {
    build_artifacts_with(ZeroKnowledge::No)
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

/// Trailing data. A proof carrying extra field elements past the last
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

/// Off-curve point, proof side. Corrupting a coordinate of the KZG `W`
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

/// Off-curve point, VK side. A verification key whose commitment bytes
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

/// Transcript-consumption property: for a valid proof of length L, EVERY
/// truncation must be rejected, extensions of various sizes must be rejected
/// (generalizes `trailing_proof_data_rejected`), and only the exact length
/// verifies. Pins the verifier's read-exactly-L transcript discipline as a
/// property, not a single case.
#[test]
fn proof_length_property_exact_length_only() {
    let (proof, public_inputs, vk) = build_artifacts();
    let inner = proof.inner();
    let n = inner.len();

    // Exact length verifies (property baseline).
    let ok = UltraHonk::<_, Poseidon2Sponge>::verify(
        HonkProof::new(inner.clone()),
        &public_inputs,
        &vk,
        ZeroKnowledge::No,
    )
    .unwrap();
    assert!(ok, "exact-length proof must verify");

    // Every truncation rejects. Truncations fail at the transcript-read
    // boundary (cheap parse error), so sweeping all L-1 lengths is affordable.
    for len in 0..n {
        let mut t = inner.clone();
        t.truncate(len);
        let res = UltraHonk::<_, Poseidon2Sponge>::verify(
            HonkProof::new(t),
            &public_inputs,
            &vk,
            ZeroKnowledge::No,
        );
        assert!(
            !matches!(res, Ok(true)),
            "verifier accepted a proof truncated to {len}/{n} fields: {res:?}"
        );
    }

    // Extensions reject. Each extension costs a full verify (the trailing
    // check fires after the final read), so probe a spread instead of all.
    for extra in [1usize, 2, 7, 48, n] {
        let mut t = inner.clone();
        t.extend(std::iter::repeat_n(ark_bn254::Fr::zero(), extra));
        let res = UltraHonk::<_, Poseidon2Sponge>::verify(
            HonkProof::new(t),
            &public_inputs,
            &vk,
            ZeroKnowledge::No,
        );
        assert!(
            !matches!(res, Ok(true)),
            "verifier accepted a proof extended by {extra} fields: {res:?}"
        );
    }
}

/// Zero / out-of-range `log_circuit_size` in a VK must be rejected cleanly by
/// both loaders. A `log_circuit_size = 0` VK drives the verifier's round count
/// to 0; before this hardening the field-encoded (`from_buffer`) path PANICKED
/// (`to_u64_digits()[0]` on zero indexes an empty vec) and the keccak path
/// silently accepted it. Mirrors bb `1391c49546`.
#[test]
fn zero_log_circuit_size_vk_rejected() {
    let (_proof, _public_inputs, vk) = build_artifacts();

    // Field-encoded layout: log_circuit_size is the first header field element.
    // Zeroing its 32-byte big-endian slot sets log_circuit_size = 0.
    let mut buf = vk.inner_vk.to_buffer();
    for b in buf.iter_mut().take(32) {
        *b = 0;
    }
    let res = VerifyingKeyBarretenberg::<Bn254G1>::from_buffer(&buf);
    assert!(
        matches!(res, Err(HonkProofError::CorruptedKey)),
        "from_buffer accepted (or panicked on) a log_circuit_size=0 VK: {res:?}"
    );

    // Keccak (U256) layout: same first-32-bytes header slot.
    let mut buf_k = vk.inner_vk.to_buffer_keccak();
    for b in buf_k.iter_mut().take(32) {
        *b = 0;
    }
    let res_k = VerifyingKeyBarretenberg::<Bn254G1>::from_buffer_keccak(&buf_k);
    assert!(
        matches!(res_k, Err(HonkProofError::CorruptedKey)),
        "from_buffer_keccak accepted a log_circuit_size=0 VK: {res_k:?}"
    );
}

/// Sanity: a genuine ZK proof verifies. Guards the ZK negative tests below.
#[test]
fn baseline_zk_proof_accepts() {
    let (proof, public_inputs, vk) = build_artifacts_with(ZeroKnowledge::Yes);
    let ok =
        UltraHonk::<_, Poseidon2Sponge>::verify(proof, &public_inputs, &vk, ZeroKnowledge::Yes)
            .unwrap();
    assert!(ok, "untampered ZK proof must verify");
}

/// ZK-path tamper coverage. Flipping any single field element in the decider
/// portion of a ZK proof (which includes the SmallSubgroupIPA / Libra region
/// carrying the grand-sum evaluations) must NOT verify. This is a general
/// binding check on the ZK proof body — it confirms every field of the
/// decider/SSIPA region is actually consumed and constrained by the verifier,
/// not silently ignored.
///
/// NOTE: this is deliberately NOT the full SmallSubgroupIPA A(1)=0 consistency
/// test. That one requires constructing the homogeneous-kernel perturbation
/// (delta_A(1)=delta, delta_A(g^j) = -delta/(g-1), delta_s = c) that satisfies
/// the standalone SSIPA identity yet changes the claimed Libra inner product,
/// and asserting rejection specifically through the Shplemini-batched path (the
/// standalone consistency check accepts such a perturbation, so a test that
/// bypasses Shplemini would pass without exercising the real enforcement). That
/// is a known follow-up; a naive version would give false confidence, so it is
/// intentionally not written here.
#[test]
fn zk_proof_decider_field_tamper_rejected() {
    let (proof, public_inputs, vk) = build_artifacts_with(ZeroKnowledge::Yes);
    let n = proof.inner_as_ref().len();

    // Probe several positions across the decider/SSIPA region (second half of
    // the proof) rather than a single fixed index, so the test does not depend
    // on the exact ZK proof layout. Each tampered copy must fail to verify.
    for frac in [55usize, 70, 85, 95] {
        let pos = n * frac / 100;
        let mut inner = proof.inner_as_ref().clone();
        inner[pos] += ark_bn254::Fr::from(1u64);
        let tampered = HonkProof::new(inner);

        let res = UltraHonk::<_, Poseidon2Sponge>::verify(
            tampered,
            &public_inputs,
            &vk,
            ZeroKnowledge::Yes,
        );
        assert!(
            !matches!(res, Ok(true)),
            "ZK verifier accepted a proof with field {pos}/{n} tampered: {res:?}"
        );
    }
}

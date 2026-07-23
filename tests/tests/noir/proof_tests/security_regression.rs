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

/// Downcast a `catch_unwind` payload to a printable message. Panic payloads
/// are `Box<dyn Any + Send>`; in practice `panic!`/`assert!`/`unwrap` all
/// produce either `&'static str` or `String`.
fn describe_panic_payload(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}

/// `UltraHonk::verify`, but a panic on malformed input is caught and returned
/// as `Err(message)` instead of aborting the whole sweep with an opaque
/// unwind. A malformed-input panic is itself a robustness finding (see the
/// module doc), so callers must not treat `Err` here the same as a clean
/// rejection: propagate it loudly.
///
/// `Ok(accepted)` collapses `Ok(true)` to `true` and both `Ok(false)` and
/// `Err(_)` to `false` — for the transcript-consumption property below, a
/// clean verifier error and a clean `false` are equally valid rejections.
fn verify_catching_panics(
    proof: HonkProof<ark_bn254::Fr>,
    public_inputs: &[ark_bn254::Fr],
    vk: &VerifyingKey<Bn254>,
    has_zk: ZeroKnowledge,
) -> Result<bool, String> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        UltraHonk::<_, Poseidon2Sponge>::verify(proof, public_inputs, vk, has_zk)
    })) {
        Ok(res) => Ok(matches!(res, Ok(true))),
        Err(payload) => Err(describe_panic_payload(&payload)),
    }
}

/// Transcript-consumption property, shared between the non-ZK (410-field) and
/// ZK (458-field) proof shapes: for a valid proof of byte-length L, (a) EVERY
/// truncation is rejected (cleanly, never panicking), (b) extensions carrying
/// trailing bytes are rejected, and (c) the exact-length proof verifies.
/// Generalizes `trailing_proof_data_rejected` into a loop over lengths, and
/// pins the verifier's read-exactly-L transcript discipline as a property
/// rather than a single case.
///
/// This operates at the BYTE level (`HonkProof::to_buffer` / `from_buffer`),
/// not just the in-memory `Vec<Fr>`, because that is the boundary a real
/// caller actually feeds (a proof file / wire buffer can be truncated or
/// extended at any byte, not just at a 32-byte field-element boundary).
///
/// Cost note: truncation is swept EXHAUSTIVELY over every byte length
/// `0..=total_bytes`, rather than the coarser "byte-exact for the last two
/// field elements, field-boundary-only elsewhere" sampling that would be
/// needed if this were expensive: a non-32-aligned length fails to
/// deserialize before ever reaching `verify` (a cheap length
/// check, no proving-system work), and only the `total_bytes / 32` aligned
/// lengths pay a `verify` call — the same number of `verify` calls as the
/// field-level sweep this replaces, plus ~31x that many near-free length
/// checks. Measured: full sweep (both shapes, truncation + extension) runs in
/// low single-digit seconds in `--release`. Extension is NOT exhaustive: the
/// "extra bytes present" check fires only after a complete, successful
/// verify, so every extension probe pays the full verify cost; we probe
/// densely at the smallest scale (every extra byte count from 1 up to two
/// field elements' worth, covering both sub-field-element and
/// cross-field-element trailing garbage) and sparsely at field-multiple scale
/// beyond that.
fn assert_transcript_consumption_property(has_zk: ZeroKnowledge) {
    let (proof, public_inputs, vk) = build_artifacts_with(has_zk);
    let buf = proof.to_buffer();
    let total_bytes = buf.len();
    let n = total_bytes / 32;
    assert_eq!(
        n * 32,
        total_bytes,
        "proof byte length must be a whole number of field elements"
    );

    // (c) Exact length verifies (property baseline). A panic here is fatal to
    // the whole test, since the tampering checks below are meaningless if the
    // baseline is broken.
    let ok = verify_catching_panics(
        HonkProof::<ark_bn254::Fr>::from_buffer(&buf).expect("untampered proof must deserialize"),
        &public_inputs,
        &vk,
        has_zk,
    )
    .unwrap_or_else(|panic_msg| {
        panic!("verify PANICKED on the untampered exact-length proof ({has_zk:?}): {panic_msg}")
    });
    assert!(ok, "exact-length proof must verify ({has_zk:?})");

    // (a) Every truncation, swept byte-by-byte, is rejected or fails to
    // deserialize — and never panics.
    let mut panicking_truncations = Vec::new();
    for len in 0..total_bytes {
        match HonkProof::<ark_bn254::Fr>::from_buffer(&buf[..len]) {
            // Non-field-aligned length: clean deserialization failure. Rejected.
            Err(_) => continue,
            Ok(parsed) => match verify_catching_panics(parsed, &public_inputs, &vk, has_zk) {
                Ok(accepted) => assert!(
                    !accepted,
                    "verifier ACCEPTED a proof truncated to {len}/{total_bytes} bytes ({has_zk:?})"
                ),
                Err(panic_msg) => panicking_truncations.push((len, panic_msg)),
            },
        }
    }
    assert!(
        panicking_truncations.is_empty(),
        "verify PANICKED on {} truncated byte length(s) ({has_zk:?}) — a malformed-input \
         panic is a robustness regression in its own right, distinct from (and worse than) \
         a clean rejection: {panicking_truncations:?}",
        panicking_truncations.len()
    );

    // (b) Extensions carrying trailing bytes are rejected: dense over the
    // smallest scale, sparse over field-multiple scale.
    let dense_extra_bytes = 1..=64usize;
    let sparse_extra_fields = [2usize, 7, 48, n];
    let extra_lens = dense_extra_bytes.chain(sparse_extra_fields.iter().map(|f| f * 32));
    let mut panicking_extensions = Vec::new();
    for extra in extra_lens {
        let mut extended = buf.clone();
        extended.extend(std::iter::repeat_n(0u8, extra));
        match HonkProof::<ark_bn254::Fr>::from_buffer(&extended) {
            // Non-field-aligned extension: clean deserialization failure. Rejected.
            Err(_) => continue,
            Ok(parsed) => match verify_catching_panics(parsed, &public_inputs, &vk, has_zk) {
                Ok(accepted) => assert!(
                    !accepted,
                    "verifier ACCEPTED a proof extended by {extra} trailing byte(s) ({has_zk:?})"
                ),
                Err(panic_msg) => panicking_extensions.push((extra, panic_msg)),
            },
        }
    }
    assert!(
        panicking_extensions.is_empty(),
        "verify PANICKED on {} extended byte length(s) ({has_zk:?}): {panicking_extensions:?}",
        panicking_extensions.len()
    );
}

/// Transcript-consumption property on the non-ZK (410-field) proof shape. See
/// `assert_transcript_consumption_property` for the full property and cost
/// notes.
#[test]
fn proof_length_property_exact_length_only() {
    assert_transcript_consumption_property(ZeroKnowledge::No);
}

/// Transcript-consumption property on the ZK (458-field) proof shape — same
/// property, applied to the SmallSubgroupIPA/Libra-carrying ZK proof body so
/// the sweep isn't blind to that region's transcript discipline.
#[test]
fn proof_length_property_exact_length_only_zk() {
    assert_transcript_consumption_property(ZeroKnowledge::Yes);
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
/// NOTE: this general binding check is complemented by
/// `zk_proof_ssipa_evaluation_tamper_rejected` below, which pins the four
/// transmitted SmallSubgroupIPA evaluation fields specifically (this test's
/// fractional probe positions do not land on the SSIPA eval region). See that
/// test for the SSIPA-specific enforcement discussion and the mutation matrix.
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

/// SmallSubgroupIPA (Libra) evaluation binding — the deferred §3a #8 negative.
///
/// The ZK prover emits four transmitted SmallSubgroupIPA evaluations in the
/// proof, in this transcript order at the tail of the decider proof:
///   G(r)  = "Libra:concatenation_eval"
///   A(g*r)= "Libra:shifted_grand_sum_eval"
///   A(r)  = "Libra:grand_sum_eval"
///   Q(r)  = "Libra:quotient_eval"
/// Together with the untransmitted, hard-coded boundary opening A(1) = 0 these
/// form the five SmallSubgroupIPA opening claims (NUM_SMALL_IPA_OPENING_CLAIMS)
/// batched through Shplonk/Shplemini. They occupy the four field elements just
/// before the two trailing commitments (Shplonk:Q = 4 frs, then KZG:W = 4 frs),
/// i.e. inner indices n-12 ..= n-9. This test tampers each one in turn and
/// asserts the ZK verifier rejects cleanly (Ok(false) or a clean Err), never a
/// panic.
///
/// What the verifier actually enforces here (empirically established while
/// writing this test, via a temporary two-point mutation of the verifier — the
/// verifier is unchanged in the committed tree):
///
///   * the final ZK verdict is `sumcheck.verified && pcs_verified &&
///     consistency_checked` — a three-way AND;
///   * each of the four evaluations is bound *twice, independently*: once by
///     the Shplemini/KZG batched opening (they feed the Shplonk constant-term
///     accumulator, so any change breaks the KZG pairing → `pcs_verified`
///     false), and once by `check_evaluations_consistency` (they must satisfy
///     the SmallSubgroupIPA identity at the Gemini challenge r → the returned
///     `consistency_checked` false).
///
/// Mutation matrix observed for each of the four fields (tamper = +1):
///   honest verifier                       -> Ok(false)   (rejected)
///   check_evaluations_consistency := true  -> Ok(false)   (KZG still catches it)
///   pairing_check := true                  -> Ok(false)   (consistency catches it)
///   BOTH neutralized                       -> Ok(true)    (accepted — RED)
///
/// So this is defense-in-depth: it is *stronger* than bb's own note that the
/// standalone SmallSubgroupIPA `check_consistency` accepts the homogeneous
/// kernel perturbation (delta_A(1)=delta, delta_A(g^j)=-delta/(g-1), delta_s=c).
/// That perturbation is a prover-side forgery: it rebuilds the [A]/[Q]
/// commitments and re-derives the whole Fiat-Shamir transcript so the identity
/// holds at r while A(1) != 0, leaving only the KZG boundary opening to reject
/// it. It cannot be reproduced by byte-tampering a finished proof, because the
/// transmitted evaluations are absorbed into the transcript *before* the Shplonk
/// challenges nu/z are drawn, so any byte edit desynchronizes every downstream
/// challenge. Reproducing it in-process would require the SmallSubgroupIPA
/// prover internals (they are `pub(crate)`), i.e. a production-code change,
/// which this test intentionally avoids. The byte-level negative here still
/// pins the property the deferral cared about: the verifier does not silently
/// accept altered SmallSubgroupIPA evaluations — the A(1)=0 / identity binding
/// is enforced on the verifier side.
#[test]
fn zk_proof_ssipa_evaluation_tamper_rejected() {
    let (proof, public_inputs, vk) = build_artifacts_with(ZeroKnowledge::Yes);
    let n = proof.inner_as_ref().len();

    // Layout at the tail of the ZK decider proof: [.. , 4 SSIPA evals, Shplonk:Q
    // (4 frs), KZG:W (4 frs)]. Locate the SSIPA evals relative to the end so the
    // test does not depend on the (public-input-dependent) absolute offset.
    const TRAILING_COMMITMENT_FRS: usize = 8; // Shplonk:Q (4) + KZG:W (4)
    let ssipa_eval_indices = [
        n - TRAILING_COMMITMENT_FRS - 4, // Libra:concatenation_eval   G(r)
        n - TRAILING_COMMITMENT_FRS - 3, // Libra:shifted_grand_sum_eval A(g*r)
        n - TRAILING_COMMITMENT_FRS - 2, // Libra:grand_sum_eval        A(r)
        n - TRAILING_COMMITMENT_FRS - 1, // Libra:quotient_eval         Q(r)
    ];
    let labels = [
        "Libra:concatenation_eval G(r)",
        "Libra:shifted_grand_sum_eval A(g*r)",
        "Libra:grand_sum_eval A(r)",
        "Libra:quotient_eval Q(r)",
    ];

    for (pos, label) in ssipa_eval_indices.into_iter().zip(labels) {
        let mut inner = proof.inner_as_ref().clone();
        inner[pos] += ark_bn254::Fr::from(1u64);
        let tampered = HonkProof::new(inner);

        // Must reject and must not panic. A malformed-input panic would itself
        // be a robustness regression (see the module doc and
        // `verify_catching_panics`).
        let accepted = verify_catching_panics(tampered, &public_inputs, &vk, ZeroKnowledge::Yes)
            .unwrap_or_else(|panic_msg| {
                panic!(
                    "ZK verify PANICKED on tampered SSIPA field {label} (idx {pos}/{n}): \
                     {panic_msg}"
                )
            });
        assert!(
            !accepted,
            "ZK verifier ACCEPTED a proof with SSIPA field {label} (idx {pos}/{n}) tampered"
        );
    }
}

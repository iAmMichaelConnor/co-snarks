use crate::co_decider::relations::CRAND_PAIRS_FACTOR;
use crate::co_oink::{
    CRAND_PAIRS_CONST, CRAND_PAIRS_FACTOR_DOMAIN_SIZE_MINUS_ONE, CRAND_PAIRS_FACTOR_N,
};
use crate::{
    CONST_PROOF_SIZE_LOG_N, co_decider::co_decider_prover::CoDecider,
    co_decider::types::ProverMemory, co_oink::co_oink_prover::CoOink,
};
use co_noir_common::constants::{MAX_PARTIAL_RELATION_LENGTH, TRACE_OFFSET};
use co_noir_common::keys::verification_key::VerifyingKeyBarretenberg;
use co_noir_common::polynomials::polynomial::NUM_MASKED_ROWS;
use co_noir_common::{
    constants::PAIRING_POINT_ACCUMULATOR_SIZE,
    crs::ProverCrs,
    honk_curve::HonkCurve,
    honk_proof::{HonkProofResult, TranscriptFieldType},
    keys::proving_key::ProvingKey,
    mpc::{
        NoirUltraHonkProver, plain::PlainUltraHonkDriver, rep3::Rep3UltraHonkDriver,
        shamir::ShamirUltraHonkDriver,
    },
    transcript::{Transcript, TranscriptHasher},
    types::ZeroKnowledge,
    zk_masking::SeededZkBlinding,
};
use mpc_core::protocols::{
    rep3::{Rep3State, conversion::A2BType},
    shamir::{ShamirPreprocessing, ShamirState},
};
use mpc_core::uint::FieldUint;
use mpc_net::Network;
use noir_types::HonkProof;
use std::marker::PhantomData;

pub type Rep3CoUltraHonk<P, H> = CoUltraHonk<Rep3UltraHonkDriver, P, H>;
pub type ShamirCoUltraHonk<P, H> = CoUltraHonk<ShamirUltraHonkDriver, P, H>;

pub struct CoUltraHonk<
    T: NoirUltraHonkProver<P>,
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
> {
    phantom_data: PhantomData<(P, H, T)>,
}

impl<
    T: NoirUltraHonkProver<C>,
    C: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
> CoUltraHonk<T, C, H>
{
    fn generate_gate_challenges(
        transcript: &mut Transcript<TranscriptFieldType, H>,
        virtual_log_n: usize,
    ) -> Vec<C::ScalarField> {
        tracing::trace!("generate gate challenges");

        transcript
            .get_powers_of_challenge::<C>("Sumcheck:gate_challenge".to_string(), virtual_log_n)
    }

    /// Inner proving flow. `zk_blinding` must be `None` in production: `Some` deterministically
    /// seeds the ZK masking values and exists ONLY for cross-driver determinism testing (a
    /// seeded proof is not zero-knowledge). See [`co_noir_common::zk_masking`].
    pub fn prove_inner<N: Network>(
        net: &N,
        state: &mut T::State,
        mut proving_key: ProvingKey<T, C>,
        crs: &ProverCrs<C>,
        has_zk: ZeroKnowledge,
        verifying_key: &VerifyingKeyBarretenberg<C>,
        zk_blinding: Option<&SeededZkBlinding>,
    ) -> HonkProofResult<HonkProof<H::DataType>> {
        proving_key
            .proof_privacy
            .validate_proving_mode(has_zk, zk_blinding.is_some())?;
        tracing::trace!("CoUltraHonk prove");

        let mut transcript = Transcript::<TranscriptFieldType, H>::new();

        let phase_start = std::time::Instant::now();
        let oink = CoOink::new(net, state, has_zk, zk_blinding);
        let oink_result = oink.prove(&mut proving_key, &mut transcript, crs, verifying_key)?;
        crate::phase_timing("oink", phase_start);

        let circuit_size = proving_key.circuit_size;
        let log_dyadic_circuit_size = proving_key.circuit_size.next_power_of_two().ilog2() as usize;
        let virtual_log_n = if H::USE_PADDING {
            CONST_PROOF_SIZE_LOG_N
        } else {
            log_dyadic_circuit_size
        };

        let phase_start = std::time::Instant::now();
        let mut memory =
            ProverMemory::from_memory_and_polynomials(oink_result, proving_key.polynomials);
        memory.gate_challenges = Self::generate_gate_challenges(&mut transcript, virtual_log_n);
        crate::phase_timing("memory_handoff", phase_start);

        let phase_start = std::time::Instant::now();
        let decider = CoDecider::new(net, state, memory, has_zk, zk_blinding);
        let proof = decider.prove(circuit_size, crs, transcript, virtual_log_n);
        crate::phase_timing("decider_total", phase_start);
        proof
    }
}

impl<C: HonkCurve<TranscriptFieldType>, H: TranscriptHasher<TranscriptFieldType>>
    Rep3CoUltraHonk<C, H>
where
    C::ScalarField: FieldUint,
    C::BaseField: FieldUint<Uint = <C::ScalarField as FieldUint>::Uint>,
{
    #[expect(clippy::type_complexity)]
    pub fn prove<N: Network>(
        net: &N,
        proving_key: ProvingKey<Rep3UltraHonkDriver, C>,
        crs: &ProverCrs<C>,
        has_zk: ZeroKnowledge,
        verifying_key: &VerifyingKeyBarretenberg<C>,
    ) -> eyre::Result<(HonkProof<H::DataType>, Vec<H::DataType>)> {
        proving_key
            .proof_privacy
            .validate_proving_mode(has_zk, false)?;
        let mut state = Rep3State::new(net, A2BType::default())?;
        let num_public_inputs = proving_key.num_public_inputs - PAIRING_POINT_ACCUMULATOR_SIZE;
        let proof = Self::prove_inner(
            net,
            &mut state,
            proving_key,
            crs,
            has_zk,
            verifying_key,
            None,
        )?;
        let (proof, public_inputs) =
            proof.separate_proof_and_public_inputs(num_public_inputs as usize);
        Ok((proof, public_inputs))
    }

    /// Like [`Self::prove`], but with the ZK masking values drawn deterministically from
    /// `zk_blinding`.
    ///
    /// TESTING ONLY: this exists so tests can prove cross-driver determinism (same witness +
    /// same injected blinding randomness => byte-identical proofs across drivers). Seeding
    /// the blinding makes the masking predictable, i.e. the proof is NOT zero-knowledge.
    /// It must never be used in production and is deliberately not reachable from the
    /// co-noir CLI.
    #[expect(clippy::type_complexity)]
    pub fn prove_with_seeded_zk_blinding<N: Network>(
        net: &N,
        proving_key: ProvingKey<Rep3UltraHonkDriver, C>,
        crs: &ProverCrs<C>,
        has_zk: ZeroKnowledge,
        verifying_key: &VerifyingKeyBarretenberg<C>,
        zk_blinding: &SeededZkBlinding,
    ) -> eyre::Result<(HonkProof<H::DataType>, Vec<H::DataType>)> {
        proving_key
            .proof_privacy
            .validate_proving_mode(has_zk, true)?;
        let mut state = Rep3State::new(net, A2BType::default())?;
        let num_public_inputs = proving_key.num_public_inputs - PAIRING_POINT_ACCUMULATOR_SIZE;
        let proof = Self::prove_inner(
            net,
            &mut state,
            proving_key,
            crs,
            has_zk,
            verifying_key,
            Some(zk_blinding),
        )?;
        let (proof, public_inputs) =
            proof.separate_proof_and_public_inputs(num_public_inputs as usize);
        Ok((proof, public_inputs))
    }
}

impl<C: HonkCurve<TranscriptFieldType>, H: TranscriptHasher<TranscriptFieldType>>
    ShamirCoUltraHonk<C, H>
{
    #[expect(clippy::type_complexity)]
    pub fn prove<N: Network>(
        net: &N,
        num_parties: usize,
        threshold: usize,
        proving_key: ProvingKey<ShamirUltraHonkDriver, C>,
        crs: &ProverCrs<C>,
        has_zk: ZeroKnowledge,
        verifying_key: &VerifyingKeyBarretenberg<C>,
    ) -> eyre::Result<(HonkProof<H::DataType>, Vec<H::DataType>)> {
        proving_key
            .proof_privacy
            .validate_proving_mode(has_zk, false)?;
        // init MPC protocol
        let virtual_log_n = if H::USE_PADDING {
            CONST_PROOF_SIZE_LOG_N
        } else {
            proving_key.circuit_size.next_power_of_two().ilog2() as usize
        };
        let num_pairs = if num_parties == 3 {
            0 // Precomputation is done on the fly since it requires no communication
        } else {
            ultrahonk_num_randomness(&proving_key, has_zk, virtual_log_n)
        };
        let preprocessing = ShamirPreprocessing::new(num_parties, threshold, num_pairs, net)?;
        let mut state = ShamirState::from(preprocessing);
        let num_public_inputs = proving_key.num_public_inputs - PAIRING_POINT_ACCUMULATOR_SIZE;
        let proof = Self::prove_inner(
            net,
            &mut state,
            proving_key,
            crs,
            has_zk,
            verifying_key,
            None,
        )?;
        let (proof, public_inputs) =
            proof.separate_proof_and_public_inputs(num_public_inputs as usize);
        Ok((proof, public_inputs))
    }
}

impl<C: HonkCurve<TranscriptFieldType>, H: TranscriptHasher<TranscriptFieldType>>
    CoUltraHonk<PlainUltraHonkDriver, C, H>
{
    #[expect(clippy::type_complexity)]
    pub fn prove(
        proving_key: ProvingKey<PlainUltraHonkDriver, C>,
        crs: &ProverCrs<C>,
        has_zk: ZeroKnowledge,
        verifying_key: &VerifyingKeyBarretenberg<C>,
    ) -> eyre::Result<(HonkProof<H::DataType>, Vec<H::DataType>)> {
        proving_key
            .proof_privacy
            .validate_proving_mode(has_zk, false)?;
        let num_public_inputs = proving_key.num_public_inputs - PAIRING_POINT_ACCUMULATOR_SIZE;
        let proof = Self::prove_inner(
            &(),
            &mut Default::default(),
            proving_key,
            crs,
            has_zk,
            verifying_key,
            None,
        )?;
        Ok(proof.separate_proof_and_public_inputs(num_public_inputs as usize))
    }

    /// Like [`Self::prove`], but with the ZK masking values drawn deterministically from
    /// `zk_blinding`.
    ///
    /// TESTING ONLY: this exists so tests can prove cross-driver determinism (same witness +
    /// same injected blinding randomness => byte-identical proofs across drivers). Seeding
    /// the blinding makes the masking predictable, i.e. the proof is NOT zero-knowledge.
    /// It must never be used in production and is deliberately not reachable from the
    /// co-noir CLI.
    #[expect(clippy::type_complexity)]
    pub fn prove_with_seeded_zk_blinding(
        proving_key: ProvingKey<PlainUltraHonkDriver, C>,
        crs: &ProverCrs<C>,
        has_zk: ZeroKnowledge,
        verifying_key: &VerifyingKeyBarretenberg<C>,
        zk_blinding: &SeededZkBlinding,
    ) -> eyre::Result<(HonkProof<H::DataType>, Vec<H::DataType>)> {
        proving_key
            .proof_privacy
            .validate_proving_mode(has_zk, true)?;
        let num_public_inputs = proving_key.num_public_inputs - PAIRING_POINT_ACCUMULATOR_SIZE;
        let proof = Self::prove_inner(
            &(),
            &mut Default::default(),
            proving_key,
            crs,
            has_zk,
            verifying_key,
            Some(zk_blinding),
        )?;
        Ok(proof.separate_proof_and_public_inputs(num_public_inputs as usize))
    }
}

fn ultrahonk_num_randomness<C, T>(
    proving_key: &ProvingKey<T, C>,
    has_zk: ZeroKnowledge,
    virtual_log_n: usize,
) -> usize
where
    C: HonkCurve<TranscriptFieldType>,
    T: NoirUltraHonkProver<C>,
{
    // TODO because a lot is skipped in sumcheck prove, we generate a lot more than we really need
    // The grand product is computed over the contiguous rows [TRACE_OFFSET, final_active_wire_idx),
    // i.e. final_active_wire_idx - TRACE_OFFSET rows.
    let grand_product_num_rows = proving_key.final_active_wire_idx - TRACE_OFFSET;

    let n = proving_key.circuit_size as usize;
    // Each ROM denominator inversion draws one fresh Shamir random pair.
    let num_pairs_oink_prove = proving_key.rom_logup_records.len()
        + CRAND_PAIRS_FACTOR_N * n
        + CRAND_PAIRS_FACTOR_DOMAIN_SIZE_MINUS_ONE * grand_product_num_rows
        + CRAND_PAIRS_CONST;
    // log2(n) * ((n >>= 1) / 2) == n - 1
    let num_pairs_sumcheck_prove = CRAND_PAIRS_FACTOR * MAX_PARTIAL_RELATION_LENGTH * (n - 1);

    let num_pairs_sumcheck_disabled_contributions = if has_zk == ZeroKnowledge::No {
        0
    } else {
        // compute_disabled_contribution: 2 edges in round 0, then 1 edge in each of the remaining
        // log2(n) - 1 real rounds => log2(n) + 1 edges in total
        (n.ilog(2) as usize + 1) * CRAND_PAIRS_FACTOR * MAX_PARTIAL_RELATION_LENGTH
    };

    // For ZK, each virtual round (virtual_log_n - log2(n) of them) computes an honest round
    // univariate: one relation evaluation at a single edge.
    let num_pairs_sumcheck_virtual_rounds = if has_zk == ZeroKnowledge::No {
        0
    } else {
        (virtual_log_n - n.ilog2() as usize) * CRAND_PAIRS_FACTOR * MAX_PARTIAL_RELATION_LENGTH
    };

    let num_zk_randomness = if has_zk == ZeroKnowledge::No {
        0
    } else {
        co_noir_common::zk_masking::gemini_masking_support(n).len() // Gemini mask draws
        + 8 * NUM_MASKED_ROWS as usize // mask_polynomial: w_l/w_r/w_o, read_counts/read_tags/w_4, lookup_inverses/z_perm
        + 1 // ZKSumcheckData constant_term
        + virtual_log_n * C::LIBRA_UNIVARIATES_LENGTH // generate_libra_univariates (all virtual rounds)
        + 2 // compute_concatenated_libra_polynomial masking
        + 3 // compute_grand_sum_polynomial masking
    };
    num_pairs_oink_prove
        + num_pairs_sumcheck_prove
        + num_pairs_sumcheck_disabled_contributions
        + num_pairs_sumcheck_virtual_rounds
        + num_zk_randomness
}

#[cfg(test)]
#[path = "proof_privacy_tests.rs"]
mod proof_privacy_tests;

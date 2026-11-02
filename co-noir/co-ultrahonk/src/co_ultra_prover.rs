use crate::co_decider::relations::CRAND_PAIRS_FACTOR;
use crate::co_oink::{
    CRAND_PAIRS_CONST, CRAND_PAIRS_FACTOR_DOMAIN_SIZE_MINUS_ONE, CRAND_PAIRS_FACTOR_N,
};
use crate::zk_masking::ZkMasking;
use crate::{
    CONST_PROOF_SIZE_LOG_N, co_decider::co_decider_prover::CoDecider,
    co_decider::types::ProverMemory, co_oink::co_oink_prover::CoOink,
};
use co_noir_common::constants::MAX_PARTIAL_RELATION_LENGTH;
use co_noir_common::keys::verification_key::VerifyingKeyBarretenberg;
use co_noir_common::polynomials::polynomial::gemini_masking_support;
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

    pub fn prove_inner<N: Network>(
        net: &N,
        state: &mut T::State,
        proving_key: ProvingKey<T, C>,
        crs: &ProverCrs<C>,
        has_zk: ZeroKnowledge,
        verifying_key: &VerifyingKeyBarretenberg<C>,
    ) -> HonkProofResult<HonkProof<H::DataType>> {
        Self::prove_with_masking(
            net,
            state,
            proving_key,
            crs,
            has_zk,
            verifying_key,
            ZkMasking::Random,
        )
    }

    fn prove_with_masking<N: Network>(
        net: &N,
        state: &mut T::State,
        mut proving_key: ProvingKey<T, C>,
        crs: &ProverCrs<C>,
        has_zk: ZeroKnowledge,
        verifying_key: &VerifyingKeyBarretenberg<C>,
        masking: ZkMasking,
    ) -> HonkProofResult<HonkProof<H::DataType>> {
        proving_key
            .proof_privacy
            .validate_proving_mode(has_zk, matches!(masking, ZkMasking::Seeded(_)))?;
        tracing::trace!("CoUltraHonk prove");

        let mut transcript = Transcript::<TranscriptFieldType, H>::new();

        let oink = CoOink::new(net, state, has_zk, masking.clone());
        let oink_result = oink.prove(&mut proving_key, &mut transcript, crs, verifying_key)?;

        let circuit_size = proving_key.circuit_size;
        let log_dyadic_circuit_size = proving_key.circuit_size.next_power_of_two().ilog2() as usize;
        let virtual_log_n = if H::USE_PADDING {
            CONST_PROOF_SIZE_LOG_N
        } else {
            log_dyadic_circuit_size
        };

        let mut memory =
            ProverMemory::from_memory_and_polynomials(oink_result, proving_key.polynomials);
        memory.gate_challenges = Self::generate_gate_challenges(&mut transcript, virtual_log_n);

        let decider = CoDecider::new(net, state, memory, has_zk, masking);
        decider.prove(circuit_size, crs, transcript, virtual_log_n)
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
        let mut state = Rep3State::new(net, A2BType::default())?;
        let num_public_inputs = proving_key.num_public_inputs - PAIRING_POINT_ACCUMULATOR_SIZE;
        let proof = Self::prove_inner(net, &mut state, proving_key, crs, has_zk, verifying_key)?;
        let (proof, public_inputs) =
            proof.separate_proof_and_public_inputs(num_public_inputs as usize);
        Ok((proof, public_inputs))
    }

    /// Like [`Self::prove`] with ZK, but the masking values are derived from `seed`, so the proof
    /// is a deterministic function of the witness and `seed`. **The proof is not
    /// zero-knowledge.** For tests only, e.g. to compare proofs of different MPC protocols.
    #[cfg(any(test, feature = "test-utils"))]
    #[expect(clippy::type_complexity)]
    pub fn prove_with_seeded_zk_masking<N: Network>(
        net: &N,
        proving_key: ProvingKey<Rep3UltraHonkDriver, C>,
        crs: &ProverCrs<C>,
        verifying_key: &VerifyingKeyBarretenberg<C>,
        seed: [u8; 32],
    ) -> eyre::Result<(HonkProof<H::DataType>, Vec<H::DataType>)> {
        let mut state = Rep3State::new(net, A2BType::default())?;
        let num_public_inputs = proving_key.num_public_inputs - PAIRING_POINT_ACCUMULATOR_SIZE;
        let proof = Self::prove_with_masking(
            net,
            &mut state,
            proving_key,
            crs,
            ZeroKnowledge::Yes,
            verifying_key,
            ZkMasking::Seeded(seed),
        )?;
        Ok(proof.separate_proof_and_public_inputs(num_public_inputs as usize))
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
        // init MPC protocol
        let num_pairs = if num_parties == 3 {
            0 // Precomputation is done on the fly since it requires no communication
        } else {
            ultrahonk_num_randomness(&proving_key, has_zk)
        };
        let preprocessing = ShamirPreprocessing::new(num_parties, threshold, num_pairs, net)?;
        let mut state = ShamirState::from(preprocessing);
        let num_public_inputs = proving_key.num_public_inputs - PAIRING_POINT_ACCUMULATOR_SIZE;
        let proof = Self::prove_inner(net, &mut state, proving_key, crs, has_zk, verifying_key)?;
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
        let num_public_inputs = proving_key.num_public_inputs - PAIRING_POINT_ACCUMULATOR_SIZE;
        let proof = Self::prove_inner(
            &(),
            &mut Default::default(),
            proving_key,
            crs,
            has_zk,
            verifying_key,
        )?;
        Ok(proof.separate_proof_and_public_inputs(num_public_inputs as usize))
    }

    /// Like [`Self::prove`] with ZK, but the masking values are derived from `seed`, so the proof
    /// is a deterministic function of the witness and `seed`. **The proof is not
    /// zero-knowledge.** For tests only, e.g. to compare proofs of different MPC protocols.
    #[cfg(any(test, feature = "test-utils"))]
    #[expect(clippy::type_complexity)]
    pub fn prove_with_seeded_zk_masking(
        proving_key: ProvingKey<PlainUltraHonkDriver, C>,
        crs: &ProverCrs<C>,
        verifying_key: &VerifyingKeyBarretenberg<C>,
        seed: [u8; 32],
    ) -> eyre::Result<(HonkProof<H::DataType>, Vec<H::DataType>)> {
        let num_public_inputs = proving_key.num_public_inputs - PAIRING_POINT_ACCUMULATOR_SIZE;
        let proof = Self::prove_with_masking(
            &(),
            &mut Default::default(),
            proving_key,
            crs,
            ZeroKnowledge::Yes,
            verifying_key,
            ZkMasking::Seeded(seed),
        )?;
        Ok(proof.separate_proof_and_public_inputs(num_public_inputs as usize))
    }
}

fn ultrahonk_num_randomness<C, T>(proving_key: &ProvingKey<T, C>, has_zk: ZeroKnowledge) -> usize
where
    C: HonkCurve<TranscriptFieldType>,
    T: NoirUltraHonkProver<C>,
{
    // TODO because a lot is skipped in sumcheck prove, we generate a lot more than we really need
    let active_domain_size_mul = if proving_key.active_region_data.size() > 0 {
        proving_key.active_region_data.size() - 1
    } else {
        proving_key.final_active_wire_idx
    };

    let n = proving_key.circuit_size as usize;
    let num_pairs_oink_prove = CRAND_PAIRS_FACTOR_N * n
        + CRAND_PAIRS_FACTOR_DOMAIN_SIZE_MINUS_ONE * active_domain_size_mul
        + CRAND_PAIRS_CONST;
    // log2(n) * ((n >>= 1) / 2) == n - 1
    let num_pairs_sumcheck_prove = CRAND_PAIRS_FACTOR * MAX_PARTIAL_RELATION_LENGTH * (n - 1);

    let num_pairs_sumcheck_disabled_contributions = if has_zk == ZeroKnowledge::No {
        0
    } else {
        // compute_disabled_contribution: log2(n) rounds, each once relation, plus additional in round 0
        (n.ilog(2) as usize + 1) * CRAND_PAIRS_FACTOR * MAX_PARTIAL_RELATION_LENGTH
    };

    let num_zk_randomness = if has_zk == ZeroKnowledge::No {
        0
    } else {
        gemini_masking_support(n).len() // commit_to_masking_poly
        + 1 // ZKData::new
        + n.ilog2() as usize * C::LIBRA_UNIVARIATES_LENGTH // generate_libra_univariates
        + 2 // compute_concatenated_libra_polynomial
        + 3 // compute_grand_sum_polynomial
    };
    num_pairs_oink_prove
        + num_pairs_sumcheck_prove
        + num_pairs_sumcheck_disabled_contributions
        + num_zk_randomness
}

#[cfg(test)]
mod tests {
    use super::*;
    use co_noir_common::{
        keys::proof_privacy::ProofPrivacy, transcript::Poseidon2Sponge, types::Bn254G1,
    };

    type Prover = CoUltraHonk<PlainUltraHonkDriver, Bn254G1, Poseidon2Sponge>;

    /// Keys of the private recursion profile are rejected without ZK and with seeded masking,
    /// before anything is proven.
    #[test]
    fn private_recursion_keys_need_fresh_zero_knowledge() {
        let key = || ProvingKey::<PlainUltraHonkDriver, Bn254G1> {
            proof_privacy: ProofPrivacy::PrivateRecursion,
            num_public_inputs: PAIRING_POINT_ACCUMULATOR_SIZE,
            ..Default::default()
        };
        let vk = VerifyingKeyBarretenberg {
            log_circuit_size: 0,
            num_public_inputs: 0,
            pub_inputs_offset: 0,
            commitments: Default::default(),
        };
        let crs = ProverCrs::default();
        for error in [
            Prover::prove(key(), &crs, ZeroKnowledge::No, &vk).unwrap_err(),
            Prover::prove_with_seeded_zk_masking(key(), &crs, &vk, [7; 32]).unwrap_err(),
        ] {
            assert!(
                error
                    .to_string()
                    .contains("requires a zero-knowledge proof")
            );
        }
    }
}

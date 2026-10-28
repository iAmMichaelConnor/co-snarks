use std::array;

use co_acvm::mpc::NoirWitnessExtensionProtocol;

use ark_ff::AdditiveGroup;
use co_noir_common::constants::{
    BATCHED_RELATION_PARTIAL_LENGTH, BATCHED_RELATION_PARTIAL_LENGTH_ZK, NUM_LIBRA_COMMITMENTS,
    PAIRING_POINT_ACCUMULATOR_SIZE, ULTRA_PROOF_LENGTH_WITHOUT_PUB_INPUTS,
    ULTRA_PROOF_LENGTH_WITHOUT_PUB_INPUTS_ZK,
};
use co_noir_common::types::ZeroKnowledge;
use co_noir_common::{constants::CONST_PROOF_SIZE_LOG_N, honk_curve::HonkCurve};

use crate::honk_verifier::verifier_relations::NUM_SUBRELATIONS;
use crate::types::types::PairingPoints;
use crate::{
    honk_verifier::{
        claim_batcher::{Batch, ClaimBatcher},
        kzg::KZG,
        oink_recursive_verifier::OinkRecursiveVerifier,
        recursive_decider_verification_key::RecursiveDeciderVerificationKey,
        shplemini::ShpleminiVerifier,
        sumcheck::SumcheckVerifier,
    },
    prelude::GenericUltraCircuitBuilder,
    transcript_ct::{TranscriptCT, TranscriptFieldType, TranscriptHasherCT},
    types::{big_group::BigGroup, field_ct::FieldCT},
};

pub(crate) struct UltraRecursiveVerifier;

impl UltraRecursiveVerifier {
    // Like v6 BB, derive shape from the actual proof, never from a VK witness.
    fn public_input_count(proof_len: usize, has_zk: ZeroKnowledge) -> eyre::Result<usize> {
        let fixed_len = if has_zk == ZeroKnowledge::Yes {
            ULTRA_PROOF_LENGTH_WITHOUT_PUB_INPUTS_ZK
        } else {
            ULTRA_PROOF_LENGTH_WITHOUT_PUB_INPUTS
        };
        proof_len
            .checked_sub(fixed_len)
            .filter(|count| *count >= PAIRING_POINT_ACCUMULATOR_SIZE as usize)
            .ok_or_else(|| co_noir_common::honk_proof::HonkProofError::InvalidProofLength.into())
    }
    pub fn verify_proof<
        C: HonkCurve<TranscriptFieldType>,
        H: TranscriptHasherCT<C>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
    >(
        proof: Vec<FieldCT<C::ScalarField>>,
        mut key: RecursiveDeciderVerificationKey<C, T>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
        has_zk: ZeroKnowledge,
    ) -> eyre::Result<PairingPoints<C, T>> {
        let num_public_inputs = Self::public_input_count(proof.len(), has_zk)?;
        if num_public_inputs != key.public_inputs.len() + PAIRING_POINT_ACCUMULATOR_SIZE as usize {
            return Err(co_noir_common::honk_proof::HonkProofError::InvalidProofLength.into());
        }
        let mut transcript = TranscriptCT::<C, H>::new_verifier(proof);

        // No IPA accumulator on the UltraRecursiveFlavor

        let stage_start = std::time::Instant::now();
        OinkRecursiveVerifier::verify(
            &mut key,
            &mut transcript,
            builder,
            has_zk,
            num_public_inputs,
            driver,
        )?;
        crate::phase_timing("recursion/oink", stage_start);
        let stage_start = std::time::Instant::now();

        // Execute Sumcheck Verifier and extract multivariate opening point u = (u_0, ..., u_{d-1}) and purported
        // multivariate evaluations at u
        key.gate_challenges = transcript.get_powers_of_challenge(
            "Sumcheck:gate_challenge".to_string(),
            CONST_PROOF_SIZE_LOG_N,
            builder,
            driver,
        )?;

        // Receive commitments to Libra masking polynomials
        let mut libra_commitments: [BigGroup<C::ScalarField, T>; NUM_LIBRA_COMMITMENTS] =
            array::from_fn(|_| BigGroup::<C::ScalarField, T>::default());

        for i in 1..(NUM_SUBRELATIONS - 1) {
            let next_alpha = key.alphas[i - 1].multiply(&key.alphas[0], builder, driver)?;
            key.alphas[i] = next_alpha;
        }

        if has_zk == ZeroKnowledge::Yes {
            libra_commitments[0] = transcript.receive_point_from_prover(
                "Libra:concatenation_commitment".to_owned(),
                builder,
                driver,
            )?;
        }

        let sumcheck_output = if has_zk == ZeroKnowledge::Yes {
            SumcheckVerifier::verify::<
                BATCHED_RELATION_PARTIAL_LENGTH_ZK,
                CONST_PROOF_SIZE_LOG_N,
                C,
                T,
                H,
            >(
                &mut transcript,
                &mut key.target_sum,
                &key.relation_parameters,
                &key.alphas,
                &key.gate_challenges,
                CONST_PROOF_SIZE_LOG_N,
                builder,
                has_zk,
                driver,
            )?
        } else {
            SumcheckVerifier::verify::<
                BATCHED_RELATION_PARTIAL_LENGTH,
                CONST_PROOF_SIZE_LOG_N,
                C,
                T,
                H,
            >(
                &mut transcript,
                &mut key.target_sum,
                &key.relation_parameters,
                &key.alphas,
                &key.gate_challenges,
                CONST_PROOF_SIZE_LOG_N,
                builder,
                has_zk,
                driver,
            )?
        };

        if has_zk == ZeroKnowledge::Yes {
            libra_commitments[1] = transcript.receive_point_from_prover(
                "Libra:grand_sum_commitment".to_owned(),
                builder,
                driver,
            )?;
            libra_commitments[2] = transcript.receive_point_from_prover(
                "Libra:quotient_commitment".to_owned(),
                builder,
                driver,
            )?;
        }

        crate::phase_timing("recursion/sumcheck", stage_start);
        let stage_start = std::time::Instant::now();

        // Execute Shplemini to produce a batch opening claim subsequently verified by a univariate PCS
        let mut consistency_checked = true;
        let mut unshifted_commitments = Vec::with_capacity(
            key.vk_and_hash.vk.precomputed_commitments.elements.len()
                + key.witness_commitments.elements.len(),
        );
        let mut unshifted_scalars = Vec::with_capacity(
            sumcheck_output
                .claimed_evaluations
                .precomputed
                .elements
                .len()
                + sumcheck_output.claimed_evaluations.witness.elements.len(),
        );
        unshifted_commitments
            .extend_from_slice(&key.vk_and_hash.vk.precomputed_commitments.elements);
        unshifted_commitments.extend_from_slice(&key.witness_commitments.elements);
        unshifted_scalars
            .extend_from_slice(&sumcheck_output.claimed_evaluations.precomputed.elements);
        unshifted_scalars.extend_from_slice(&sumcheck_output.claimed_evaluations.witness.elements);

        let to_be_shifted_commitments = key.witness_commitments.to_be_shifted().to_vec();
        let shifted_scalars = sumcheck_output
            .claimed_evaluations
            .shifted_witness
            .elements
            .to_vec();

        let mut claim_batcher = ClaimBatcher {
            unshifted: Batch {
                commitments: unshifted_commitments,
                evaluations: unshifted_scalars,
                scalar: FieldCT::from(C::ScalarField::ZERO),
            },
            shifted: Batch {
                commitments: to_be_shifted_commitments,
                evaluations: shifted_scalars,
                scalar: FieldCT::from(C::ScalarField::ZERO),
            },
        };
        let libra_commitments = if has_zk == ZeroKnowledge::Yes {
            Some(&libra_commitments)
        } else {
            None
        };

        let mut opening_claim = ShpleminiVerifier::compute_batch_opening_claim(
            &mut claim_batcher,
            &sumcheck_output.challenges,
            &BigGroup::one(),
            &mut transcript,
            &mut consistency_checked,
            libra_commitments,
            sumcheck_output.claimed_libra_evaluation.as_ref(),
            key.gemini_masking_commitment.as_ref(),
            sumcheck_output.claimed_gemini_masking_evaluation.as_ref(),
            builder,
            driver,
        )?;

        crate::phase_timing("recursion/shplemini", stage_start);
        let stage_start = std::time::Instant::now();
        let pairing_points = KZG::reduce_verify_batch_opening_claim(
            &mut opening_claim,
            &mut transcript,
            builder,
            driver,
        )?;

        crate::phase_timing("recursion/kzg", stage_start);
        let stage_start = std::time::Instant::now();
        let mut inputs =
            PairingPoints::reconstruct_from_public(&key.public_inputs, builder, driver)?;

        inputs.aggregate::<H>(pairing_points, builder, driver)?;
        crate::phase_timing("recursion/aggregate", stage_start);

        Ok(inputs)
    }
}

#[cfg(test)]
mod proof_length_tests {
    use super::*;
    #[test]
    fn recursive_proof_length_reserves_accumulator_inputs() {
        for (zk, base) in [
            (ZeroKnowledge::No, ULTRA_PROOF_LENGTH_WITHOUT_PUB_INPUTS),
            (ZeroKnowledge::Yes, ULTRA_PROOF_LENGTH_WITHOUT_PUB_INPUTS_ZK),
        ] {
            for length in [
                0,
                base - 1,
                base,
                base + PAIRING_POINT_ACCUMULATOR_SIZE as usize - 1,
            ] {
                assert!(UltraRecursiveVerifier::public_input_count(length, zk).is_err());
            }
            for application_inputs in [0, 1, 20] {
                let total = application_inputs + PAIRING_POINT_ACCUMULATOR_SIZE as usize;
                assert_eq!(
                    UltraRecursiveVerifier::public_input_count(base + total, zk).unwrap(),
                    total
                );
            }
        }
    }
}

use crate::honk_verifier::verifier_relations::AllRelationsEvals;
use crate::honk_verifier::verifier_relations::NUM_SUBRELATIONS;
use crate::honk_verifier::verifier_relations::compute_full_relation_purported_value;
use crate::prelude::GenericUltraCircuitBuilder;
use crate::transcript_ct::TranscriptCT;
use crate::transcript_ct::TranscriptHasherCT;
use crate::types::field_ct::FieldCT;
use crate::types::gate_separator::GateSeparatorPolynomial;
use ark_ff::Field;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_noir_common::constants::NUM_ALL_ENTITIES;
use co_noir_common::polynomials::entities::AllEntities;
use co_noir_common::polynomials::entities::PRECOMPUTED_ENTITIES_SIZE;
use co_noir_common::types::RelationParameters;
use co_noir_common::types::ZeroKnowledge;
use co_noir_common::{
    honk_curve::HonkCurve,
    honk_proof::{HonkProofResult, TranscriptFieldType},
};

pub struct SumcheckOutput<C: HonkCurve<TranscriptFieldType>> {
    pub(crate) challenges: Vec<FieldCT<C::ScalarField>>,
    pub(crate) claimed_evaluations: AllEntities<FieldCT<C::ScalarField>, FieldCT<C::ScalarField>>,
    pub(crate) claimed_libra_evaluation: Option<FieldCT<C::ScalarField>>,
    pub(crate) claimed_gemini_masking_evaluation: Option<FieldCT<C::ScalarField>>,
}

pub struct SumcheckVerifier;

impl SumcheckVerifier {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn verify<
        const SIZE: usize,
        const VIRTUAL_LOG_N: usize,
        C: HonkCurve<TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
        H: TranscriptHasherCT<C>,
    >(
        transcript: &mut TranscriptCT<C, H>,
        target_sum: &mut FieldCT<C::ScalarField>,
        relation_parameters: &RelationParameters<FieldCT<C::ScalarField>>,
        alphas: &[FieldCT<C::ScalarField>; NUM_SUBRELATIONS - 1],
        gate_challenges: &[FieldCT<C::ScalarField>],
        virtual_log_n: usize,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        has_zk: ZeroKnowledge,
        driver: &mut T,
    ) -> HonkProofResult<SumcheckOutput<C>> {
        let is_zk = has_zk == ZeroKnowledge::Yes;

        let mut gate_separators =
            GateSeparatorPolynomial::new_without_products(gate_challenges.to_vec());

        let libra_challenge = if is_zk {
            // If running zero-knowledge sumcheck the target total sum is corrected by the claimed sum of libra masking
            // multivariate over the hypercube
            let libra_total_sum = transcript.receive_fr_from_prover("Libra:Sum".to_owned())?;
            let libra_challenge =
                transcript.get_challenge("Libra:Challenge".to_string(), builder, driver)?;
            *target_sum = libra_total_sum.multiply(&libra_challenge, builder, driver)?;
            Some(libra_challenge)
        } else {
            None
        };

        // MegaRecursiveFlavor does not have ZK
        // All (virtual) sumcheck rounds are processed uniformly: the prover computes honest round
        // univariates for the virtual rounds, so no padding indicator is needed.
        let mut multivariate_challenge = Vec::with_capacity(virtual_log_n);
        for round_idx in 0..virtual_log_n {
            let round_univariate = transcript
                .receive_n_from_prover(format!("Sumcheck:univariate_{round_idx}"), SIZE)?;

            let round_challenge =
                transcript.get_challenge(format!("Sumcheck:u_{round_idx}"), builder, driver)?;

            multivariate_challenge.push(round_challenge.clone());

            SumcheckVerifier::check_sum(&round_univariate, target_sum, builder, driver)?;

            // Update the target sum for the next round
            *target_sum = FieldCT::evaluate_with_domain_start::<{ SIZE }, _, _>(
                &round_univariate.try_into().unwrap(),
                &round_challenge,
                0,
                builder,
                driver,
            )?;

            // Partially evaluate the gate separator polynomial
            gate_separators.partially_evaluate(&round_challenge, builder, driver)?;
        }
        // Extract claimed evaluations of Libra univariates and compute their sum multiplied by the Libra challenge
        // Final round
        let eval_offset = usize::from(is_zk);
        let transcript_evaluations = transcript.receive_n_from_prover(
            "Sumcheck:evaluations".to_owned(),
            NUM_ALL_ENTITIES + eval_offset,
        )?;
        let claimed_gemini_masking_evaluation = is_zk.then(|| transcript_evaluations[0].clone());

        let (precomputed, witness) =
            transcript_evaluations[eval_offset..].split_at(PRECOMPUTED_ENTITIES_SIZE);
        let claimed_evaluations =
            AllEntities::from_elements(witness.to_vec(), precomputed.to_vec());

        // Evaluate the Honk relation at the point (u_0, ..., u_{d-1}) using claimed evaluations of prover polynomials.
        // For ZK Flavors, the row-disabling factor is applied inside, per subrelation (bb's
        // emission order), and the evaluation is then corrected by full_libra_purported_value.
        let mut full_honk_purported_value = compute_full_relation_purported_value(
            &claimed_evaluations,
            &mut AllRelationsEvals::default(),
            relation_parameters,
            gate_separators,
            alphas,
            is_zk.then_some(multivariate_challenge.as_slice()),
            builder,
            driver,
        )?;

        // For ZK Flavors: the libra univariate evaluation hides the contribution from the actual
        // Honk relation
        let libra_evaluation = if is_zk {
            let libra_evaluation =
                transcript.receive_fr_from_prover("Libra:claimed_evaluation".to_owned())?;
            let tmp = libra_evaluation.multiply(
                &libra_challenge.expect("We have ZK"),
                builder,
                driver,
            )?;
            full_honk_purported_value = full_honk_purported_value.add(&tmp, builder, driver);
            Some(libra_evaluation)
        } else {
            None
        };

        // Final Verification Step
        full_honk_purported_value.assert_equal(target_sum, builder, driver);

        Ok(SumcheckOutput {
            challenges: multivariate_challenge,
            claimed_evaluations,
            claimed_libra_evaluation: libra_evaluation,
            claimed_gemini_masking_evaluation,
        })
    }

    /**
     * @brief Check that the round target sum is correct
     * @details The verifier receives the claimed evaluations of the round univariate \f$ \tilde{S}^i \f$ at \f$X_i =
     * 0,\ldots, D \f$ and checks \f$\sigma_i = \tilde{S}^{i-1}(u_{i-1}) \stackrel{?}{=} \tilde{S}^i(0) + \tilde{S}^i(1)
     * \f$
     * @param univariate Round univariate \f$\tilde{S}^{i}\f$ represented by its evaluations over \f$0,\ldots,D\f$.
     *
     */
    /// Matches bb's unconditional `check_sum` (no indicator-based freeze) — see the target-sum
    /// update in `verify` above for why the indicator can no longer be used to skip virtual/padding
    /// rounds.
    fn check_sum<
        C: HonkCurve<TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
    >(
        univariate: &[FieldCT<C::ScalarField>],
        target_sum: &FieldCT<C::ScalarField>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<()> {
        let total_sum = univariate[0].add(&univariate[1], builder, driver);
        target_sum.assert_equal(&total_sum, builder, driver);
        Ok(())
    }

    /**
     * @brief Compute the evaluation of 1 - L at the sumcheck challenge, i.e.
     * 1 - \prod_{k=2}^{d-1} (1 - u_k). This is circuit-size independent: it is evaluated over ALL
     * (virtual) sumcheck challenges, so no padding indicator is needed.
     */
    pub fn evaluate_at_challenge<
        C: HonkCurve<TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
    >(
        multivariate_challenge: &[FieldCT<C::ScalarField>],
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> eyre::Result<FieldCT<C::ScalarField>> {
        let one = FieldCT::from(C::ScalarField::ONE);
        let mut evaluation_at_multivariate_challenge = one.clone();

        for challenge in multivariate_challenge.iter().skip(2) {
            evaluation_at_multivariate_challenge = evaluation_at_multivariate_challenge.multiply(
                &one.sub(challenge, builder, driver),
                builder,
                driver,
            )?;
        }

        Ok(one.sub(&evaluation_at_multivariate_challenge, builder, driver))
    }
}

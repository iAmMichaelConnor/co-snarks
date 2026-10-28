use crate::honk_verifier::recursive_decider_verification_key::RecursiveDeciderVerificationKey;
use crate::honk_verifier::recursive_decider_verification_key::WitnessCommitments;
use crate::{
    prelude::GenericUltraCircuitBuilder,
    transcript_ct::{TranscriptCT, TranscriptHasherCT},
    types::field_ct::FieldCT,
};
use ark_ff::Field;
use co_acvm::mpc::NoirWitnessExtensionProtocol;

use co_noir_common::constants::PERMUTATION_ARGUMENT_VALUE_SEPARATOR;
use co_noir_common::types::RelationParameters;
use co_noir_common::types::ZeroKnowledge;
use co_noir_common::{
    honk_curve::HonkCurve,
    honk_proof::{HonkProofResult, TranscriptFieldType},
};

pub(crate) struct OinkRecursiveVerifier;

impl OinkRecursiveVerifier {
    pub fn verify<
        C: HonkCurve<TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
        H: TranscriptHasherCT<C>,
    >(
        verification_key: &mut RecursiveDeciderVerificationKey<C, T>,
        transcript: &mut TranscriptCT<C, H>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        has_zk: ZeroKnowledge,
        num_public_inputs: usize,
        driver: &mut T,
    ) -> HonkProofResult<()> {
        let vk_hash = verification_key
            .vk_and_hash
            .vk
            .hash_through_transcript(transcript, builder, driver)?;

        // Check that the vk hash matches the hash of the verification key
        verification_key
            .vk_and_hash
            .hash
            .assert_equal(&vk_hash, builder, driver);

        transcript.add_element_frs_to_hash_buffer("vk_hash".to_string(), &[vk_hash]);

        let public_inputs = Self::receive_public_inputs(
            &verification_key.vk_and_hash.vk.num_public_inputs,
            num_public_inputs,
            transcript,
            builder,
            driver,
        )?;

        let mut commitments = WitnessCommitments::<C::ScalarField, T>::default();

        if has_zk == ZeroKnowledge::Yes {
            verification_key.gemini_masking_commitment =
                Some(transcript.receive_point_from_prover(
                    "Gemini:masking_poly_comm".to_owned(),
                    builder,
                    driver,
                )?);
        }

        // TACEO TODO: batch `is_zero` calls on `receive_point_from_prover`
        // Get commitments to first three wire polynomials
        *commitments.w_l_mut() =
            transcript.receive_point_from_prover("w_l".to_owned(), builder, driver)?;
        *commitments.w_r_mut() =
            transcript.receive_point_from_prover("w_r".to_owned(), builder, driver)?;
        *commitments.w_o_mut() =
            transcript.receive_point_from_prover("w_o".to_owned(), builder, driver)?;

        // Get eta challenge and derive eta, eta² and eta³ used in memory and lookup arguments.
        let [eta, rom_logup_gamma] = transcript
            .get_challenges(
                &["eta".to_string(), "rom_logup_gamma".to_string()],
                builder,
                driver,
            )?
            .try_into()
            .unwrap();
        let eta_1 = eta.clone();
        let eta_2 = eta.multiply(&eta, builder, driver)?;
        let eta_3 = eta_2.multiply(&eta, builder, driver)?;

        // Get commitments to lookup argument polynomials and fourth wire
        *commitments.lookup_read_counts_mut() = transcript.receive_point_from_prover(
            "lookup_read_counts".to_owned(),
            builder,
            driver,
        )?;
        *commitments.lookup_read_tags_mut() =
            transcript.receive_point_from_prover("lookup_read_tags".to_owned(), builder, driver)?;
        *commitments.w_4_mut() =
            transcript.receive_point_from_prover("w_4".to_owned(), builder, driver)?;

        // Get permutation challenges
        let [beta, gamma] = transcript
            .get_challenges(&["beta".to_owned(), "gamma".to_owned()], builder, driver)?
            .try_into()
            .unwrap();
        let beta_sqr = beta.multiply(&beta, builder, driver)?;
        let beta_cube = beta_sqr.multiply(&beta, builder, driver)?;

        *commitments.lookup_inverses_mut() =
            transcript.receive_point_from_prover("lookup_inverses".to_owned(), builder, driver)?;

        // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/1283): Suspicious get_value().
        let public_input_delta = Self::compute_public_input_delta(
            &public_inputs,
            &beta,
            &gamma,
            &verification_key.vk_and_hash.vk.pub_inputs_offset,
            builder,
            driver,
        )?;

        // Get commitments to permutation and lookup grand products
        *commitments.z_perm_mut() =
            transcript.receive_point_from_prover("z_perm".to_owned(), builder, driver)?;

        let alpha = transcript.get_challenge("alpha".to_string(), builder, driver)?;

        verification_key.relation_parameters = RelationParameters {
            beta,
            beta_sqr,
            beta_cube,
            gamma,
            eta_1,
            eta_2,
            eta_3,
            rom_logup_gamma,
            public_input_delta,
        };
        verification_key.witness_commitments = commitments;
        verification_key.alphas[0] = alpha;
        verification_key.public_inputs = public_inputs;
        Ok(())
    }

    fn receive_public_inputs<
        C: HonkCurve<TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
        H: TranscriptHasherCT<C>,
    >(
        vk_count: &FieldCT<C::ScalarField>,
        num_public_inputs: usize,
        transcript: &mut TranscriptCT<C, H>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<Vec<FieldCT<C::ScalarField>>> {
        let expected = C::ScalarField::from(num_public_inputs as u64);
        // An invalid public header must not determine an allocation or loop bound.
        if T::get_public(&vk_count.get_value(builder, driver))
            .is_some_and(|value| value != expected)
        {
            return Err(co_noir_common::honk_proof::HonkProofError::CorruptedKey);
        }
        vk_count.assert_equal(&FieldCT::from(expected), builder, driver);
        (0..num_public_inputs)
            .map(|i| transcript.receive_fr_from_prover(format!("public_input_{i}")))
            .collect()
    }

    /**
     * @brief Compute the correction term for the permutation argument.
     *
     * @tparam Field
     * @param public_inputs x₀, ..., xₘ₋₁ public inputs to the circuit
     * @param beta random linear-combination term to combine both (wʲ, IDʲ) and (wʲ, σʲ)
     * @param gamma Schwartz-Zippel random evaluation to ensure ∏ᵢ (γ + Sᵢ) = ∏ᵢ (γ + Tᵢ)
     * @param domain_size Total number of rows required for the circuit (power of 2)
     * @param offset Extent to which PI are offset from the 0th index in the wire polynomials, for example, due to inclusion
     * of a leading zero row or Goblin style ECC op gates at the top of the execution trace.
     * @return Field Public input Δ
     */
    fn compute_public_input_delta<
        C: HonkCurve<TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
    >(
        public_inputs: &[FieldCT<C::ScalarField>],
        beta: &FieldCT<C::ScalarField>,
        gamma: &FieldCT<C::ScalarField>,
        // domain_size: &FieldCT<C::ScalarField>,
        offset: &FieldCT<C::ScalarField>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<FieldCT<C::ScalarField>> {
        let one = FieldCT::from(C::ScalarField::ONE);

        // Let m be the number of public inputs x₀,…, xₘ₋₁.
        // Recall that we broke the permutation σ⁰ by changing the mapping
        //  (i) -> (n+i)   to   (i) -> (-(i+1))   i.e. σ⁰ᵢ = −(i+1)
        //
        // Therefore, the term in the numerator with ID¹ᵢ = n+i does not cancel out with any term in the denominator.
        // Similarly, the denominator contains an extra σ⁰ᵢ = −(i+1) term that does not appear in the numerator.
        // We expect the values of W⁰ᵢ and W¹ᵢ to be equal to xᵢ.
        // The expected accumulated product would therefore be equal to

        //   ∏ᵢ (γ + W¹ᵢ + β⋅ID¹ᵢ)        ∏ᵢ (γ + xᵢ + β⋅(n+i) )
        //  -----------------------  =  ------------------------
        //   ∏ᵢ (γ + W⁰ᵢ + β⋅σ⁰ᵢ )        ∏ᵢ (γ + xᵢ - β⋅(i+1) )

        // At the start of the loop for each xᵢ where i = 0, 1, …, m-1,
        // we have
        //      numerator_acc   = γ + β⋅(n+i) = γ + β⋅n + β⋅i
        //      denominator_acc = γ - β⋅(1+i) = γ - β   - β⋅i
        // at the end of the loop, add and subtract β to each term respectively to
        // set the expected value for the start of iteration i+1.
        // Note: The public inputs may be offset from the 0th index of the wires, for example due to the inclusion of an
        // initial zero row or Goblin-style ECC op gates. Accordingly, the indices i in the above formulas are given by i =
        // [0, m-1] + offset, i.e. i = offset, 1 + offset, …, m - 1 + offset.

        let mut numerator = one.clone();
        let mut denominator = one.clone();
        let separator = FieldCT::from(C::ScalarField::from(PERMUTATION_ARGUMENT_VALUE_SEPARATOR));

        let beta_mul_n_plus_i =
            beta.multiply(&separator.add(offset, builder, driver), builder, driver)?;
        let mut numerator_acc = gamma.add(&beta_mul_n_plus_i, builder, driver);
        let beta_mul_one_plus_i =
            beta.multiply(&offset.add(&one, builder, driver), builder, driver)?;
        let mut denominator_acc = gamma.sub(&beta_mul_one_plus_i, builder, driver);

        // TACEO TODO: Is there a more efficient way to do this?
        for i in 0..public_inputs.len() {
            let input = &public_inputs[i];
            numerator =
                numerator.multiply(&numerator_acc.add(input, builder, driver), builder, driver)?;
            denominator = denominator.multiply(
                &denominator_acc.add(input, builder, driver),
                builder,
                driver,
            )?;

            if i + 1 < public_inputs.len() {
                numerator_acc = numerator_acc.add(beta, builder, driver);
                denominator_acc = denominator_acc.sub(beta, builder, driver);
            }
        }

        Ok(numerator.divide(&denominator, builder, driver)?)
    }
}

#[cfg(test)]
mod public_input_count_tests {
    use super::*;
    use crate::transcript_ct::Poseidon2SpongeCT;
    use ark_bn254::{Fr, G1Projective};
    use co_acvm::PlainAcvmSolver;
    #[test]
    fn recursive_public_input_count_rejects_zero_and_oversized_headers() {
        use ark_ff::{One, Zero};
        for count in [Fr::zero(), Fr::one(), Fr::from(u64::MAX), -Fr::one()] {
            let mut builder =
                GenericUltraCircuitBuilder::<G1Projective, PlainAcvmSolver<Fr>>::new_minimal(0);
            let mut driver = PlainAcvmSolver::default();
            let count = FieldCT::from_witness(count, &mut builder);
            let mut transcript =
                TranscriptCT::<G1Projective, Poseidon2SpongeCT<G1Projective>>::new_verifier(
                    vec![FieldCT::default(); 8],
                );
            assert!(matches!(
                OinkRecursiveVerifier::receive_public_inputs(
                    &count,
                    8,
                    &mut transcript,
                    &mut builder,
                    &mut driver
                ),
                Err(co_noir_common::honk_proof::HonkProofError::CorruptedKey)
            ));
        }
    }
    #[test]
    fn recursive_public_input_count_binds_shared_headers_without_opening_them() {
        use co_acvm::{Rep3AcvmSolver, Rep3AcvmType};
        use mpc_core::protocols::rep3::{conversion::A2BType, share_field_elements};
        use mpc_net::local::LocalNetwork;
        let values = [8u64, 0, u64::MAX].map(Fr::from);
        let shares = share_field_elements(&values, &mut rand::thread_rng());
        let workers: Vec<_> = LocalNetwork::new_3_parties()
            .into_iter()
            .zip(shares)
            .map(|(net, shares)| {
                std::thread::spawn(move || {
                    let mut driver =
                        Rep3AcvmSolver::<Fr, _>::new(&net, A2BType::default()).unwrap();
                    let mut results = Vec::new();
                    for share in shares {
                        let mut builder =
                            GenericUltraCircuitBuilder::<G1Projective, _>::new_minimal(0);
                        let count =
                            FieldCT::from_witness(Rep3AcvmType::Shared(share), &mut builder);
                        // A prior arithmetic use stands in for the VK hash, which
                        // is computed before the count is tied to the fixed shape.
                        let square = count.multiply(&count, &mut builder, &mut driver).unwrap();
                        let mut transcript = TranscriptCT::<
                            G1Projective,
                            Poseidon2SpongeCT<G1Projective>,
                        >::new_verifier(
                            vec![FieldCT::default(); 8]
                        );
                        let public_inputs = OinkRecursiveVerifier::receive_public_inputs(
                            &count,
                            8,
                            &mut transcript,
                            &mut builder,
                            &mut driver,
                        )
                        .unwrap();
                        assert_eq!(public_inputs.len(), 8);
                        assert_eq!(
                            count.get_value(&builder, &mut driver),
                            Rep3AcvmType::Public(Fr::from(8u64))
                        );
                        match square.get_value(&builder, &mut driver) {
                            Rep3AcvmType::Shared(square) => results.push(square.a),
                            _ => panic!("prior shared arithmetic output must stay shared"),
                        }
                    }
                    results
                })
            })
            .collect();
        let results: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
        for (case, original) in values.into_iter().enumerate() {
            let square: Fr = results.iter().map(|party| party[case]).sum();
            assert_eq!(square, original * original);
            // The correct count satisfies its earlier arithmetic gate. An
            // incorrect count now conflicts with that gate, so fixing the
            // host allocation does not discard the witness binding.
            assert_eq!(square == Fr::from(64u64), case == 0);
        }
    }
}

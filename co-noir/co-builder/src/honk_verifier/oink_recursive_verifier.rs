use crate::honk_verifier::recursive_decider_verification_key::RecursiveDeciderVerificationKey;
use crate::honk_verifier::recursive_decider_verification_key::WitnessCommitments;
use crate::{
    prelude::GenericUltraCircuitBuilder,
    transcript_ct::{TranscriptCT, TranscriptHasherCT},
    types::field_ct::FieldCT,
};
use ark_ff::Field;
use co_acvm::mpc::NoirWitnessExtensionProtocol;

use co_noir_common::constants::{
    PAIRING_POINT_ACCUMULATOR_SIZE, PERMUTATION_ARGUMENT_VALUE_SEPARATOR,
};
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

        // As in barretenberg, the number of public inputs follows from the size of the proof (the
        // inner public inputs of the recursion constraint and the pairing point accumulator), and
        // the key's value is constrained to it. The key's value may be secret-shared.
        let num_public_inputs =
            verification_key.public_inputs.len() + PAIRING_POINT_ACCUMULATOR_SIZE as usize;
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

        // Get the eta and ROM-LogUp challenges and derive eta, eta² and eta³ used in memory and lookup arguments.
        let [eta, rom_logup_gamma] = transcript
            .get_challenges(
                &["eta".to_owned(), "rom_logup_gamma".to_owned()],
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

    /// Receives `num_public_inputs` public inputs from the transcript and constrains the key's
    /// number of public inputs `key_value` to be equal to it.
    fn receive_public_inputs<
        C: HonkCurve<TranscriptFieldType>,
        T: NoirWitnessExtensionProtocol<C::ScalarField>,
        H: TranscriptHasherCT<C>,
    >(
        key_value: &FieldCT<C::ScalarField>,
        num_public_inputs: usize,
        transcript: &mut TranscriptCT<C, H>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<Vec<FieldCT<C::ScalarField>>> {
        let public_inputs = (0..num_public_inputs)
            .map(|i| transcript.receive_fr_from_prover(format!("public_input_{i}")))
            .collect::<Result<Vec<_>, _>>()?;
        key_value.assert_equal(
            &FieldCT::from(C::ScalarField::from(num_public_inputs as u64)),
            builder,
            driver,
        );
        Ok(public_inputs)
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
mod tests {
    use super::*;
    use crate::transcript_ct::{Bn254G1, Poseidon2SpongeCT};
    use crate::types::field_ct::tests::{Gadget, rep3_witness_verifies};
    use ark_bn254::Fr;
    use ark_ff::Zero;

    /// Uses the input witness, the key's number of public inputs, then receives 8 public inputs
    /// and binds the key's number to 8.
    #[derive(Clone, Copy)]
    struct ReceivePublicInputs;

    impl Gadget for ReceivePublicInputs {
        fn build<T: NoirWitnessExtensionProtocol<Fr>>(
            self,
            inputs: &[T::AcvmType],
            builder: &mut GenericUltraCircuitBuilder<Bn254G1, T>,
            driver: &mut T,
        ) {
            let key_value = FieldCT::from_witness(inputs[0].clone(), builder);
            // An earlier use of the value, as in the key hash.
            key_value.multiply(&key_value, builder, driver).unwrap();
            let mut transcript =
                TranscriptCT::<Bn254G1, Poseidon2SpongeCT<Bn254G1>>::new_verifier(vec![
                    FieldCT::from(Fr::zero());
                    8
                ]);
            let public_inputs = OinkRecursiveVerifier::receive_public_inputs(
                &key_value,
                8,
                &mut transcript,
                builder,
                driver,
            )
            .unwrap();
            assert_eq!(public_inputs.len(), 8);
        }
    }

    /// A secret-shared number of public inputs in the inner key is constrained, not opened. (The
    /// builder resolves the equality with a constant by giving the shared witness the constant's
    /// value, so a wrong value shows up in the gate that used it before.)
    #[test]
    fn shared_key_public_input_count_is_constrained() {
        assert!(rep3_witness_verifies(
            &[Fr::from(8u64)],
            ReceivePublicInputs
        ));
        for wrong in [0u64, 7, 9, u64::MAX] {
            assert!(!rep3_witness_verifies(
                &[Fr::from(wrong)],
                ReceivePublicInputs
            ));
        }
    }
}

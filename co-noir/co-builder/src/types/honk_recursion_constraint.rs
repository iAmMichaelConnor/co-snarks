use crate::acir_format::ProofType;
use crate::honk_verifier::recursive_decider_verification_key::{
    RecursiveDeciderVerificationKey, VKAndHash,
};
use crate::honk_verifier::ultra_recursive_verifier::UltraRecursiveVerifier;
use crate::keys::proving_key::create_keys_barretenberg;
use crate::prelude::{GenericUltraCircuitBuilder, RecursionInputVisibility};
use crate::transcript_ct::{Poseidon2SpongeCT, TranscriptCT, TranscriptHasherCT};
use crate::types::big_group::BigGroup;
use crate::types::types::{AddQuad, PairingPoints, RecursionConstraint};
use crate::{transcript_ct::TranscriptFieldType, types::field_ct::FieldCT};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, One, PrimeField, Zero};
use co_acvm::PlainAcvmSolver;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_noir_common::constants::{
    BATCHED_RELATION_PARTIAL_LENGTH, BATCHED_RELATION_PARTIAL_LENGTH_ZK, CONST_PROOF_SIZE_LOG_N,
    DECIDER_PROOF_LENGTH, NUM_ALL_ENTITIES, NUM_SMALL_IPA_EVALUATIONS, NUM_ZERO_ROWS,
    OINK_PROOF_LENGTH_WITHOUT_PUB_INPUTS, OINK_PROOF_LENGTH_WITHOUT_PUB_INPUTS_ZK,
    PUBLIC_INPUTS_SIZE, ULTRA_PROOF_LENGTH_WITHOUT_PUB_INPUTS,
    ULTRA_PROOF_LENGTH_WITHOUT_PUB_INPUTS_ZK, ULTRA_VERIFICATION_KEY_LENGTH,
};
use co_noir_common::crs::ProverCrs;
use co_noir_common::honk_curve::HonkCurve;
use co_noir_common::honk_proof::{HonkProofError, HonkProofResult};
use co_noir_common::keys::verification_key::VerifyingKeyBarretenberg;
use co_noir_common::mpc::plain::PlainUltraHonkDriver;
use co_noir_common::polynomials::entities::{PrecomputedEntities, WITNESS_ENTITIES_SIZE};
use co_noir_common::transcript::{Poseidon2Sponge, Transcript};
use co_noir_common::types::ZeroKnowledge;
use co_ultrahonk::prelude::CoUltraHonk;
use itertools::izip;
use mpc_core::{MpcState, PlainState};
use rand::SeedableRng;
use std::any::{Any, TypeId};
use std::array;

pub type PrecomputedCommitments<C, T> = PrecomputedEntities<BigGroup<C, T>>;

// TACEO TODO: This is not so nice, can we avoid?
fn downcast<A: 'static, B: 'static>(a: &A) -> Option<&B> {
    (a as &dyn Any).downcast_ref::<B>()
}

pub struct RecursiveVerificationKey<
    C: HonkCurve<TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
> {
    pub log_circuit_size: FieldCT<C::ScalarField>,
    pub num_public_inputs: FieldCT<C::ScalarField>,
    pub pub_inputs_offset: FieldCT<C::ScalarField>,
    pub precomputed_commitments: PrecomputedCommitments<C::ScalarField, T>,
}

impl<C: HonkCurve<TranscriptFieldType>, T: NoirWitnessExtensionProtocol<C::ScalarField>>
    RecursiveVerificationKey<C, T>
{
    fn new(
        elements: &[FieldCT<C::ScalarField>],
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<Self> {
        if elements.len() != ULTRA_VERIFICATION_KEY_LENGTH {
            return Err(HonkProofError::InvalidKeyLength);
        }
        let log_circuit_size = elements[0].clone();
        let num_public_inputs = elements[1].clone();
        let pub_inputs_offset = elements[2].clone();
        let mut precomputed_commitments = PrecomputedCommitments::default();

        // TACEO TODO: Maybe we could batch the is_zero checks here
        for (des, src) in precomputed_commitments
            .elements
            .iter_mut()
            .zip(elements[3..].chunks(BigGroup::<C::ScalarField, T>::NUM_BN254_FRS))
        {
            *des = BigGroup::reconstruct_from_public(src, builder, driver)?;
        }

        Ok(RecursiveVerificationKey {
            log_circuit_size,
            num_public_inputs,
            pub_inputs_offset,
            precomputed_commitments,
        })
    }

    pub fn hash_through_transcript<H: TranscriptHasherCT<C>>(
        &self,
        transcript: &mut TranscriptCT<C, H>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> eyre::Result<FieldCT<C::ScalarField>> {
        transcript.add_fr_to_independent_hash_buffer::<T>(&self.log_circuit_size);
        transcript.add_fr_to_independent_hash_buffer::<T>(&self.num_public_inputs);
        transcript.add_fr_to_independent_hash_buffer::<T>(&self.pub_inputs_offset);

        for commitment in self.precomputed_commitments.elements.iter() {
            transcript.add_point_to_independent_hash_buffer(commitment, builder, driver)?;
        }

        transcript.hash_independent_buffer(builder, driver)
    }
}

impl<C: HonkCurve<TranscriptFieldType>, T: NoirWitnessExtensionProtocol<C::ScalarField>>
    GenericUltraCircuitBuilder<C, T>
{
    /// Applies the agreed [`RecursionInputVisibility`] to the inputs of a recursion constraint
    /// (inner proof and public inputs, verification key, key hash and a witness predicate).
    ///
    /// With [`RecursionInputVisibility::RevealToParticipants`], the secret-shared inputs are opened
    /// to all parties. With [`RecursionInputVisibility::KeepSecret`], a secret-shared input is an
    /// error. With [`RecursionInputVisibility::PrivateRecursion`], the inputs stay secret-shared
    /// and the verifier is built on them. Before that, all parties check that they use the same setting, which sends only the
    /// setting itself. Nothing secret is sent before a party could reject.
    fn prepare_recursion_inputs(
        &mut self,
        input: &RecursionConstraint<C::ScalarField>,
        driver: &mut T,
    ) -> eyre::Result<()> {
        // Every party takes part, even if all its recursion inputs are public.
        driver.agree_recursion_input_visibility(self.recursion_input_visibility)?;

        let proof_indices =
            create_indices_for_reconstructed_proof(&input.proof, &input.public_inputs);
        let shared_indices: Vec<u32> = proof_indices
            .iter()
            .chain(input.key.iter())
            .chain(std::iter::once(&input.key_hash))
            .chain(std::iter::once(&input.predicate.index).filter(|_| !input.predicate.is_constant))
            .filter(|idx| T::is_shared(&self.get_variable(**idx as usize)))
            .copied()
            .collect();
        if shared_indices.is_empty() {
            return Ok(());
        }
        match self.recursion_input_visibility {
            RecursionInputVisibility::KeepSecret => eyre::bail!(
                "The recursion constraint has secret-shared inputs. Verifying it requires opening the inner proof, its public inputs, the verification key, the key hash and the predicate to all parties; all parties must explicitly allow this with RecursionInputVisibility::RevealToParticipants (co-noir: --reveal-recursion-inputs)"
            ),
            RecursionInputVisibility::PrivateRecursion => Ok(()),
            RecursionInputVisibility::RevealToParticipants => {
                let shares: Vec<_> = shared_indices
                    .iter()
                    .map(|idx| {
                        T::get_shared(&self.get_variable(*idx as usize))
                            .expect("We already checked it is shared")
                    })
                    .collect();
                let opened_values = driver.open_many(&shares)?;
                for (idx, value) in izip!(shared_indices, opened_values) {
                    self.set_variable(idx, T::AcvmType::from(value));
                }
                Ok(())
            }
        }
    }

    /// Add constraints required to recursively verify an UltraHonk proof
    pub(crate) fn create_honk_recursion_constraints(
        &mut self,
        input: &RecursionConstraint<C::ScalarField>,
        crs: &ProverCrs<C>,
        driver: &mut T,
    ) -> eyre::Result<PairingPoints<C, T>> {
        let is_honk = input.proof_type == ProofType::Honk as u32;
        let is_honk_zk = input.proof_type == ProofType::HonkZk as u32;
        assert!(
            is_honk || is_honk_zk,
            "create_honk_recursion_constraints: Only HONK, HONK_ZK proof types are supported."
        );

        let has_zk = if input.proof_type == ProofType::Honk as u32 {
            ZeroKnowledge::No
        } else {
            ZeroKnowledge::Yes
        };

        // Validate the ACIR input sizes before using any of the inputs, as barretenberg does. The
        // ACIR proof excludes the inner public inputs but contains the pairing point object.
        if input.key.len() != ULTRA_VERIFICATION_KEY_LENGTH {
            return Err(HonkProofError::InvalidKeyLength.into());
        }
        let expected_proof_size = PUBLIC_INPUTS_SIZE
            + match has_zk {
                ZeroKnowledge::Yes => ULTRA_PROOF_LENGTH_WITHOUT_PUB_INPUTS_ZK,
                ZeroKnowledge::No => ULTRA_PROOF_LENGTH_WITHOUT_PUB_INPUTS,
            };
        eyre::ensure!(
            input.proof.len() == expected_proof_size,
            "create_honk_recursion_constraints: ACIR proof size mismatch: expected {expected_proof_size}, got {}",
            input.proof.len()
        );

        // MPC adaptation: apply the agreed treatment of secret-shared inputs before any input,
        // including the predicate, is used.
        self.prepare_recursion_inputs(input, driver)?;

        // Currently no IPA support

        // Step 1.
        // Construct in-circuit representations of the recursion data.
        let mut vk_fields: Vec<FieldCT<C::ScalarField>> = input
            .key
            .iter()
            .map(|idx| FieldCT::<C::ScalarField>::from_witness_index(*idx))
            .collect();
        let mut vk_hash = FieldCT::<C::ScalarField>::from_witness_index(input.key_hash);
        let proof_indices =
            create_indices_for_reconstructed_proof(&input.proof, &input.public_inputs);
        let mut proof_fields: Vec<FieldCT<C::ScalarField>> = proof_indices
            .iter()
            .map(|idx| FieldCT::<C::ScalarField>::from_witness_index(*idx))
            .collect();
        let predicate = input.predicate.to_field_ct().to_bool_ct(self, driver);

        // Construct a Honk proof and vk with the correct number of public inputs.
        // If we are in a write vk scenario, the proof and vk are not necessarily valid
        let (honk_proof_to_be_set, honk_vk_to_be_set) = if self.is_write_vk_mode {
            (
                self.create_mock_honk_proof(input.public_inputs.len(), has_zk, driver)?,
                Self::create_mock_honk_vk(1 << CONST_PROOF_SIZE_LOG_N, input.public_inputs.len()),
            )
        } else {
            self.construct_honk_proof_for_simple_circuit(
                input.public_inputs.len(),
                crs,
                has_zk,
                driver,
            )?
        };
        // Step 2.
        if self.is_write_vk_mode {
            // Set honk vk in builder
            let vk_elements = honk_vk_to_be_set.to_field_elements();
            for (field, value) in vk_fields.iter().zip(vk_elements.iter()) {
                let index = field.get_witness_index(self, driver);
                self.set_variable(index, T::AcvmType::from(*value));
            }

            // Set honk proof in the builder
            for (field, value) in proof_fields.iter().zip(honk_proof_to_be_set.iter()) {
                let index = field.get_witness_index(self, driver);
                self.set_variable(index, T::AcvmType::from(*value));
            }
        }
        // Step 3.
        if !predicate.is_constant() {
            let mut transcript = Transcript::<TranscriptFieldType, Poseidon2Sponge>::new();
            let honk_vk_hash = honk_vk_to_be_set.hash_with_origin_tagging("", &mut transcript);
            // If the predicate is a witness, we conditionally assign a valid vk, proof and vk hash so that verification
            // succeeds. Note: in doing this, we create some new witnesses that are only used in the conditional assignment.
            // It would be optimal to hard-code these values in the selectors, but due to the randomness needed to generate
            // valid ZK proofs, we cannot do that without adding a dependency of the VKs on the witness values. Note that
            // the new witnesses are used only in the recursive verification when the predicate is set to true, so they
            // don't create a soundness issue and can be filled with anything - as long as they contain a valid vk, proof
            // and vk hash
            let vk_elements = honk_vk_to_be_set.to_field_elements();
            for (vk_witness, vk_element) in vk_fields.iter_mut().zip(vk_elements.iter()) {
                let valid_vk_witness = FieldCT::from_witness((*vk_element).into(), self);
                *vk_witness = FieldCT::conditional_assign(
                    &predicate,
                    vk_witness,
                    &valid_vk_witness,
                    self,
                    driver,
                )?;
            }
            for (proof_witness, proof_element) in
                proof_fields.iter_mut().zip(honk_proof_to_be_set.iter())
            {
                let valid_proof_witness = FieldCT::from_witness((*proof_element).into(), self);
                *proof_witness = FieldCT::conditional_assign(
                    &predicate,
                    proof_witness,
                    &valid_proof_witness,
                    self,
                    driver,
                )?;
            }
            let valid_vk_hash_val = T::AcvmType::from(honk_vk_hash);
            vk_hash = FieldCT::conditional_assign(
                &predicate,
                &vk_hash,
                &FieldCT::from_witness(valid_vk_hash_val, self),
                self,
                driver,
            )?;
        }
        let vkey = RecursiveVerificationKey::<C, T>::new(&vk_fields, self, driver)?;
        let vk_and_hash = VKAndHash {
            vk: vkey,
            hash: vk_hash,
        };
        let recursive_decider_vkey = RecursiveDeciderVerificationKey {
            vk_and_hash,
            _is_complete: false,
            public_inputs: proof_fields
                .iter()
                .take(input.public_inputs.len())
                .cloned()
                .collect(),
            relation_parameters: Default::default(),
            target_sum: FieldCT::<C::ScalarField>::default(),
            witness_commitments: Default::default(),
            gemini_masking_commitment: None,
            alphas: array::from_fn(|_| FieldCT::<C::ScalarField>::default()),
            gate_challenges: Vec::new(),
        };

        UltraRecursiveVerifier::verify_proof::<C, Poseidon2SpongeCT<C>, T>(
            proof_fields,
            recursive_decider_vkey,
            self,
            driver,
            has_zk,
        )
    }

    /**
     * @brief Create a verifiable honk proof for a circuit with a single big add gate. Adds random public inputs to match
     * num_public_inputs provided
     *
     * @param inner_public_inputs_size Number of public inputs coming from the ACIR constraints
     */
    pub fn construct_honk_proof_for_simple_circuit(
        &mut self,
        num_inner_public_inputs: usize,
        crs: &ProverCrs<C>,
        has_zk: ZeroKnowledge,
        driver: &mut T,
    ) -> eyre::Result<(Vec<C::ScalarField>, VerifyingKeyBarretenberg<C>)> {
        // 3 as inputs for the simple circuit, rest for public inputs and one for the shared randomness for initializing the rng for the plaindriver prover
        let mut random_fields = Vec::with_capacity(num_inner_public_inputs + 3 + 1);
        for _ in 0..num_inner_public_inputs + 4 {
            random_fields.push(driver.rand()?);
        }
        let opened = driver.open_many(&random_fields)?;
        let rng_seed = opened[0];
        let a = opened[1];
        let b = opened[2];
        let c = opened[3];
        let public_inputs = &opened[4..];
        let d = a + b + c;

        // TACEO TODO: I think this is fine?
        let mut builder =
            GenericUltraCircuitBuilder::<C, PlainAcvmSolver<C::ScalarField>>::new_minimal(0);
        let mut plain_driver = PlainAcvmSolver::<C::ScalarField>::new();

        let a_idx = builder.add_variable(a);
        let b_idx = builder.add_variable(b);
        let c_idx = builder.add_variable(c);
        let d_idx = builder.add_variable(d);

        builder.create_big_add_gate(
            &AddQuad {
                a: a_idx,
                b: b_idx,
                c: c_idx,
                d: d_idx,
                a_scaling: C::ScalarField::one(),
                b_scaling: C::ScalarField::one(),
                c_scaling: C::ScalarField::one(),
                d_scaling: -C::ScalarField::one(),
                const_scaling: C::ScalarField::zero(),
            },
            false,
        );

        // Add the public inputs
        for pi in public_inputs.iter() {
            builder.add_public_variable(*pi);
        }

        // Add the default pairing points and IPA claim
        builder.add_default_to_public_inputs();

        builder.finalize_circuit(&mut plain_driver)?;

        // prove the circuit constructed above
        // Create the decider proving key
        let (pk, vk) = create_keys_barretenberg::<_, _, PlainAcvmSolver<_>>(
            ().id(),
            builder,
            crs,
            &mut plain_driver,
        )?;

        // Every party needs to use the same RNG for the below proofs to be identical. We derive it from shared randomness.
        let rng = rand_chacha::ChaCha12Rng::from_seed(
            rng_seed
                .into_bigint()
                .to_bytes_be()
                .try_into()
                .expect("field element should fit into seed size"),
        );

        let mut plain_state = PlainState::new(rng);
        let proof = CoUltraHonk::<PlainUltraHonkDriver, _, Poseidon2Sponge>::prove_inner(
            &(),
            &mut plain_state,
            pk,
            crs,
            has_zk,
            &vk,
        )?
        .inner();

        // TACEO TODO: Handle unsafeness properly
        if TypeId::of::<C::ScalarField>() != TypeId::of::<TranscriptFieldType>() {
            return Err(eyre::eyre!("Proof type mismatch"));
        }

        let proof: Vec<C::ScalarField> = downcast::<_, Vec<C::ScalarField>>(&proof)
            .expect("We checked types")
            .clone();

        Ok((proof, vk))
    }

    /**
     * @brief Create a mock MegaHonk VK that has the correct structure
     *
     * @param dyadic_size Dyadic size of the circuit for which we generate a vk
     * @param pub_inputs_offset Indicating whether the circuit has a first zero row
     * @param inner_public_inputs_size Number of public inputs coming from the ACIR constraints
     */
    fn create_mock_honk_vk(
        dyadic_size: usize,
        acir_public_inputs_size: usize,
    ) -> VerifyingKeyBarretenberg<C> {
        let mut commitments = PrecomputedEntities::default();
        for el in commitments.iter_mut() {
            *el = C::generator().into_affine();
        }

        VerifyingKeyBarretenberg {
            log_circuit_size: dyadic_size.ilog2().into(),
            num_public_inputs: (acir_public_inputs_size + PUBLIC_INPUTS_SIZE) as u64,
            pub_inputs_offset: NUM_ZERO_ROWS as u64,
            commitments,
        }
    }

    /**
     * @brief Create a mock honk proof that has the correct structure but is not in general valid
     *
     * @param inner_public_inputs_size Number of public inputs coming from the ACIR constraints
     */
    fn create_mock_honk_proof(
        &mut self,
        acir_public_inputs_size: usize,
        has_zk: ZeroKnowledge,
        driver: &mut T,
    ) -> eyre::Result<Vec<C::ScalarField>> {
        // Construct a Honk proof as the concatenation of an Oink proof and a Decider proof
        let proof_capacity = if has_zk == ZeroKnowledge::Yes {
            ULTRA_PROOF_LENGTH_WITHOUT_PUB_INPUTS_ZK
        } else {
            ULTRA_PROOF_LENGTH_WITHOUT_PUB_INPUTS
        };
        let mut proof = Vec::with_capacity(proof_capacity);
        proof.extend_from_slice(&self.create_mock_oink_proof(
            acir_public_inputs_size,
            has_zk,
            driver,
        )?);
        proof.extend_from_slice(&self.create_mock_decider_proof(has_zk, driver)?);
        let shared: Vec<_> = proof.iter().map(|y| driver.get_as_shared(y)).collect();
        let proof_as_scalars: Vec<C::ScalarField> = driver.open_many(&shared)?;

        Ok(proof_as_scalars)
    }

    fn create_mock_oink_proof(
        &mut self,
        inner_public_inputs_size: usize,
        has_zk: ZeroKnowledge,
        driver: &mut T,
    ) -> eyre::Result<Vec<T::AcvmType>> {
        let proof_capacity = if has_zk == ZeroKnowledge::Yes {
            OINK_PROOF_LENGTH_WITHOUT_PUB_INPUTS_ZK
        } else {
            OINK_PROOF_LENGTH_WITHOUT_PUB_INPUTS
        };
        let mut proof = Vec::with_capacity(proof_capacity);

        // Populate the proof with as many public inputs as required from the ACIR constraints
        populate_field_elements::<C, T>(&mut proof, inner_public_inputs_size, None, driver)?;

        let mut builder =
            GenericUltraCircuitBuilder::<C, PlainAcvmSolver<C::ScalarField>>::new_minimal(0);
        builder.add_default_to_public_inputs();
        // Populate the proof with the public inputs added from barretenberg
        for public_input in builder.public_inputs.iter() {
            proof.push(builder.get_variable(*public_input as usize).into());
        }

        if has_zk == ZeroKnowledge::Yes {
            // ZK proofs bind the Gemini masking commitment in Oink before the witness commitments.
            populate_field_elements_for_mock_commitments::<C, T>(&mut proof, 1);
        }

        // Populate mock witness polynomial commitments
        populate_field_elements_for_mock_commitments::<C, T>(&mut proof, WITNESS_ENTITIES_SIZE);

        Ok(proof)
    }

    /*
     * @brief Create a mock decider proof that has the correct structure but is not in general valid
     *
     */
    fn create_mock_decider_proof(
        &mut self,
        has_zk: ZeroKnowledge,
        driver: &mut T,
    ) -> eyre::Result<Vec<T::AcvmType>> {
        let mut proof = Vec::with_capacity(DECIDER_PROOF_LENGTH);

        // No AVM flavor
        let const_proof_log_n = CONST_PROOF_SIZE_LOG_N;

        if has_zk == ZeroKnowledge::Yes {
            // Libra concatenation commitment
            populate_field_elements_for_mock_commitments::<C, T>(&mut proof, 1);
            // Libra sum
            populate_field_elements::<C, T>(&mut proof, 1, None, driver)?;
        }

        // Sumcheck univariates
        let total_size_sumcheck_univariates = if has_zk == ZeroKnowledge::Yes {
            const_proof_log_n * BATCHED_RELATION_PARTIAL_LENGTH_ZK
        } else {
            const_proof_log_n * BATCHED_RELATION_PARTIAL_LENGTH
        };
        populate_field_elements::<C, T>(&mut proof, total_size_sumcheck_univariates, None, driver)?;

        let num_all_entities = NUM_ALL_ENTITIES + usize::from(has_zk == ZeroKnowledge::Yes);
        populate_field_elements::<C, T>(&mut proof, num_all_entities, None, driver)?;

        if has_zk == ZeroKnowledge::Yes {
            // Libra claimed evaluation
            populate_field_elements::<C, T>(&mut proof, 1, None, driver)?;

            // Libra grand sum commitment
            populate_field_elements_for_mock_commitments::<C, T>(&mut proof, 1);

            // Libra quotient commitment
            populate_field_elements_for_mock_commitments::<C, T>(&mut proof, 1);
        }

        // Gemini fold commitments
        let num_gemini_fold_commitments = const_proof_log_n - 1;
        populate_field_elements_for_mock_commitments::<C, T>(
            &mut proof,
            num_gemini_fold_commitments,
        );

        // Gemini fold evaluations
        let num_gemini_fold_evaluations = const_proof_log_n;
        populate_field_elements::<C, T>(&mut proof, num_gemini_fold_evaluations, None, driver)?;

        if has_zk == ZeroKnowledge::Yes {
            let num_small_ipa_evaluations = NUM_SMALL_IPA_EVALUATIONS;
            populate_field_elements::<C, T>(&mut proof, num_small_ipa_evaluations, None, driver)?;
        }

        // Shplonk batched quotient commitment
        populate_field_elements_for_mock_commitments::<C, T>(&mut proof, 1);
        // KZG quotient commitment
        populate_field_elements_for_mock_commitments::<C, T>(&mut proof, 1);

        Ok(proof)
    }
}

fn create_indices_for_reconstructed_proof(proof_in: &[u32], public_inputs: &[u32]) -> Vec<u32> {
    let mut proof = Vec::with_capacity(proof_in.len() + public_inputs.len());
    proof.extend_from_slice(public_inputs);
    proof.extend_from_slice(proof_in);
    proof
}

fn populate_field_elements<
    C: HonkCurve<TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
>(
    fields: &mut Vec<T::AcvmType>,
    num_elements: usize,
    value: Option<C::ScalarField>,
    driver: &mut T,
) -> eyre::Result<()> {
    for _ in 0..num_elements {
        let val = match &value {
            Some(v) => T::AcvmType::from(*v),
            None => T::AcvmType::from(driver.rand()?),
        };
        fields.push(val);
    }

    Ok(())
}

fn populate_field_elements_for_mock_commitments<
    C: HonkCurve<TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
>(
    fields: &mut Vec<T::AcvmType>,
    num_commitments: usize,
) {
    let mock_commitment = C::Affine::generator();
    let mock_commitment_frs = if mock_commitment.is_zero() {
        let convert = C::convert_basefield_to_scalarfield(&C::BaseField::zero());
        [
            T::AcvmType::from(convert[0]),
            T::AcvmType::from(convert[1]),
            T::AcvmType::from(convert[0]),
            T::AcvmType::from(convert[1]),
        ]
    } else {
        let (x, y) = C::g1_affine_to_xy(&mock_commitment);
        [
            T::AcvmType::from(C::convert_basefield_to_scalarfield(&x)[0]),
            T::AcvmType::from(C::convert_basefield_to_scalarfield(&x)[1]),
            T::AcvmType::from(C::convert_basefield_to_scalarfield(&y)[0]),
            T::AcvmType::from(C::convert_basefield_to_scalarfield(&y)[1]),
        ]
    };

    for _ in 0..num_commitments {
        fields.extend_from_slice(&mock_commitment_frs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcript_ct::Bn254G1;
    use crate::types::types::WitnessOrConstant;
    use ark_bn254::Fr;

    type Builder = GenericUltraCircuitBuilder<Bn254G1, PlainAcvmSolver<Fr>>;
    type Key = RecursiveVerificationKey<Bn254G1, PlainAcvmSolver<Fr>>;

    fn valid_key_fields() -> Vec<FieldCT<Fr>> {
        Builder::create_mock_honk_vk(16, 0)
            .to_field_elements()
            .into_iter()
            .map(FieldCT::from)
            .collect()
    }

    #[test]
    fn recursive_vk_accepts_exact_field_count() {
        let fields = valid_key_fields();
        assert_eq!(fields.len(), ULTRA_VERIFICATION_KEY_LENGTH);
        let mut builder = Builder::new_minimal(0);
        let mut driver = PlainAcvmSolver::default();
        assert!(Key::new(&fields, &mut builder, &mut driver).is_ok());
    }

    #[test]
    fn recursive_vk_rejects_wrong_field_counts() {
        let fields = valid_key_fields();
        for length in [
            0,
            2,
            3,
            fields.len() - 1,
            fields.len() + 1,
            fields.len() + 4,
        ] {
            let mut malformed = fields.clone();
            malformed.resize(length, FieldCT::from(Fr::zero()));
            let result = std::panic::catch_unwind(|| {
                let mut builder = Builder::new_minimal(0);
                let mut driver = PlainAcvmSolver::default();
                Key::new(&malformed, &mut builder, &mut driver).map(|_| ())
            });
            assert!(
                matches!(result, Ok(Err(HonkProofError::InvalidKeyLength))),
                "key with {length} fields"
            );
        }
    }

    fn recursion_constraint(
        builder: &mut Builder,
        key_len: usize,
        proof_len: usize,
        proof_type: ProofType,
    ) -> RecursionConstraint<Fr> {
        let mut witnesses =
            |n: usize| -> Vec<u32> { (0..n).map(|_| builder.add_variable(Fr::zero())).collect() };
        let key = witnesses(key_len);
        let proof = witnesses(proof_len);
        let public_inputs = witnesses(1);
        let key_hash = witnesses(1)[0];
        RecursionConstraint {
            key,
            proof,
            public_inputs,
            key_hash,
            proof_type: proof_type as u32,
            predicate: WitnessOrConstant::from_constant(Fr::one()),
        }
    }

    #[test]
    fn recursion_constraint_rejects_wrong_input_lengths() {
        for (proof_type, proof_len) in [
            (ProofType::Honk, ULTRA_PROOF_LENGTH_WITHOUT_PUB_INPUTS),
            (ProofType::HonkZk, ULTRA_PROOF_LENGTH_WITHOUT_PUB_INPUTS_ZK),
        ] {
            let proof_len = proof_len + PUBLIC_INPUTS_SIZE;
            for (key_len, proof_len) in [
                (ULTRA_VERIFICATION_KEY_LENGTH - 1, proof_len),
                (ULTRA_VERIFICATION_KEY_LENGTH + 1, proof_len),
                (ULTRA_VERIFICATION_KEY_LENGTH, proof_len - 1),
                (ULTRA_VERIFICATION_KEY_LENGTH, proof_len + 1),
            ] {
                let result = std::panic::catch_unwind(|| {
                    let mut builder = Builder::new_minimal(0);
                    let mut driver = PlainAcvmSolver::default();
                    let input = recursion_constraint(&mut builder, key_len, proof_len, proof_type);
                    builder
                        .create_honk_recursion_constraints(
                            &input,
                            &ProverCrs::default(),
                            &mut driver,
                        )
                        .map(|_| ())
                });
                assert!(
                    matches!(result, Ok(Err(_))),
                    "{proof_type:?}: key length {key_len}, proof length {proof_len}"
                );
            }
        }
    }
}

#[cfg(test)]
mod recursion_input_visibility_tests {
    use super::*;
    use crate::transcript_ct::Bn254G1;
    use crate::types::types::WitnessOrConstant;
    use ark_bn254::Fr;
    use co_acvm::{Rep3AcvmSolver, Rep3AcvmType, ShamirAcvmSolver, ShamirAcvmType};
    use mpc_core::protocols::rep3::{conversion::A2BType, share_field_elements};
    use mpc_core::protocols::shamir::{self, ShamirPreprocessing, ShamirState};
    use mpc_net::{Network, local::LocalNetwork};
    use std::sync::Mutex;

    /// A [`Network`] that records every message its party sends.
    struct RecordingNetwork {
        inner: LocalNetwork,
        sent: Mutex<Vec<Vec<u8>>>,
    }

    impl RecordingNetwork {
        fn new(inner: LocalNetwork) -> Self {
            Self {
                inner,
                sent: Mutex::default(),
            }
        }

        fn clear(&self) {
            self.sent.lock().unwrap().clear();
        }

        /// Asserts that this party sent nothing but the visibility setting with tag `tag` to the
        /// two other parties.
        fn assert_sent_only_the_setting(&self, tag: u8) {
            let mut setting = b"co-noir recursion input visibility v1".to_vec();
            setting.push(tag);
            assert_eq!(*self.sent.lock().unwrap(), vec![setting.clone(), setting]);
        }
    }

    impl Network for RecordingNetwork {
        fn id(&self) -> usize {
            self.inner.id()
        }

        fn send(&self, to: usize, data: mpc_net::bytes::Bytes) -> eyre::Result<()> {
            self.sent.lock().unwrap().push(data.to_vec());
            self.inner.send(to, data)
        }

        fn recv(&self, from: usize) -> eyre::Result<mpc_net::bytes::Bytes> {
            self.inner.recv(from)
        }

        fn get_connection_stats(&self) -> mpc_net::ConnectionStats {
            self.inner.get_connection_stats()
        }
    }

    /// A recursion constraint of the right shape in which only the input `role` (0: proof, 1:
    /// key, 2: key hash, 3: inner public input, 4: predicate) is `shared`. Returns the constraint
    /// and the index of the shared witness.
    fn constraint_with_shared_input<T: NoirWitnessExtensionProtocol<Fr>>(
        builder: &mut GenericUltraCircuitBuilder<Bn254G1, T>,
        role: usize,
        shared: T::AcvmType,
        proof_type: ProofType,
    ) -> (RecursionConstraint<Fr>, u32) {
        let indices: Vec<u32> = (0..5)
            .map(|i| {
                builder.add_variable(if i == role {
                    shared.clone()
                } else {
                    T::AcvmType::from(Fr::one())
                })
            })
            .collect();
        let proof_len = PUBLIC_INPUTS_SIZE
            + match proof_type {
                ProofType::Honk => ULTRA_PROOF_LENGTH_WITHOUT_PUB_INPUTS,
                _ => ULTRA_PROOF_LENGTH_WITHOUT_PUB_INPUTS_ZK,
            };
        let input = RecursionConstraint {
            proof: vec![indices[0]; proof_len],
            key: vec![indices[1]; ULTRA_VERIFICATION_KEY_LENGTH],
            key_hash: indices[2],
            public_inputs: vec![indices[3]],
            predicate: WitnessOrConstant::from_index(indices[4]),
            proof_type: proof_type as u32,
        };
        (input, indices[role])
    }

    /// By default, a recursion constraint with any secret-shared input is rejected, and the
    /// parties send each other nothing but the (public) visibility setting.
    fn shared_inputs_are_rejected<T: NoirWitnessExtensionProtocol<Fr>>(
        driver: &mut T,
        net: &RecordingNetwork,
        shared: T::AcvmType,
    ) {
        for proof_type in [ProofType::Honk, ProofType::HonkZk] {
            for role in 0..5 {
                let mut builder = GenericUltraCircuitBuilder::<Bn254G1, T>::new_minimal(0);
                let (input, index) =
                    constraint_with_shared_input(&mut builder, role, shared.clone(), proof_type);
                net.clear();
                let error = builder
                    .create_honk_recursion_constraints(&input, &ProverCrs::default(), driver)
                    .map(|_| ())
                    .expect_err("a secret-shared recursion input must be rejected");
                assert!(
                    error.to_string().contains("secret-shared inputs"),
                    "{proof_type:?}, input {role}: {error}"
                );
                net.assert_sent_only_the_setting(0);
                assert!(T::is_shared(&builder.get_variable(index as usize)));
            }
        }
    }

    #[test]
    fn rep3_shared_recursion_inputs_are_rejected_without_secret_traffic() {
        let shares = share_field_elements(&[Fr::from(101u64)], &mut rand::thread_rng());
        let threads: Vec<_> = LocalNetwork::new_3_parties()
            .into_iter()
            .zip(shares)
            .map(|(net, shares)| {
                std::thread::spawn(move || {
                    let net = RecordingNetwork::new(net);
                    let mut driver =
                        Rep3AcvmSolver::<Fr, _>::new(&net, A2BType::default()).unwrap();
                    shared_inputs_are_rejected(&mut driver, &net, Rep3AcvmType::Shared(shares[0]));
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
    }

    #[test]
    fn shamir_shared_recursion_inputs_are_rejected_without_secret_traffic() {
        let shares = shamir::share_field_element(Fr::from(101u64), 1, 3, &mut rand::thread_rng());
        let threads: Vec<_> = LocalNetwork::new_3_parties()
            .into_iter()
            .zip(shares)
            .map(|(net, share)| {
                std::thread::spawn(move || {
                    let net = RecordingNetwork::new(net);
                    let preprocessing = ShamirPreprocessing::new(3, 1, 0, &net).unwrap();
                    let mut driver =
                        ShamirAcvmSolver::<Fr, _>::new(&net, ShamirState::from(preprocessing));
                    shared_inputs_are_rejected(&mut driver, &net, ShamirAcvmType::Shared(share));
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
    }

    /// With private recursion, secret-shared recursion inputs stay shared and the parties send
    /// each other nothing but the setting. Drivers without support for it (`supported == false`)
    /// fail after that.
    fn private_recursion_keeps_inputs_shared<T: NoirWitnessExtensionProtocol<Fr>>(
        driver: &mut T,
        net: &RecordingNetwork,
        shared: T::AcvmType,
        supported: bool,
    ) {
        for proof_type in [ProofType::Honk, ProofType::HonkZk] {
            for role in 0..5 {
                let mut builder = GenericUltraCircuitBuilder::<Bn254G1, T>::new_minimal(0);
                builder.recursion_input_visibility = RecursionInputVisibility::PrivateRecursion;
                let (input, index) =
                    constraint_with_shared_input(&mut builder, role, shared.clone(), proof_type);
                net.clear();
                let result = builder.prepare_recursion_inputs(&input, driver);
                assert_eq!(result.is_ok(), supported, "{proof_type:?}, input {role}");
                net.assert_sent_only_the_setting(2);
                assert!(T::is_shared(&builder.get_variable(index as usize)));
            }
        }
    }

    #[test]
    fn rep3_private_recursion_keeps_recursion_inputs_shared() {
        let shares = share_field_elements(&[Fr::from(101u64)], &mut rand::thread_rng());
        let threads: Vec<_> = LocalNetwork::new_3_parties()
            .into_iter()
            .zip(shares)
            .map(|(net, shares)| {
                std::thread::spawn(move || {
                    let net = RecordingNetwork::new(net);
                    let mut driver =
                        Rep3AcvmSolver::<Fr, _>::new(&net, A2BType::default()).unwrap();
                    let shared = Rep3AcvmType::Shared(shares[0]);
                    private_recursion_keeps_inputs_shared(&mut driver, &net, shared, true);
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
    }

    #[test]
    fn shamir_rejects_private_recursion_without_secret_traffic() {
        let shares = shamir::share_field_element(Fr::from(101u64), 1, 3, &mut rand::thread_rng());
        let threads: Vec<_> = LocalNetwork::new_3_parties()
            .into_iter()
            .zip(shares)
            .map(|(net, share)| {
                std::thread::spawn(move || {
                    let net = RecordingNetwork::new(net);
                    let preprocessing = ShamirPreprocessing::new(3, 1, 0, &net).unwrap();
                    let mut driver =
                        ShamirAcvmSolver::<Fr, _>::new(&net, ShamirState::from(preprocessing));
                    let shared = ShamirAcvmType::Shared(share);
                    private_recursion_keeps_inputs_shared(&mut driver, &net, shared, false);
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
    }

    #[test]
    fn revealing_opens_exactly_the_recursion_inputs() {
        // proof, key, key hash, public input, (false) predicate, unrelated witness
        let values = [101u64, 103, 107, 109, 0, 113].map(Fr::from);
        let shares = share_field_elements(&values, &mut rand::thread_rng());
        let threads: Vec<_> = LocalNetwork::new_3_parties()
            .into_iter()
            .zip(shares)
            .map(|(net, shares)| {
                std::thread::spawn(move || {
                    let mut driver =
                        Rep3AcvmSolver::<Fr, _>::new(&net, A2BType::default()).unwrap();
                    let mut builder = GenericUltraCircuitBuilder::<Bn254G1, _>::new_minimal(0);
                    builder.recursion_input_visibility =
                        RecursionInputVisibility::RevealToParticipants;
                    let indices: Vec<_> = shares
                        .iter()
                        .map(|share| builder.add_variable(Rep3AcvmType::Shared(*share)))
                        .collect();
                    let input = RecursionConstraint {
                        proof: vec![indices[0]],
                        key: vec![indices[1]],
                        key_hash: indices[2],
                        public_inputs: vec![indices[3]],
                        predicate: WitnessOrConstant::from_index(indices[4]),
                        proof_type: ProofType::Honk as u32,
                    };
                    builder
                        .prepare_recursion_inputs(&input, &mut driver)
                        .unwrap();
                    for (index, value) in indices[..5].iter().zip(&values) {
                        assert_eq!(
                            builder.get_variable(*index as usize),
                            Rep3AcvmType::Public(*value)
                        );
                    }
                    assert_eq!(
                        builder.get_variable(indices[5] as usize),
                        Rep3AcvmType::Shared(shares[5])
                    );
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
    }

    #[test]
    fn revealing_handles_repeated_and_aliased_witnesses() {
        let values = [Fr::from(127u64), Fr::from(131u64)];
        let shares = share_field_elements(&values, &mut rand::thread_rng());
        let threads: Vec<_> = LocalNetwork::new_3_parties()
            .into_iter()
            .zip(shares)
            .map(|(net, shares)| {
                std::thread::spawn(move || {
                    let mut driver =
                        Rep3AcvmSolver::<Fr, _>::new(&net, A2BType::default()).unwrap();
                    let mut builder = GenericUltraCircuitBuilder::<Bn254G1, _>::new_minimal(0);
                    builder.recursion_input_visibility =
                        RecursionInputVisibility::RevealToParticipants;
                    let original = builder.add_variable(Rep3AcvmType::Shared(shares[0]));
                    let alias = builder.add_variable(Rep3AcvmType::Shared(shares[0]));
                    let unrelated = builder.add_variable(Rep3AcvmType::Shared(shares[1]));
                    builder.assert_equal(alias as usize, original as usize);
                    let input = RecursionConstraint {
                        proof: vec![original, alias, original],
                        key: vec![alias, original],
                        key_hash: alias,
                        public_inputs: vec![original, alias],
                        // The index of a constant predicate is not a witness.
                        predicate: WitnessOrConstant::from_constant(Fr::one()),
                        proof_type: ProofType::HonkZk as u32,
                    };
                    builder
                        .prepare_recursion_inputs(&input, &mut driver)
                        .unwrap();
                    for index in [original, alias] {
                        assert_eq!(
                            builder.get_variable(index as usize),
                            Rep3AcvmType::Public(values[0])
                        );
                    }
                    assert_eq!(
                        builder.get_variable(unrelated as usize),
                        Rep3AcvmType::Shared(shares[1])
                    );
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
    }

    /// If one party selects a different setting than the others, all parties fail before any
    /// secret is sent, and the channels stay usable.
    fn different_settings_are_rejected<T: NoirWitnessExtensionProtocol<Fr>>(
        driver: &mut T,
        net: &RecordingNetwork,
        shared: T::AcvmType,
    ) {
        for odd_party in 0..3 {
            for odd_reveals in [false, true] {
                let reveal = (net.id() == odd_party) == odd_reveals;
                let visibility = if reveal {
                    RecursionInputVisibility::RevealToParticipants
                } else {
                    RecursionInputVisibility::KeepSecret
                };
                let mut builder = GenericUltraCircuitBuilder::<Bn254G1, T>::new_minimal(0);
                builder.recursion_input_visibility = visibility;
                let (input, index) = constraint_with_shared_input(
                    &mut builder,
                    0,
                    shared.clone(),
                    ProofType::HonkZk,
                );
                net.clear();
                let error = builder
                    .prepare_recursion_inputs(&input, driver)
                    .unwrap_err();
                assert!(
                    error
                        .to_string()
                        .contains("different recursion input visibilities")
                );
                net.assert_sent_only_the_setting(u8::from(reveal));
                assert!(T::is_shared(&builder.get_variable(index as usize)));
            }
        }
        net.clear();
        driver
            .agree_recursion_input_visibility(RecursionInputVisibility::KeepSecret)
            .unwrap();
        net.assert_sent_only_the_setting(0);
    }

    #[test]
    fn rep3_different_visibility_settings_are_rejected_without_secret_traffic() {
        let shares = share_field_elements(&[Fr::from(101u64)], &mut rand::thread_rng());
        let threads: Vec<_> = LocalNetwork::new_3_parties()
            .into_iter()
            .zip(shares)
            .map(|(net, shares)| {
                std::thread::spawn(move || {
                    let net = RecordingNetwork::new(net);
                    let mut driver =
                        Rep3AcvmSolver::<Fr, _>::new(&net, A2BType::default()).unwrap();
                    different_settings_are_rejected(
                        &mut driver,
                        &net,
                        Rep3AcvmType::Shared(shares[0]),
                    );
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
    }

    #[test]
    fn shamir_different_visibility_settings_are_rejected_without_secret_traffic() {
        let shares = shamir::share_field_element(Fr::from(101u64), 1, 3, &mut rand::thread_rng());
        let threads: Vec<_> = LocalNetwork::new_3_parties()
            .into_iter()
            .zip(shares)
            .map(|(net, share)| {
                std::thread::spawn(move || {
                    let net = RecordingNetwork::new(net);
                    let preprocessing = ShamirPreprocessing::new(3, 1, 0, &net).unwrap();
                    let mut driver =
                        ShamirAcvmSolver::<Fr, _>::new(&net, ShamirState::from(preprocessing));
                    different_settings_are_rejected(
                        &mut driver,
                        &net,
                        ShamirAcvmType::Shared(share),
                    );
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
    }
}

#[cfg(test)]
mod conditional_recursion_tests {
    use super::*;
    use crate::prelude::constraint_system_from_reader;
    use crate::transcript_ct::Bn254G1;
    use crate::types::types::WitnessOrConstant;
    use ark_bn254::{Bn254, Fr};
    use co_noir_common::{crs::parse::CrsParser, keys::verification_key::VerifyingKey};
    use co_ultrahonk::prelude::UltraHonk;

    type Builder = GenericUltraCircuitBuilder<Bn254G1, PlainAcvmSolver<Fr>>;

    fn crs_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../co-noir-common/src/crs")
    }

    /// Finalizes the circuit, proves it with ZK and returns whether the proof verifies, and the
    /// verification key.
    fn prove_and_verify(mut builder: Builder, driver: &mut PlainAcvmSolver<Fr>) -> (bool, Vec<u8>) {
        builder.finalize_circuit(driver).unwrap();
        let (prover_crs, verifier_crs) = CrsParser::<Bn254G1>::get_crs::<Bn254>(
            crs_dir().join("bn254_g1.dat"),
            crs_dir().join("bn254_g2.dat"),
            builder.compute_dyadic_size(),
            ZeroKnowledge::Yes,
        )
        .unwrap()
        .split();
        let (pk, vk): (_, VerifyingKey<Bn254>) = builder
            .create_keys::<Bn254>(prover_crs.into(), verifier_crs, driver)
            .unwrap();
        let vk_bytes = vk.inner_vk.to_buffer();
        let (proof, public_inputs) =
            UltraHonk::<_, Poseidon2Sponge>::prove(pk, ZeroKnowledge::Yes, &vk.inner_vk).unwrap();
        let verified =
            UltraHonk::<_, Poseidon2Sponge>::verify(proof, &public_inputs, &vk, ZeroKnowledge::Yes)
                .unwrap();
        (verified, vk_bytes)
    }

    /// Runs the in-circuit verifier on the given, possibly invalid, inputs. Write-vk mode only
    /// suppresses the host-side checks of witness values in the verifier, so that an invalid
    /// proof gives an unsatisfiable circuit instead of a panic; the inputs are not replaced.
    fn verify_directly(
        builder: &mut Builder,
        driver: &mut PlainAcvmSolver<Fr>,
        input: &RecursionConstraint<Fr>,
        has_zk: ZeroKnowledge,
    ) -> PairingPoints<Bn254G1, PlainAcvmSolver<Fr>> {
        builder.is_write_vk_mode = true;
        let proof_indices =
            create_indices_for_reconstructed_proof(&input.proof, &input.public_inputs);
        let inputs: Vec<_> = input.key.iter().chain(&proof_indices).copied().collect();
        let values_before: Vec<_> = inputs
            .iter()
            .map(|i| builder.get_variable(*i as usize))
            .collect();
        let vk_fields: Vec<_> = input
            .key
            .iter()
            .map(|i| FieldCT::from_witness_index(*i))
            .collect();
        let proof_fields: Vec<_> = proof_indices
            .iter()
            .map(|i| FieldCT::from_witness_index(*i))
            .collect();
        let key = RecursiveDeciderVerificationKey {
            vk_and_hash: VKAndHash {
                vk: RecursiveVerificationKey::new(&vk_fields, builder, driver).unwrap(),
                hash: FieldCT::from_witness_index(input.key_hash),
            },
            _is_complete: false,
            public_inputs: proof_fields[..input.public_inputs.len()].to_vec(),
            relation_parameters: Default::default(),
            target_sum: FieldCT::default(),
            witness_commitments: Default::default(),
            gemini_masking_commitment: None,
            alphas: array::from_fn(|_| FieldCT::default()),
            gate_challenges: Vec::new(),
        };
        let points = UltraRecursiveVerifier::verify_proof::<
            Bn254G1,
            Poseidon2SpongeCT<Bn254G1>,
            PlainAcvmSolver<Fr>,
        >(proof_fields, key, builder, driver, has_zk)
        .unwrap();
        let values_after: Vec<_> = inputs
            .iter()
            .map(|i| builder.get_variable(*i as usize))
            .collect();
        assert_eq!(values_before, values_after);
        builder.is_write_vk_mode = false;
        points
    }

    /// A recursion constraint with a witness predicate accepts an invalid inner proof only if the
    /// predicate is false, and the predicate and the validity of the inner proof do not change
    /// the circuit.
    fn invalid_inner_proof_is_rejected_only_when_enabled(name: &str, has_zk: ZeroKnowledge) {
        let vectors =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test_vectors/noir");
        let kat = vectors.join(name).join("kat");
        let constraint_system = constraint_system_from_reader(
            std::fs::File::open(kat.join(format!("{name}.json"))).unwrap(),
        )
        .unwrap();
        let witness = noir_types::witness_from_reader(
            std::fs::File::open(kat.join(format!("{name}.gz"))).unwrap(),
        )
        .unwrap();
        assert_eq!(constraint_system.honk_recursion_constraints.len(), 1);
        let source = &constraint_system.honk_recursion_constraints[0];
        let recursion_crs = CrsParser::<Bn254G1>::get_crs_g1(
            crs_dir().join("bn254_g1.dat"),
            constraint_system.get_honk_recursion_public_inputs_size::<Bn254G1>(),
            ZeroKnowledge::Yes,
        )
        .unwrap();
        // The first scalar after Oink (for ZK, after the Libra commitment): changing it keeps
        // all points on the curve but makes the inner proof invalid.
        let scalar_index = PUBLIC_INPUTS_SIZE
            + match has_zk {
                ZeroKnowledge::Yes => OINK_PROOF_LENGTH_WITHOUT_PUB_INPUTS_ZK + 4,
                ZeroKnowledge::No => OINK_PROOF_LENGTH_WITHOUT_PUB_INPUTS,
            };
        let mut keys: [Option<Vec<u8>>; 2] = [None, None];
        // (predicate, invalid inner proof, verifier called directly, outer proof verifies)
        for (enabled, invalid, direct, expected) in [
            (true, false, false, true),
            (false, true, false, true),
            (true, false, true, true),
            (true, true, true, false),
        ] {
            let mut builder = Builder::new_minimal(0);
            builder.is_write_vk_mode = false;
            let mut driver = PlainAcvmSolver::<Fr>::new();
            let mut add = |index: &u32| builder.add_variable(witness[*index as usize]);
            let key = source.key.iter().map(&mut add).collect();
            let public_inputs = source.public_inputs.iter().map(&mut add).collect();
            let key_hash = add(&source.key_hash);
            let mut proof: Vec<_> = source.proof.iter().map(|i| witness[*i as usize]).collect();
            if invalid {
                proof[scalar_index] += Fr::one();
            }
            let proof = proof.into_iter().map(|v| builder.add_variable(v)).collect();
            let predicate = WitnessOrConstant::from_index(builder.add_variable(Fr::from(enabled)));
            let input = RecursionConstraint {
                key,
                proof,
                public_inputs,
                key_hash,
                predicate,
                proof_type: source.proof_type,
            };
            let mut points = if direct {
                verify_directly(&mut builder, &mut driver, &input, has_zk)
            } else {
                builder
                    .create_honk_recursion_constraints(&input, &recursion_crs, &mut driver)
                    .unwrap()
            };
            points.set_public(&mut builder, &mut driver).unwrap();
            let (verified, key) = prove_and_verify(builder, &mut driver);
            assert_eq!(
                verified, expected,
                "{name}: enabled {enabled}, invalid {invalid}, direct {direct}"
            );
            match &keys[usize::from(direct)] {
                Some(reference) => assert_eq!(&key, reference, "{name}: the key changed"),
                None => keys[usize::from(direct)] = Some(key),
            }
        }
    }

    #[test]
    #[ignore = "Test is too slow for the pipeline"]
    fn conditional_invalid_inner_proof_is_rejected_only_when_enabled() {
        invalid_inner_proof_is_rejected_only_when_enabled("recursion_private", ZeroKnowledge::No);
    }

    #[test]
    #[ignore = "Test is too slow for the pipeline"]
    fn conditional_invalid_zk_inner_proof_is_rejected_only_when_enabled() {
        invalid_inner_proof_is_rejected_only_when_enabled(
            "recursion_private_zk",
            ZeroKnowledge::Yes,
        );
    }
}

pub(crate) mod delta_range_constraint_relation;
pub(crate) mod elliptic_relation;
pub(crate) mod logderiv_lookup_relation;
pub(crate) mod memory_relation;
pub(crate) mod non_native_field_relation;
pub(crate) mod permutation_relation;
pub(crate) mod poseidon2_external_relation;
pub(crate) mod poseidon2_internal_relation;
pub(crate) mod ultra_arithmetic_relation;

use crate::accumulate_all_relations;
use crate::honk_verifier::sumcheck::SumcheckVerifier;
use crate::honk_verifier::verifier_relations::memory_relation::MemoryRelation;
use crate::honk_verifier::verifier_relations::memory_relation::MemoryRelationEvals;
use crate::honk_verifier::verifier_relations::non_native_field_relation::NonNativeFieldRelation;
use crate::honk_verifier::verifier_relations::non_native_field_relation::NonNativeFieldRelationEvals;
use crate::honk_verifier::verifier_relations::{
    delta_range_constraint_relation::{
        DeltaRangeConstraintRelation, DeltaRangeConstraintRelationEvals,
    },
    elliptic_relation::{EllipticRelation, EllipticRelationEvals},
    logderiv_lookup_relation::{LogDerivLookupRelation, LogDerivLookupRelationEvals},
    permutation_relation::{UltraPermutationRelation, UltraPermutationRelationEvals},
    poseidon2_external_relation::{Poseidon2ExternalRelation, Poseidon2ExternalRelationEvals},
    poseidon2_internal_relation::{Poseidon2InternalRelation, Poseidon2InternalRelationEvals},
    ultra_arithmetic_relation::{UltraArithmeticRelation, UltraArithmeticRelationEvals},
};
use crate::prelude::GenericUltraCircuitBuilder;
use crate::scale_and_batch_all;
use crate::types::field_ct::FieldCT;
use crate::types::gate_separator::GateSeparatorPolynomial;
use ark_ff::AdditiveGroup;
use ark_ff::Field;
use ark_ff::PrimeField;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_noir_common::honk_proof::TranscriptFieldType;
use co_noir_common::polynomials::entities::AllEntities;
use co_noir_common::types::RelationParameters;
use co_noir_common::{honk_curve::HonkCurve, honk_proof::HonkProofResult};

#[derive(Default)]
pub struct AllRelationsEvals<F: PrimeField> {
    r_arith: UltraArithmeticRelationEvals<F>,
    r_perm: UltraPermutationRelationEvals<F>,
    r_lookup: LogDerivLookupRelationEvals<F>,
    r_delta: DeltaRangeConstraintRelationEvals<F>,
    r_elliptic: EllipticRelationEvals<F>,
    r_memory: MemoryRelationEvals<F>,
    r_nnf: NonNativeFieldRelationEvals<F>,
    r_pos_ext: Poseidon2ExternalRelationEvals<F>,
    r_pos_int: Poseidon2InternalRelationEvals<F>,
}

// The order of the relations matches the Ultra flavor's relation tuple in barretenberg
// (Permutation, LogDerivLookup, Arithmetic, DeltaRangeConstraint, Elliptic, Memory,
// NonNativeField, Poseidon2External, Poseidon2Internal), which determines the
// alpha-power-to-subrelation assignment.
pub(crate) const NUM_SUBRELATIONS: usize = UltraPermutationRelation::NUM_RELATIONS
    + LogDerivLookupRelation::NUM_RELATIONS
    + UltraArithmeticRelation::NUM_RELATIONS
    + DeltaRangeConstraintRelation::NUM_RELATIONS
    + EllipticRelation::NUM_RELATIONS
    + MemoryRelation::NUM_RELATIONS
    + NonNativeFieldRelation::NUM_RELATIONS
    + Poseidon2ExternalRelation::NUM_RELATIONS
    + Poseidon2InternalRelation::NUM_RELATIONS;

// Aztec v6 Ultra flavor: 31 subrelations. A change in any relation's subrelation count re-slices
// every subsequent relation's alpha powers; fail at compile time rather than mis-batching silently.
const _: () = assert!(NUM_SUBRELATIONS == 31);

pub(crate) trait VerifyAccGetter<C: HonkCurve<TranscriptFieldType>> {
    fn get_accumulators(&self) -> Vec<FieldCT<C::ScalarField>>;
    fn scale_by_challenge_and_accumulate<T: NoirWitnessExtensionProtocol<C::ScalarField>>(
        &self,
        result: &mut FieldCT<C::ScalarField>,
        challenges: &[FieldCT<C::ScalarField>],
        row_disabling_factor: Option<&FieldCT<C::ScalarField>>,
        builder: &mut GenericUltraCircuitBuilder<C, T>,
        driver: &mut T,
    ) -> HonkProofResult<()> {
        // The row-disabling factor (ZK only) is folded in PER SUBRELATION, `entry × α × rd`,
        // mirroring bb's scale_and_batch_elements — algebraically the same as one post-multiply
        // of the batched total, but the per-element form is what bb's recursive verifier emits
        // as gates.
        for (entry, challenge) in self.get_accumulators().iter().zip(challenges) {
            if challenge.is_constant()
                && challenge.get_value(builder, driver) == C::ScalarField::ONE.into()
            {
                *result = match row_disabling_factor {
                    Some(rd) => entry.multiply(rd, builder, driver)?,
                    None => entry.clone(),
                };
                continue;
            }
            let mut tmp = entry.multiply(challenge, builder, driver)?;
            if let Some(rd) = row_disabling_factor {
                tmp = tmp.multiply(rd, builder, driver)?;
            }
            result.add_assign(&tmp, builder, driver);
        }
        Ok(())
    }
}

pub(crate) trait Relation<C: HonkCurve<TranscriptFieldType>> {
    type VerifyAcc: Default + VerifyAccGetter<C> + Send + Sync;
    fn accumulate_evaluations<T: NoirWitnessExtensionProtocol<C::ScalarField>>(
        _univariate_accumulator: &mut Self::VerifyAcc,
        _input: &AllEntities<FieldCT<C::ScalarField>, FieldCT<C::ScalarField>>,
        _relation_parameters: &RelationParameters<FieldCT<C::ScalarField>>,
        _scaling_factor: &FieldCT<C::ScalarField>,
        _builder: &mut GenericUltraCircuitBuilder<C, T>,
        _driver: &mut T,
    ) -> HonkProofResult<()> {
        panic!("accumulate_evaluations is not implemented for this relation");
    }
}

#[expect(clippy::too_many_arguments)]
pub(crate) fn compute_full_relation_purported_value<
    C: HonkCurve<TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
>(
    purported_evaluations: &AllEntities<FieldCT<C::ScalarField>, FieldCT<C::ScalarField>>,
    univariate_accumulators: &mut AllRelationsEvals<C::ScalarField>,
    relation_parameters: &RelationParameters<FieldCT<C::ScalarField>>,
    gate_separators: GateSeparatorPolynomial<C>,
    alphas: &[FieldCT<C::ScalarField>],
    // ZK only: the full sumcheck challenge, used to evaluate the row-disabling polynomial. The
    // factor must be computed HERE, between relation accumulation and batching, and applied per
    // subrelation — bb's gate-emission order, which VK byte-parity depends on.
    row_disabling_challenge: Option<&[FieldCT<C::ScalarField>]>,
    builder: &mut GenericUltraCircuitBuilder<C, T>,
    driver: &mut T,
) -> HonkProofResult<FieldCT<C::ScalarField>> {
    accumulate_all_relations!(
        univariate_accumulators,
        purported_evaluations,
        relation_parameters,
        &gate_separators.partial_evaluation_result,
        builder,
        driver
    )?;

    let row_disabling_factor = match row_disabling_challenge {
        Some(challenge) => Some(SumcheckVerifier::evaluate_at_challenge(
            challenge, builder, driver,
        )?),
        None => None,
    };

    let mut output = FieldCT::from(C::ScalarField::ZERO);
    let first_scalar = FieldCT::from(C::ScalarField::ONE);
    scale_and_batch_all!(
        &mut output,
        &univariate_accumulators,
        first_scalar,
        row_disabling_factor.as_ref(),
        alphas,
        builder,
        driver
    )?;

    Ok(output)
}

#[macro_export]
macro_rules! accumulate_all_relations {
    ($univariate_accumulators:expr, $input:expr, $relation_parameters:expr, $scaling_factor:expr, $builder:expr, $driver:expr) => {{
        // Helper macro to process each relation
        macro_rules! process_relation {
            ($relation:ident, $relation_accumulator:ident) => {
                $relation::accumulate_evaluations(
                    &mut $univariate_accumulators.$relation_accumulator,
                    $input,
                    $relation_parameters,
                    $scaling_factor,
                    $builder,
                    $driver,
                )?;
            };
        }

        // Apply to all relations
        process_relation!(UltraPermutationRelation, r_perm);
        process_relation!(LogDerivLookupRelation, r_lookup);
        process_relation!(UltraArithmeticRelation, r_arith);
        process_relation!(DeltaRangeConstraintRelation, r_delta);
        process_relation!(EllipticRelation, r_elliptic);
        process_relation!(MemoryRelation, r_memory);
        process_relation!(NonNativeFieldRelation, r_nnf);
        process_relation!(Poseidon2ExternalRelation, r_pos_ext);
        process_relation!(Poseidon2InternalRelation, r_pos_int);

        HonkProofResult::Ok(())
    }};
}

#[macro_export]
macro_rules! scale_and_batch_all {
    ($output:expr, $univariate_accumulators:expr, $first_scalar:expr, $row_disabling_factor:expr, $challenges:ident, $builder:expr, $driver:expr) => {{
        let row_disabling_factor = $row_disabling_factor;
        // Helper macro to process each relation
        macro_rules! process_relation {
            ($relation_accumulator:ident, $relevant_challenges:expr) => {
                $univariate_accumulators
                    .$relation_accumulator
                    .scale_by_challenge_and_accumulate(
                        $output,
                        $relevant_challenges,
                        row_disabling_factor,
                        $builder,
                        $driver,
                    )?;
            };
        }

        // Apply to all relations
        process_relation!(
            r_perm,
            &[
                $first_scalar,
                $challenges[0].clone(),
                $challenges[1].clone()
            ]
        );
        process_relation!(r_lookup, &$challenges[2..5]);
        process_relation!(r_arith, &$challenges[5..7]);
        process_relation!(r_delta, &$challenges[7..11]);
        process_relation!(r_elliptic, &$challenges[11..13]);
        process_relation!(r_memory, &$challenges[13..21]);
        process_relation!(r_nnf, &$challenges[21..22]);
        process_relation!(r_pos_ext, &$challenges[22..26]);
        process_relation!(r_pos_int, &$challenges[26..]);

        HonkProofResult::Ok(())
    }};
}

#[macro_export]
macro_rules! impl_relation_evals {
    ($struct_name:ident, $($field_name:ident),*) => {
        impl<F: PrimeField> Default
            for $struct_name<F>
        {
            fn default() -> Self {
                Self {
                    $($field_name: Default::default(),)*
                }
            }
        }

        impl<C: HonkCurve<TranscriptFieldType>> VerifyAccGetter<C>
            for $struct_name<C::ScalarField>
        {
            fn get_accumulators(&self) -> Vec<FieldCT<C::ScalarField>> {
                vec![
                    $(self.$field_name.clone(),)*
                ]
            }
        }
    }
}

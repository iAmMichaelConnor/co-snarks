use ark_ec::{CurveGroup, PrimeGroup};
use rayon::prelude::*;
use co_noir_common::{
    honk_curve::HonkCurve,
    honk_proof::TranscriptFieldType,
    mpc::NoirUltraHonkProver,
    polynomials::entities::{
        AllEntities, PrecomputedEntities, ShiftedWitnessEntities, WitnessEntities,
    },
};
use ultrahonk::prelude::Univariate;

pub(crate) type WitnessEntitiesBatch<T> = WitnessEntities<Vec<T>>;
pub(crate) type PrecomputedEntitiesBatch<T> = PrecomputedEntities<Vec<T>>;
pub(crate) type ShiftedWitnessEntitiesBatch<T> = ShiftedWitnessEntities<Vec<T>>;

use crate::co_decider::{
    relations::{
        Relation as _, delta_range_constraint_relation::DeltaRangeConstraintRelation,
        elliptic_relation::EllipticRelation, logderiv_lookup_relation::LogDerivLookupRelation,
        memory_relation::MemoryRelation, non_native_field_relation::NonNativeFieldRelation,
        permutation_relation::UltraPermutationRelation,
        poseidon2_external_relation::Poseidon2ExternalRelation,
        poseidon2_internal_relation::Poseidon2InternalRelation,
        ultra_arithmetic_relation::UltraArithmeticRelation,
    },
    univariates::SharedUnivariate,
};
use co_noir_common::constants::MAX_PARTIAL_RELATION_LENGTH;

type Shared<T, P> = SharedUnivariate<T, P, MAX_PARTIAL_RELATION_LENGTH>;
type Public<P> = Univariate<<P as PrimeGroup>::ScalarField, MAX_PARTIAL_RELATION_LENGTH>;

#[derive(Default)]
pub(crate) struct AllEntitiesBatch<T, P>
where
    T: NoirUltraHonkProver<P>,
    P: CurveGroup,
{
    pub(crate) witness: WitnessEntitiesBatch<T::ArithmeticShare>,
    pub(crate) precomputed: PrecomputedEntitiesBatch<P::ScalarField>,
    pub(crate) shifted_witness: ShiftedWitnessEntitiesBatch<T::ArithmeticShare>,
}

#[derive(Default)]
pub(crate) struct SumCheckDataForRelation<T, P>
where
    T: NoirUltraHonkProver<P>,
    P: CurveGroup,
{
    pub(crate) can_skip: bool,
    pub(crate) all_entities: AllEntitiesBatch<T, P>,
    pub(crate) scaling_factors: Vec<P::ScalarField>,
}

#[derive(Default)]
pub(crate) struct AllEntitiesBatchRelations<T, P>
where
    T: NoirUltraHonkProver<P>,
    P: CurveGroup,
{
    pub(crate) ultra_arith: SumCheckDataForRelation<T, P>,
    pub(crate) ultra_perm: SumCheckDataForRelation<T, P>,
    pub(crate) delta_range: SumCheckDataForRelation<T, P>,
    pub(crate) elliptic: SumCheckDataForRelation<T, P>,
    pub(crate) memory: SumCheckDataForRelation<T, P>,
    pub(crate) nnf: SumCheckDataForRelation<T, P>,
    pub(crate) log_lookup: SumCheckDataForRelation<T, P>,
    pub(crate) poseidon_ext: SumCheckDataForRelation<T, P>,
    pub(crate) poseidon_int: SumCheckDataForRelation<T, P>,
}

impl<T, P> SumCheckDataForRelation<T, P>
where
    T: NoirUltraHonkProver<P>,
    P: CurveGroup,
{
    fn new() -> Self {
        Self {
            can_skip: true,
            all_entities: AllEntitiesBatch::new(),
            scaling_factors: vec![],
        }
    }

    /// Concatenate per-chunk relation data in chunk order. The result is exactly what a single
    /// sequential pass over the same edges (in the same order) would have produced: `Vec::append`
    /// preserves element order, and `can_skip` stays true only if every chunk was skippable.
    fn concat(parts: Vec<Self>) -> Self {
        let mut parts = parts.into_iter();
        let Some(mut out) = parts.next() else {
            return Self::new();
        };
        for mut part in parts {
            out.can_skip &= part.can_skip;
            for (des, src) in out
                .all_entities
                .witness
                .iter_mut()
                .zip(part.all_entities.witness.iter_mut())
            {
                des.append(src);
            }
            for (des, src) in out
                .all_entities
                .precomputed
                .iter_mut()
                .zip(part.all_entities.precomputed.iter_mut())
            {
                des.append(src);
            }
            for (des, src) in out
                .all_entities
                .shifted_witness
                .iter_mut()
                .zip(part.all_entities.shifted_witness.iter_mut())
            {
                des.append(src);
            }
            out.scaling_factors.append(&mut part.scaling_factors);
        }
        out
    }
}

impl<T, P> AllEntitiesBatchRelations<T, P>
where
    P: HonkCurve<TranscriptFieldType>,
    T: NoirUltraHonkProver<P>,
{
    pub fn new() -> Self {
        Self {
            ultra_arith: SumCheckDataForRelation::new(),
            ultra_perm: SumCheckDataForRelation::new(),
            delta_range: SumCheckDataForRelation::new(),
            log_lookup: SumCheckDataForRelation::new(),
            elliptic: SumCheckDataForRelation::new(),
            memory: SumCheckDataForRelation::new(),
            nnf: SumCheckDataForRelation::new(),
            poseidon_ext: SumCheckDataForRelation::new(),
            poseidon_int: SumCheckDataForRelation::new(),
        }
    }

    /// Concatenate per-chunk batches in chunk order, yielding the same batch a sequential pass
    /// over all edges would have built (same operand order, same lengths, same skip flags) —
    /// independent of how many chunks/threads produced the parts. The nine relations are merged
    /// in parallel; within a relation the merge is a sequential, order-preserving append.
    pub fn concat(parts: Vec<Self>) -> Self {
        const NUM_RELATION_BATCHES: usize = 9;
        let mut per_relation: [Vec<SumCheckDataForRelation<T, P>>; NUM_RELATION_BATCHES] =
            std::array::from_fn(|_| Vec::with_capacity(parts.len()));
        for part in parts {
            let Self {
                ultra_arith,
                ultra_perm,
                delta_range,
                elliptic,
                memory,
                nnf,
                log_lookup,
                poseidon_ext,
                poseidon_int,
            } = part;
            per_relation[0].push(ultra_arith);
            per_relation[1].push(ultra_perm);
            per_relation[2].push(delta_range);
            per_relation[3].push(elliptic);
            per_relation[4].push(memory);
            per_relation[5].push(nnf);
            per_relation[6].push(log_lookup);
            per_relation[7].push(poseidon_ext);
            per_relation[8].push(poseidon_int);
        }
        let mut merged: Vec<SumCheckDataForRelation<T, P>> = per_relation
            .into_par_iter()
            .map(SumCheckDataForRelation::concat)
            .collect();
        // collect() preserves order; pop in reverse field order.
        let poseidon_int = merged.pop().expect("nine merged relation batches");
        let poseidon_ext = merged.pop().expect("nine merged relation batches");
        let log_lookup = merged.pop().expect("nine merged relation batches");
        let nnf = merged.pop().expect("nine merged relation batches");
        let memory = merged.pop().expect("nine merged relation batches");
        let elliptic = merged.pop().expect("nine merged relation batches");
        let delta_range = merged.pop().expect("nine merged relation batches");
        let ultra_perm = merged.pop().expect("nine merged relation batches");
        let ultra_arith = merged.pop().expect("nine merged relation batches");
        Self {
            ultra_arith,
            ultra_perm,
            delta_range,
            elliptic,
            memory,
            nnf,
            log_lookup,
            poseidon_ext,
            poseidon_int,
        }
    }

    pub fn fold_and_filter(
        &mut self,
        entity: AllEntities<Shared<T, P>, Public<P>>,
        scaling_factor: P::ScalarField,
    ) {
        // 0xThemis TODO - for all (?) accumulator we don't need all 7 elements. Can we remove
        // somehow skip those to decrease work even further?
        // e.g. UltraArith only has
        //
        // pub(crate) r0: SharedUnivariate<T, P, 6>,
        // pub(crate) r1: SharedUnivariate<T, P, 5>,
        //
        // Can we somehow only add 5/6 elements?

        UltraArithmeticRelation::add_edge(&entity, scaling_factor, &mut self.ultra_arith);
        UltraPermutationRelation::add_edge(&entity, scaling_factor, &mut self.ultra_perm);
        DeltaRangeConstraintRelation::add_edge(&entity, scaling_factor, &mut self.delta_range);

        EllipticRelation::add_edge(&entity, scaling_factor, &mut self.elliptic);
        MemoryRelation::add_edge(&entity, scaling_factor, &mut self.memory);
        NonNativeFieldRelation::add_edge(&entity, scaling_factor, &mut self.nnf);
        LogDerivLookupRelation::add_edge(&entity, scaling_factor, &mut self.log_lookup);

        Poseidon2ExternalRelation::add_edge(&entity, scaling_factor, &mut self.poseidon_ext);
        Poseidon2InternalRelation::add_edge(&entity, scaling_factor, &mut self.poseidon_int);
    }
}

impl<T, P> AllEntitiesBatch<T, P>
where
    P: CurveGroup,
    T: NoirUltraHonkProver<P>,
{
    pub fn new() -> Self {
        let witness = WitnessEntitiesBatch::<T::ArithmeticShare>::new();
        let precomputed = PrecomputedEntitiesBatch::<P::ScalarField>::new();
        let shifted_witness = ShiftedWitnessEntitiesBatch::<T::ArithmeticShare>::new();
        Self {
            witness,
            precomputed,
            shifted_witness,
        }
    }

    pub fn add_w_l(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.witness
            .w_l_mut()
            .extend(entity.witness.w_l().evaluations)
    }

    pub fn add_w_r(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.witness
            .w_r_mut()
            .extend(entity.witness.w_r().evaluations)
    }

    pub fn add_w_o(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.witness
            .w_o_mut()
            .extend(entity.witness.w_o().evaluations)
    }

    pub fn add_w_4(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.witness
            .w_4_mut()
            .extend(entity.witness.w_4().evaluations)
    }

    pub fn add_z_perm(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.witness
            .z_perm_mut()
            .extend(entity.witness.z_perm().evaluations)
    }

    pub fn add_lookup_read_tags(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.witness
            .lookup_read_tags_mut()
            .extend(entity.witness.lookup_read_tags().evaluations)
    }

    pub fn add_lookup_inverses(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.witness
            .lookup_inverses_mut()
            .extend(entity.witness.lookup_inverses().evaluations)
    }

    pub fn add_lookup_read_counts(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.witness
            .lookup_read_counts_mut()
            .extend(entity.witness.lookup_read_counts().evaluations)
    }

    pub fn add_q_m(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .q_m_mut()
            .extend(entity.precomputed.q_m().evaluations)
    }

    pub fn add_q_l(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .q_l_mut()
            .extend(entity.precomputed.q_l().evaluations)
    }

    pub fn add_q_r(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .q_r_mut()
            .extend(entity.precomputed.q_r().evaluations)
    }

    pub fn add_q_o(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .q_o_mut()
            .extend(entity.precomputed.q_o().evaluations)
    }

    pub fn add_q_4(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .q_4_mut()
            .extend(entity.precomputed.q_4().evaluations)
    }

    pub fn add_q_c(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .q_c_mut()
            .extend(entity.precomputed.q_c().evaluations)
    }

    pub fn add_table_1(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .table_1_mut()
            .extend(entity.precomputed.table_1().evaluations)
    }

    pub fn add_table_2(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .table_2_mut()
            .extend(entity.precomputed.table_2().evaluations)
    }
    pub fn add_table_3(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .table_3_mut()
            .extend(entity.precomputed.table_3().evaluations)
    }
    pub fn add_table_4(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .table_4_mut()
            .extend(entity.precomputed.table_4().evaluations)
    }

    pub fn add_sigma_1(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .sigma_1_mut()
            .extend(entity.precomputed.sigma_1().evaluations)
    }

    pub fn add_sigma_2(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .sigma_2_mut()
            .extend(entity.precomputed.sigma_2().evaluations)
    }
    pub fn add_sigma_3(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .sigma_3_mut()
            .extend(entity.precomputed.sigma_3().evaluations)
    }
    pub fn add_sigma_4(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .sigma_4_mut()
            .extend(entity.precomputed.sigma_4().evaluations)
    }

    pub fn add_id_1(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .id_1_mut()
            .extend(entity.precomputed.id_1().evaluations)
    }

    pub fn add_id_2(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .id_2_mut()
            .extend(entity.precomputed.id_2().evaluations)
    }
    pub fn add_id_3(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .id_3_mut()
            .extend(entity.precomputed.id_3().evaluations)
    }
    pub fn add_id_4(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .id_4_mut()
            .extend(entity.precomputed.id_4().evaluations)
    }

    pub fn add_q_arith(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .q_arith_mut()
            .extend(entity.precomputed.q_arith().evaluations)
    }

    pub fn add_q_memory(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .q_memory_mut()
            .extend(entity.precomputed.q_memory().evaluations)
    }

    pub fn add_q_nnf(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .q_nnf_mut()
            .extend(entity.precomputed.q_nnf().evaluations)
    }

    pub fn add_q_delta_range(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .q_delta_range_mut()
            .extend(entity.precomputed.q_delta_range().evaluations)
    }

    pub fn add_q_elliptic(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .q_elliptic_mut()
            .extend(entity.precomputed.q_elliptic().evaluations)
    }

    pub fn add_q_lookup(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .q_lookup_mut()
            .extend(entity.precomputed.q_lookup().evaluations)
    }

    pub fn add_q_poseidon2_external(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .q_poseidon2_external_mut()
            .extend(entity.precomputed.q_poseidon2_external().evaluations)
    }

    pub fn add_q_poseidon2_internal(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .q_poseidon2_internal_mut()
            .extend(entity.precomputed.q_poseidon2_internal().evaluations)
    }

    pub fn add_lagrange_last(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .lagrange_last_mut()
            .extend(entity.precomputed.lagrange_last().evaluations)
    }

    pub fn add_lagrange_first(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.precomputed
            .lagrange_first_mut()
            .extend(entity.precomputed.lagrange_first().evaluations)
    }

    pub fn add_shifted_w_l(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.shifted_witness
            .w_l_mut()
            .extend(entity.shifted_witness.w_l().evaluations)
    }

    pub fn add_shifted_w_r(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.shifted_witness
            .w_r_mut()
            .extend(entity.shifted_witness.w_r().evaluations)
    }

    pub fn add_shifted_w_o(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.shifted_witness
            .w_o_mut()
            .extend(entity.shifted_witness.w_o().evaluations)
    }

    pub fn add_shifted_w_4(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.shifted_witness
            .w_4_mut()
            .extend(entity.shifted_witness.w_4().evaluations)
    }

    pub fn add_shifted_z_perm(&mut self, entity: &AllEntities<Shared<T, P>, Public<P>>) {
        self.shifted_witness
            .z_perm_mut()
            .extend(entity.shifted_witness.z_perm().evaluations)
    }
}

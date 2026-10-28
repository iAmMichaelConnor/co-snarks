use crate::{
    NUM_LIBRA_COMMITMENTS, Utils,
    decider::{shplemini::shplemini_verifier::ShpleminiZkData, types::VerifierMemory},
    ultra_verifier::HonkVerifyResult,
};
use co_noir_common::constants::{
    BATCHED_RELATION_PARTIAL_LENGTH, BATCHED_RELATION_PARTIAL_LENGTH_ZK,
};

use ark_ec::{AffineRepr, pairing::Pairing};
use ark_ff::{One, UniformRand, Zero};
use co_noir_common::{
    constants::PAIRING_POINT_ACCUMULATOR_SIZE,
    honk_curve::HonkCurve,
    honk_proof::{HonkProofError, TranscriptFieldType},
    shplemini::ShpleminiVerifierOpeningClaim,
    transcript::{Transcript, TranscriptHasher},
    types::ZeroKnowledge,
};
use std::marker::PhantomData;

pub(crate) struct DeciderVerifier<
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
> {
    pub(super) memory: VerifierMemory<P>,
    phantom_data: PhantomData<(P, H)>,
}

impl<C: HonkCurve<TranscriptFieldType>, H: TranscriptHasher<TranscriptFieldType>>
    DeciderVerifier<C, H>
{
    pub(crate) fn new(memory: VerifierMemory<C>) -> Self {
        Self {
            memory,
            phantom_data: PhantomData,
        }
    }

    pub(crate) fn reduce_verify_shplemini(
        opening_pair: &mut ShpleminiVerifierOpeningClaim<C>,
        mut transcript: Transcript<TranscriptFieldType, H>,
    ) -> HonkVerifyResult<(C::Affine, C::Affine)> {
        tracing::trace!("Reduce and verify opening pair");

        let quotient_commitment = transcript.receive_point_from_prover::<C>("KZG:W".to_string())?;
        opening_pair.commitments.push(quotient_commitment);
        opening_pair.scalars.push(opening_pair.challenge);
        let p_1 = -quotient_commitment.into_group();
        let p_0 = Utils::msm::<C>(&opening_pair.scalars, &opening_pair.commitments)?;

        Ok((p_0.into(), p_1.into()))
    }

    /// Reconstruct a single BN254 G1 pairing point from its
    /// `2 * NUM_BASEFIELD_ELEMENTS` public-input limbs. Mirrors bb's
    /// `FrCodec::deserialize_from_fields` for a bn254 commitment
    /// (`field_conversion.hpp`): all-zero limbs decode to the point at infinity;
    /// otherwise the x and y coordinates are recombined from their limb pairs
    /// (with the same canonical-encoding checks bb applies in every build) and
    /// the point is validated on-curve.
    fn reconstruct_pairing_point(limbs: &[TranscriptFieldType]) -> HonkVerifyResult<C::Affine> {
        let coord_limbs = C::NUM_BASEFIELD_ELEMENTS;
        debug_assert_eq!(limbs.len(), 2 * coord_limbs);

        // Only the canonical all-zero representation is treated as infinity; this
        // is checked BEFORE recombination so an aliased encoding cannot pose as it.
        if limbs.iter().all(|l| l.is_zero()) {
            return Ok(C::Affine::zero());
        }

        let (x_limbs, y_limbs) = limbs.split_at(coord_limbs);
        C::validate_basefield_limbs(x_limbs)?;
        C::validate_basefield_limbs(y_limbs)?;
        let x = C::convert_basefield_back(x_limbs);
        let y = C::convert_basefield_back(y_limbs);
        Ok(C::g1_affine_from_xy_checked(x, y)?)
    }

    /// Reconstruct the pairing-point accumulator carried in the last
    /// `PAIRING_POINT_ACCUMULATOR_SIZE` public inputs. Mirrors bb's
    /// `DefaultIO::reconstruct_from_public` (`special_public_inputs.hpp`): the
    /// accumulator occupies the tail of the public-inputs vector, split into two
    /// G1 points (P0 then P1).
    fn reconstruct_accumulator(
        public_inputs: &[C::ScalarField],
    ) -> HonkVerifyResult<(C::Affine, C::Affine)> {
        let size = PAIRING_POINT_ACCUMULATOR_SIZE as usize;
        if public_inputs.len() < size {
            return Err(HonkProofError::CorruptedKey.into());
        }
        // The accumulator limbs are public inputs in the transcript (destination)
        // field. For the outer BN254 verifier `ScalarField == TranscriptFieldType`,
        // so this conversion is the identity, but route through the curve's own
        // scalar-field serializer to keep the reconstruction type-correct.
        let acc: Vec<TranscriptFieldType> = public_inputs[public_inputs.len() - size..]
            .iter()
            .flat_map(C::convert_scalarfield_into)
            .collect();
        if acc.len() != size {
            return Err(HonkProofError::CorruptedKey.into());
        }
        let (p0_limbs, p1_limbs) = acc.split_at(size / 2);
        let p0 = Self::reconstruct_pairing_point(p0_limbs)?;
        let p1 = Self::reconstruct_pairing_point(p1_limbs)?;
        Ok((p0, p1))
    }

    /// Aggregate the PCS pairing points into the public-input accumulator,
    /// mirroring bb's `PairingPoints::aggregate` (`pairing_points.hpp`). A
    /// fully-default (both-infinity) accumulator is uninitialized and simply
    /// adopts the PCS points (the non-recursive case, so the aggregate equals the
    /// PCS points and matches the pre-existing behaviour); a fully-populated
    /// accumulator is combined with the PCS points via a random separator so the
    /// pairing check binds BOTH sets of points. A mixed-infinity accumulator, or
    /// PCS points at infinity, is a corrupt/invalid state and is rejected.
    fn aggregate_pairing_points(
        acc: (C::Affine, C::Affine),
        pcs: (C::Affine, C::Affine),
    ) -> HonkVerifyResult<(C::Affine, C::Affine)> {
        let acc_p0_inf = acc.0.is_zero();
        let acc_p1_inf = acc.1.is_zero();

        // The incoming PCS points are always the output of an actual PCS
        // verification, so they must be fully populated (neither at infinity).
        if pcs.0.is_zero() || pcs.1.is_zero() {
            return Err(eyre::eyre!(
                "Cannot aggregate: PCS pairing points are at infinity."
            ));
        }
        // A mixed-infinity accumulator (exactly one point at infinity) is a
        // corrupted state and must never be silently treated as uninitialized,
        // otherwise a real accumulator point would be discarded.
        if acc_p0_inf != acc_p1_inf {
            return Err(eyre::eyre!(
                "Cannot aggregate: accumulator pairing points are mixed-infinity (corrupted state)."
            ));
        }
        // Only a fully-default accumulator is uninitialized: adopt the PCS points.
        if acc_p0_inf && acc_p1_inf {
            return Ok(pcs);
        }
        // Otherwise take a random linear combination, binding both point sets.
        let mut rng = rand::thread_rng();
        let separator = C::ScalarField::rand(&mut rng);
        let p0 = (acc.0.into_group() + pcs.0 * separator).into();
        let p1 = (acc.1.into_group() + pcs.1 * separator).into();
        Ok((p0, p1))
    }

    pub fn pairing_check<P: Pairing<G1 = C, G1Affine = C::Affine>>(
        p0: C::Affine,
        p1: C::Affine,
        g2_x: P::G2Affine,
        g2_gen: P::G2Affine,
    ) -> bool {
        tracing::trace!("Pairing check");
        let p = [g2_gen, g2_x];
        let g1_prepared = [P::G1Prepared::from(p0), P::G1Prepared::from(p1)];
        P::multi_pairing(g1_prepared, p).0 == P::TargetField::one()
    }

    pub(crate) fn verify<P: Pairing<G1 = C, G1Affine = C::Affine>>(
        mut self,
        crs: &P::G2Affine,
        mut transcript: Transcript<TranscriptFieldType, H>,
        has_zk: ZeroKnowledge,
        virtual_log_n: usize,
        public_inputs: &[C::ScalarField],
    ) -> HonkVerifyResult<bool> {
        tracing::trace!("Decider verification");

        let (sumcheck_output, libra_commitments) = if has_zk == ZeroKnowledge::Yes {
            let mut libra_commitments = Vec::with_capacity(NUM_LIBRA_COMMITMENTS);

            libra_commitments
                .push(transcript.receive_point_from_prover::<C>(
                    "Libra:concatenation_commitment".to_string(),
                )?);

            let sumcheck_output = self.sumcheck_verify::<BATCHED_RELATION_PARTIAL_LENGTH_ZK>(
                &mut transcript,
                has_zk,
                virtual_log_n,
            )?;
            if !sumcheck_output.verified {
                tracing::trace!("Sumcheck failed");
                return Ok(false);
            }

            libra_commitments.push(
                transcript
                    .receive_point_from_prover::<C>("Libra:grand_sum_commitment".to_string())?,
            );
            libra_commitments.push(
                transcript
                    .receive_point_from_prover::<C>("Libra:quotient_commitment".to_string())?,
            );

            (sumcheck_output, Some(libra_commitments))
        } else {
            let sumcheck_output = self.sumcheck_verify::<BATCHED_RELATION_PARTIAL_LENGTH>(
                &mut transcript,
                has_zk,
                virtual_log_n,
            )?;
            if !sumcheck_output.verified {
                tracing::trace!("Sumcheck failed");
                return Ok(false);
            }

            (sumcheck_output, None)
        };

        let mut consistency_checked = true;
        let mut opening_claim = self.compute_batch_opening_claim(
            sumcheck_output.multivariate_challenge,
            &mut transcript,
            ShpleminiZkData {
                libra_commitments,
                libra_univariate_evaluation: sumcheck_output.claimed_libra_evaluation,
                gemini_masking_evaluation: sumcheck_output.claimed_gemini_masking_evaluation,
            },
            &mut consistency_checked,
        )?;

        let pcs_pairing_points = Self::reduce_verify_shplemini(&mut opening_claim, transcript)?;

        // Mirror bb's UltraVerifier (ultra_verifier.cpp): reconstruct the
        // pairing-point accumulator carried in the last public inputs, aggregate
        // the PCS pairing points into it, then pairing-check the AGGREGATE — not
        // the PCS points alone. Non-recursive circuits carry the default
        // (infinity) accumulator, so the aggregate is exactly the PCS points and
        // the check is unchanged; a recursive circuit carrying a malicious
        // accumulator is rejected here (the PCS points verify on their own but the
        // random-linear-combination pairing check fails).
        let accumulator = Self::reconstruct_accumulator(public_inputs)?;
        let (agg_p0, agg_p1) = Self::aggregate_pairing_points(accumulator, pcs_pairing_points)?;
        let pcs_verified = Self::pairing_check::<P>(agg_p0, agg_p1, *crs, P::G2Affine::generator());
        Ok(sumcheck_output.verified && pcs_verified && consistency_checked)
    }
}

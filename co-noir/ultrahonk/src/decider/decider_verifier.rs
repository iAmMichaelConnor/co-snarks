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
        // KZG:W is the last element of the proof.
        transcript.check_fully_consumed()?;
        opening_pair.commitments.push(quotient_commitment);
        opening_pair.scalars.push(opening_pair.challenge);
        let p_1 = -quotient_commitment.into_group();
        let p_0 = Utils::msm::<C>(&opening_pair.scalars, &opening_pair.commitments)?;

        Ok((p_0.into(), p_1.into()))
    }

    /// Reads the pairing point accumulator that a circuit propagates in its last
    /// `PAIRING_POINT_ACCUMULATOR_SIZE` public inputs (barretenberg's
    /// `DefaultIO::reconstruct_from_public`). Each point is decoded like a commitment in the proof:
    /// all-zero limbs encode the point at infinity, otherwise the coordinates must be canonical and
    /// the point must be on the curve.
    fn reconstruct_pairing_point_accumulator(
        public_inputs: &[C::ScalarField],
    ) -> HonkVerifyResult<(C::Affine, C::Affine)> {
        let size = PAIRING_POINT_ACCUMULATOR_SIZE as usize;
        let limbs = public_inputs
            .len()
            .checked_sub(size)
            .map(|start| &public_inputs[start..])
            .ok_or(HonkProofError::CorruptedKey)?
            .iter()
            .flat_map(C::convert_scalarfield_into)
            .collect::<Vec<_>>();
        let [p0, p1] = [&limbs[..limbs.len() / 2], &limbs[limbs.len() / 2..]].map(|point| {
            if point.iter().all(Zero::is_zero) {
                return Ok(C::Affine::zero());
            }
            let (x, y) = point.split_at(point.len() / 2);
            C::validate_basefield(x)?;
            C::validate_basefield(y)?;
            C::g1_affine_from_xy(C::convert_basefield_back(x), C::convert_basefield_back(y))
        });
        Ok((p0?, p1?))
    }

    /// Aggregates the pairing points of the PCS into the accumulator from the public inputs, as
    /// barretenberg's `PairingPoints::aggregate` does: a default accumulator (both points at
    /// infinity) is replaced by the PCS points, otherwise the two are combined with a random
    /// separator. Returns `None` if a PCS point or exactly one accumulator point is at infinity.
    fn aggregate_pairing_points(
        accumulator: (C::Affine, C::Affine),
        pcs: (C::Affine, C::Affine),
    ) -> Option<(C::Affine, C::Affine)> {
        if pcs.0.is_zero() || pcs.1.is_zero() {
            tracing::trace!("PCS pairing point at infinity");
            return None;
        }
        match (accumulator.0.is_zero(), accumulator.1.is_zero()) {
            (true, true) => Some(pcs),
            (false, false) => {
                let separator = C::ScalarField::rand(&mut rand::thread_rng());
                Some((
                    (accumulator.0 + pcs.0 * separator).into(),
                    (accumulator.1 + pcs.1 * separator).into(),
                ))
            }
            _ => {
                tracing::trace!("Pairing point accumulator is mixed-infinity");
                None
            }
        }
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
        log_circuit_size: u32,
        crs: &P::G2Affine,
        mut transcript: Transcript<TranscriptFieldType, H>,
        has_zk: ZeroKnowledge,
        virtual_log_n: usize,
        public_inputs: &[C::ScalarField],
    ) -> HonkVerifyResult<bool> {
        tracing::trace!("Decider verification");

        let mut padding_indicator_array = vec![C::ScalarField::one(); virtual_log_n];

        if has_zk == ZeroKnowledge::Yes {
            for (idx, value) in padding_indicator_array.iter_mut().enumerate() {
                *value = if idx < log_circuit_size as usize {
                    C::ScalarField::one()
                } else {
                    C::ScalarField::zero()
                };
            }
        }
        let (sumcheck_output, libra_commitments) = if has_zk == ZeroKnowledge::Yes {
            let mut libra_commitments = Vec::with_capacity(NUM_LIBRA_COMMITMENTS);

            libra_commitments
                .push(transcript.receive_point_from_prover::<C>(
                    "Libra:concatenation_commitment".to_string(),
                )?);

            let sumcheck_output = self.sumcheck_verify::<BATCHED_RELATION_PARTIAL_LENGTH_ZK>(
                &mut transcript,
                has_zk,
                &padding_indicator_array,
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
                &padding_indicator_array,
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
        // The pairing check must also cover the accumulator that the public inputs carry: a
        // circuit that verifies proofs recursively defers their final pairing check to here.
        let accumulator = Self::reconstruct_pairing_point_accumulator(public_inputs)?;
        let Some(pairing_points) = Self::aggregate_pairing_points(accumulator, pcs_pairing_points)
        else {
            return Ok(false);
        };
        let pcs_verified = Self::pairing_check::<P>(
            pairing_points.0,
            pairing_points.1,
            *crs,
            P::G2Affine::generator(),
        );
        Ok(sumcheck_output.verified && pcs_verified && consistency_checked)
    }
}

#[cfg(test)]
mod tests {
    use super::DeciderVerifier;
    use ark_bn254::{Fr, G1Affine, G1Projective};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::{UniformRand, Zero};
    use co_noir_common::{honk_curve::HonkCurve, transcript::Poseidon2Sponge};

    type Verifier = DeciderVerifier<G1Projective, Poseidon2Sponge>;

    fn random_point() -> G1Affine {
        (G1Affine::generator() * Fr::rand(&mut rand::thread_rng())).into_affine()
    }

    fn encode(points: [G1Affine; 2]) -> Vec<Fr> {
        points
            .iter()
            .flat_map(|p| {
                let (x, y) = G1Projective::g1_affine_to_xy(p);
                let mut limbs = G1Projective::convert_basefield_into(&x);
                limbs.extend(G1Projective::convert_basefield_into(&y));
                limbs
            })
            .collect()
    }

    #[test]
    fn accumulator_is_read_from_the_last_public_inputs() {
        let (p0, p1) = (random_point(), random_point());
        let mut public_inputs = vec![Fr::from(42u64)];
        public_inputs.extend(encode([p0, p1]));
        assert_eq!(
            Verifier::reconstruct_pairing_point_accumulator(&public_inputs).unwrap(),
            (p0, p1)
        );
        let default = vec![Fr::zero(); 8];
        let (q0, q1) = Verifier::reconstruct_pairing_point_accumulator(&default).unwrap();
        assert!(q0.is_zero() && q1.is_zero());
        assert!(Verifier::reconstruct_pairing_point_accumulator(&default[1..]).is_err());
        // Off-curve point.
        let mut off_curve = encode([p0, p1]);
        off_curve[0] += Fr::from(1u64);
        assert!(Verifier::reconstruct_pairing_point_accumulator(&off_curve).is_err());
    }

    #[test]
    fn aggregation_follows_barretenberg() {
        let infinity = G1Affine::zero();
        let pcs = (random_point(), random_point());
        let accumulator = (random_point(), random_point());
        // A default accumulator adopts the PCS points.
        assert_eq!(
            Verifier::aggregate_pairing_points((infinity, infinity), pcs),
            Some(pcs)
        );
        // A populated accumulator is combined with them.
        let (r0, r1) = Verifier::aggregate_pairing_points(accumulator, pcs).unwrap();
        assert_ne!((r0, r1), pcs);
        assert_ne!((r0, r1), accumulator);
        // Mixed-infinity accumulators and PCS points at infinity are rejected.
        for invalid in [
            Verifier::aggregate_pairing_points((accumulator.0, infinity), pcs),
            Verifier::aggregate_pairing_points((infinity, accumulator.1), pcs),
            Verifier::aggregate_pairing_points(accumulator, (pcs.0, infinity)),
            Verifier::aggregate_pairing_points((infinity, infinity), (infinity, pcs.1)),
        ] {
            assert_eq!(invalid, None);
        }
    }
}

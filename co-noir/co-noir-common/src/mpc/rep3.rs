use super::NoirUltraHonkProver;
use crate::HonkCurve;
use crate::honk_curve::NUM_LIMB_BITS;
use crate::honk_proof::TranscriptFieldType;
use ark_ff::One;
use ark_ff::PrimeField;
use ark_ff::Zero;
use mpc_core::protocols::rep3::Rep3UintShare;
use mpc_core::protocols::rep3::conversion;
use mpc_core::uint::{FieldUint, UintBackend};
use mpc_core::{
    MpcState,
    protocols::rep3::{
        Rep3PointShare, Rep3PrimeFieldShare, Rep3State, arithmetic, id::PartyID, pointshare, poly,
    },
};
use mpc_net::Network;
use rayon::prelude::*;
use std::any::TypeId;
#[derive(Debug)]
pub struct Rep3UltraHonkDriver;

// Keep the half-share optimization while using the same curve-specific backend
// as full replicated commitments. HonkCurve hides the short-Weierstrass config.
fn msm_public_points_half<P: HonkCurve<TranscriptFieldType>>(
    points: &[P::Affine],
    scalars: &[Rep3PrimeFieldShare<P::ScalarField>],
) -> P {
    debug_assert_eq!(points.len(), scalars.len());
    let a: Vec<_> = scalars.iter().map(|share| share.a).collect();
    P::fast_msm(points, &a)
}

impl<P: HonkCurve<TranscriptFieldType>> NoirUltraHonkProver<P> for Rep3UltraHonkDriver
where
    P::ScalarField: FieldUint,
    P::BaseField: FieldUint<Uint = <P::ScalarField as FieldUint>::Uint>,
{
    type ArithmeticShare = Rep3PrimeFieldShare<P::ScalarField>;
    type PointShare = Rep3PointShare<P>;
    type State = Rep3State;

    fn rand<N: Network>(_: &N, state: &mut Self::State) -> eyre::Result<Self::ArithmeticShare> {
        Ok(arithmetic::rand(state))
    }

    fn sub(a: Self::ArithmeticShare, b: Self::ArithmeticShare) -> Self::ArithmeticShare {
        arithmetic::sub(a, b)
    }

    fn sub_assign(a: &mut Self::ArithmeticShare, b: Self::ArithmeticShare) {
        arithmetic::sub_assign(a, b);
    }

    fn sub_assign_many(a: &mut [Self::ArithmeticShare], b: &[Self::ArithmeticShare]) {
        arithmetic::sub_vec_assign(a, b);
    }

    fn add(a: Self::ArithmeticShare, b: Self::ArithmeticShare) -> Self::ArithmeticShare {
        arithmetic::add(a, b)
    }

    fn add_assign(a: &mut Self::ArithmeticShare, b: Self::ArithmeticShare) {
        arithmetic::add_assign(a, b);
    }

    fn add_assign_public(
        a: &mut Self::ArithmeticShare,
        b: P::ScalarField,
        id: <Self::State as MpcState>::PartyID,
    ) {
        arithmetic::add_assign_public(a, b, id);
    }

    fn neg(a: Self::ArithmeticShare) -> Self::ArithmeticShare {
        arithmetic::neg(a)
    }

    fn mul_with_public(
        public: P::ScalarField,
        shared: Self::ArithmeticShare,
    ) -> Self::ArithmeticShare {
        arithmetic::mul_public(shared, public)
    }

    fn mul_assign_with_public(shared: &mut Self::ArithmeticShare, public: P::ScalarField) {
        arithmetic::mul_assign_public(shared, public);
    }

    fn add_assign_public_half_share(
        share: &mut P::ScalarField,
        public: P::ScalarField,
        id: <Self::State as MpcState>::PartyID,
    ) {
        if id == PartyID::ID0 {
            *share += public
        }
    }

    fn mul_with_public_to_half_share(
        public: P::ScalarField,
        shared: Self::ArithmeticShare,
    ) -> P::ScalarField {
        public * shared.a
    }

    fn local_mul_vec(
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        state: &mut Self::State,
    ) -> Vec<P::ScalarField> {
        arithmetic::local_mul_vec(a, b, state)
    }

    fn reshare<N: Network>(
        a: Vec<P::ScalarField>,
        net: &N,
        _: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        arithmetic::reshare_vec(a, net)
    }

    fn mul<N: Network>(
        a: Self::ArithmeticShare,
        b: Self::ArithmeticShare,
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Self::ArithmeticShare> {
        arithmetic::mul_vec(&[a], &[b], net, state).map(|v| v[0])
    }

    fn mul_many<N: Network>(
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        // Parallel local multiply with a single pre-squeezed mask draw, then one
        // reshare round — the same schedule as `arithmetic::mul_vec` (identical
        // message counts and opened values), but the local work runs on rayon
        // (`with_min_len(1024)` keeps small inputs on one thread).
        let local = arithmetic::local_mul_vec(a, b, state);
        arithmetic::reshare_vec(local, net)
    }

    fn add_with_public(
        public: P::ScalarField,
        shared: Self::ArithmeticShare,
        id: <Self::State as MpcState>::PartyID,
    ) -> Self::ArithmeticShare {
        arithmetic::add_public(shared, public, id)
    }

    fn promote_to_trivial_share(
        id: <Self::State as MpcState>::PartyID,
        public_value: P::ScalarField,
    ) -> Self::ArithmeticShare {
        arithmetic::promote_to_trivial_share(id, public_value)
    }

    fn promote_to_trivial_shares(
        id: <Self::State as MpcState>::PartyID,
        public_values: &[P::ScalarField],
    ) -> Vec<Self::ArithmeticShare> {
        public_values
            .par_iter()
            .with_min_len(1024)
            .map(|value| Self::ArithmeticShare::promote_from_trivial(value, id))
            .collect()
    }

    fn open_point<N: Network>(
        a: Self::PointShare,
        net: &N,
        _: &mut Self::State,
    ) -> eyre::Result<P> {
        pointshare::open_point(&a, net)
    }

    fn open_point_many<N: Network>(
        a: &[Self::PointShare],
        net: &N,
        _: &mut Self::State,
    ) -> eyre::Result<Vec<P>> {
        pointshare::open_point_many(a, net)
    }

    fn open_many<N: Network>(
        a: &[Self::ArithmeticShare],
        net: &N,
        _: &mut Self::State,
    ) -> eyre::Result<Vec<P::ScalarField>> {
        arithmetic::open_vec(a, net)
    }

    fn open_point_and_field<N: Network>(
        a: Self::PointShare,
        b: Self::ArithmeticShare,
        net: &N,
        _: &mut Self::State,
    ) -> eyre::Result<(P, P::ScalarField)> {
        pointshare::open_point_and_field(&a, &b, net)
    }

    fn open_point_and_field_many<N: Network>(
        a: &[Self::PointShare],
        b: &[Self::ArithmeticShare],
        net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<(Vec<P>, Vec<<P>::ScalarField>)> {
        pointshare::open_point_and_field_many(a, b, net)
    }

    fn mul_open_many<N: Network>(
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<P::ScalarField>> {
        arithmetic::mul_open_vec(a, b, net, state)
    }

    fn inv_many<N: Network>(
        a: &[Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        arithmetic::inv_vec(a, net, state)
    }

    fn inv_many_in_place<N: Network>(
        a: &mut [Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<()> {
        let r = (0..a.len())
            .map(|_| <Self as NoirUltraHonkProver<P>>::rand(net, state))
            .collect::<Result<Vec<_>, _>>()?;
        let mut y: Vec<P::ScalarField> =
            <Self as NoirUltraHonkProver<P>>::mul_open_many(a, &r, net, state)?;

        if y.iter().any(|y| y.is_zero()) {
            eyre::bail!("Cannot compute inverse of zero",);
        }
        // The opened y values are public, so we can Montgomery-batch-invert them. Batch
        // inversion yields exactly the per-element inverses the previous serial loop
        // computed (we bailed on zeros above), so the resulting shares are identical.
        ark_ff::batch_inversion(&mut y);
        a.par_iter_mut()
            .zip_eq(r.par_iter())
            .zip_eq(y.par_iter())
            .with_min_len(1024)
            .for_each(|((a, r), y)| *a = *r * *y);

        Ok(())
    }

    fn inv_many_in_place_leaking_zeros<N: Network>(
        a: &mut [Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<()> {
        let r = (0..a.len())
            .map(|_| <Self as NoirUltraHonkProver<P>>::rand(net, state))
            .collect::<Result<Vec<_>, _>>()?;
        let mut y: Vec<P::ScalarField> =
            <Self as NoirUltraHonkProver<P>>::mul_open_many(a, &r, net, state)?;

        // The opened y values are public, so we can Montgomery-batch-invert them.
        // `batch_inversion` skips zeros in place (they stay zero), and `r * 0` is the
        // all-zero share, which is exactly `ArithmeticShare::default()` — so the fold-in
        // below needs no zero branch and matches the previous serial loop bit-for-bit.
        ark_ff::batch_inversion(&mut y);
        a.par_iter_mut()
            .zip_eq(r.par_iter())
            .zip_eq(y.par_iter())
            .with_min_len(1024)
            .for_each(|((a, r), y)| *a = *r * *y);

        Ok(())
    }

    fn msm_public_points(
        points: &[P::Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShare {
        let (a, b): (Vec<_>, Vec<_>) = scalars.iter().map(|share| (share.a, share.b)).unzip();
        let (res_a, res_b) = rayon::join(|| P::fast_msm(points, &a), || P::fast_msm(points, &b));
        Rep3PointShare::new(res_a, res_b)
    }

    // L0d half-share override: MSM only the `a` summand (one Pippenger instead
    // of two) and open by broadcasting the partial results. Identical opened
    // point, identical knowledge (each partial sum is learnable from the
    // opened value and a party's own summands — the same information the
    // reshare-based open reveals); comms shape changes from one ring reshare
    // to a 3-way broadcast per open call (fences re-pinned for this).
    fn commit_and_open<N: Network>(
        points: &[P::Affine],
        scalars: &[Self::ArithmeticShare],
        net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<P> {
        let half = msm_public_points_half::<P>(points, scalars);
        pointshare::open_half_point(half, net)
    }

    fn commit_and_open_many<N: Network>(
        points: &[P::Affine],
        scalars: &[&[Self::ArithmeticShare]],
        net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<Vec<P>> {
        let halves = scalars
            .iter()
            .map(|poly| msm_public_points_half::<P>(&points[..poly.len()], poly))
            .collect::<Vec<_>>();
        pointshare::open_half_point_many(&halves, net)
    }

    fn point_add(a: &Self::PointShare, b: &Self::PointShare) -> Self::PointShare {
        pointshare::add(a, b)
    }

    fn eval_poly(coeffs: &[Self::ArithmeticShare], point: P::ScalarField) -> Self::ArithmeticShare {
        poly::eval_poly(coeffs, point)
    }

    fn fft<D: ark_poly::EvaluationDomain<P::ScalarField>>(
        data: &[Self::ArithmeticShare],
        domain: &D,
    ) -> Vec<Self::ArithmeticShare> {
        domain.fft(data)
    }

    fn ifft<D: ark_poly::EvaluationDomain<P::ScalarField>>(
        data: &[Self::ArithmeticShare],
        domain: &D,
    ) -> Vec<Self::ArithmeticShare> {
        domain.ifft(data)
    }

    fn is_zero_many<N: Network>(
        a: &[Self::ArithmeticShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        let zeroes = vec![P::ScalarField::zero(); a.len()];
        arithmetic::eq_public_many(a, &zeroes, net, state)
    }

    fn promote_to_trivial_point_share(
        id: <Self::State as MpcState>::PartyID,
        public_value: P,
    ) -> Self::PointShare {
        pointshare::promote_to_trivial_share(id, &public_value)
    }

    fn point_sub(a: &Self::PointShare, b: &Self::PointShare) -> Self::PointShare {
        pointshare::sub(a, b)
    }

    fn scalar_mul_public_point(a: &P, b: Self::ArithmeticShare) -> Self::PointShare {
        pointshare::scalar_mul_public_point(a, b)
    }

    fn poseidon_permutation_in_place<const T: usize, const D: u64, N: Network>(
        poseidon: &mpc_core::gadgets::poseidon2::Poseidon2<<P>::ScalarField, T, D>,
        state: &mut [Self::ArithmeticShare; T],
        net: &N,
        mpc_state: &mut Self::State,
    ) -> eyre::Result<()> {
        // TACEO TODO: We could optimize this by investigating how many we need in each prover
        let mut precomp = poseidon.precompute_rep3(1, net, mpc_state)?;
        poseidon.rep3_permutation_in_place_with_precomputation(state, &mut precomp, net)
    }

    fn pointshare_to_field_shares_many<F: PrimeField, N: Network>(
        points: &[Self::PointShare],
        net: &N,
        state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>>
    where
        P: HonkCurve<F>,
    {
        if TypeId::of::<P>()
            != TypeId::of::<ark_ec::short_weierstrass::Projective<ark_bn254::g1::Config>>()
            || TypeId::of::<F>() != TypeId::of::<ark_bn254::Fr>()
        {
            panic!("Only BN254 is supported with TranscriptFieldType = Fr");
        }

        const LOWER_BITS: usize = 2 * NUM_LIMB_BITS as usize;
        let (x_shares, y_shares, infinity_shares) =
            conversion::point_share_to_fieldshares_many(points, net, state)?;
        let mul = infinity_shares
            .iter()
            .map(|i| arithmetic::sub_public_by_shared(P::BaseField::one(), *i, state.id()))
            .collect::<Vec<_>>();
        let mut lhs = Vec::with_capacity(x_shares.len() * 2);
        lhs.extend_from_slice(&x_shares);
        lhs.extend_from_slice(&y_shares);
        let mut rhs = Vec::with_capacity(mul.len() * 2);
        rhs.extend_from_slice(&mul);
        rhs.extend_from_slice(&mul);
        let res = arithmetic::mul_vec(&lhs, &rhs, net, state)?;
        let res = conversion::a2b_many(&res, net, state)?;
        let lower_mask = <P::BaseField as FieldUint>::Uint::mask(LOWER_BITS);
        let res: Vec<_> = res
            .iter()
            .flat_map(|x| {
                let res0 = x.and_mask(&lower_mask);
                let res1 = x >> LOWER_BITS;
                [
                    Rep3UintShare::<P::ScalarField>::new(res0.a, res0.b),
                    Rep3UintShare::<P::ScalarField>::new(res1.a, res1.b),
                ]
            })
            .collect();
        conversion::b2a_many(&res, net, state)
    }
}

#[cfg(test)]
mod half_commitment_tests {
    use super::*;
    use ark_ec::AffineRepr;
    use ark_ff::UniformRand;
    use mpc_core::protocols::rep3::share_field_elements;
    use mpc_net::local::LocalNetwork;
    use rand::{SeedableRng, rngs::StdRng};

    fn check_half_commitment<P: HonkCurve<TranscriptFieldType>>()
    where
        P::ScalarField: FieldUint,
        P::BaseField: FieldUint<Uint = <P::ScalarField as FieldUint>::Uint>,
    {
        let mut rng = StdRng::seed_from_u64(0x48414c46);
        // Includes the batch-affine backend's large-window path, infinity,
        // repeated/opposite bases, and zero/one/maximal canonical scalars.
        let n = 4096;
        let mut points = P::normalize_batch(&(0..n).map(|_| P::rand(&mut rng)).collect::<Vec<_>>());
        points[0] = P::Affine::zero();
        points[1] = P::generator().into_affine();
        points[2] = points[1];
        points[3] = (-P::generator()).into_affine();
        let mut values: Vec<_> = (0..n).map(|_| P::ScalarField::rand(&mut rng)).collect();
        values[0] = P::ScalarField::zero();
        values[1] = P::ScalarField::one();
        values[2] = -P::ScalarField::one();
        values[3] = P::ScalarField::one();
        let shares = share_field_elements(&values, &mut rng);
        let lengths = [0, 1, 2, 31, 32, n];
        let expected: Vec<_> = lengths
            .iter()
            .map(|&len| P::msm_unchecked(&points[..len], &values[..len]))
            .collect();
        let workers: Vec<_> = LocalNetwork::new_3_parties()
            .into_iter()
            .zip(shares)
            .map(|(net, shares)| {
                let points = points.clone();
                let expected = expected.clone();
                std::thread::spawn(move || {
                    let mut state = Rep3State::new(&net, Default::default()).unwrap();
                    for (&len, expected) in lengths.iter().zip(&expected) {
                        let point_slice = &points[..len];
                        let scalar_slice = &shares[..len];
                        assert_eq!(
                            msm_public_points_half::<P>(point_slice, scalar_slice),
                            pointshare::msm_public_points_half::<P>(point_slice, scalar_slice)
                        );
                        let full =
                            <Rep3UltraHonkDriver as NoirUltraHonkProver<P>>::msm_public_points(
                                point_slice,
                                scalar_slice,
                            );
                        assert_eq!(pointshare::open_point(&full, &net).unwrap(), *expected);
                        let half_open =
                            <Rep3UltraHonkDriver as NoirUltraHonkProver<P>>::commit_and_open(
                                point_slice,
                                scalar_slice,
                                &net,
                                &mut state,
                            )
                            .unwrap();
                        assert_eq!(half_open, *expected);
                    }
                    let polynomials: Vec<_> = lengths.iter().map(|&len| &shares[..len]).collect();
                    let batched =
                        <Rep3UltraHonkDriver as NoirUltraHonkProver<P>>::commit_and_open_many(
                            &points,
                            &polynomials,
                            &net,
                            &mut state,
                        )
                        .unwrap();
                    assert_eq!(batched, expected);
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
    }

    #[test]
    fn half_commitments_match_replicated_and_plain_bn254() {
        check_half_commitment::<ark_bn254::G1Projective>();
    }

    #[test]
    fn half_commitments_match_replicated_and_plain_grumpkin() {
        check_half_commitment::<ark_grumpkin::Projective>();
    }
}

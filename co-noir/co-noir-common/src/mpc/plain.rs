use super::NoirUltraHonkProver;
use crate::HonkCurve;
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_ff::One;
use ark_ff::PrimeField;
use ark_ff::UniformRand;
use ark_poly::DenseUVPolynomial;
use ark_poly::{Polynomial, univariate::DensePolynomial};
use mpc_core::MpcState;
use mpc_core::PlainState;
use mpc_net::Network;
use num_traits::Zero;
use rand::thread_rng;
use rayon::prelude::*;
use std::any::Any;
use std::any::TypeId;

fn downcast<A: 'static, B: 'static>(a: &A) -> Option<&B> {
    (a as &dyn Any).downcast_ref::<B>()
}

#[derive(Clone, Debug)]
pub struct PlainUltraHonkDriver;

impl<P: CurveGroup> NoirUltraHonkProver<P> for PlainUltraHonkDriver {
    type ArithmeticShare = P::ScalarField;
    type PointShare = P;
    type State = PlainState;

    fn debug(ele: Self::ArithmeticShare) -> String {
        if ele.is_zero() {
            "0".to_string()
        } else {
            ele.to_string()
        }
    }

    fn rand<N: Network>(_: &N, state: &mut Self::State) -> eyre::Result<Self::ArithmeticShare> {
        if state.rng.is_none() {
            // We mainly use the PlainDriver in tests, so it is fine to use thread_rng here.
            // In the MPC setting, the PlainDriver is also called when doing recursive proofs, but in that
            // case we initialize it with a proper RNG.
            let mut rng = thread_rng();
            return Ok(Self::ArithmeticShare::rand(&mut rng));
        }
        let rng = state.rng.as_mut().expect("Checked is_some");
        Ok(P::ScalarField::rand(rng))
    }

    fn sub(a: Self::ArithmeticShare, b: Self::ArithmeticShare) -> Self::ArithmeticShare {
        a - b
    }

    fn sub_assign(a: &mut Self::ArithmeticShare, b: Self::ArithmeticShare) {
        *a -= b;
    }

    fn sub_assign_many(a: &mut [Self::ArithmeticShare], b: &[Self::ArithmeticShare]) {
        debug_assert_eq!(a.len(), b.len());
        a.par_iter_mut().zip(b.par_iter()).for_each(|(a, b)| {
            *a -= b;
        })
    }

    fn add(a: Self::ArithmeticShare, b: Self::ArithmeticShare) -> Self::ArithmeticShare {
        a + b
    }

    fn add_assign(a: &mut Self::ArithmeticShare, b: Self::ArithmeticShare) {
        *a += b;
    }

    fn add_assign_public(
        a: &mut Self::ArithmeticShare,
        b: P::ScalarField,
        _id: <Self::State as MpcState>::PartyID,
    ) {
        *a += b;
    }

    fn neg(a: Self::ArithmeticShare) -> Self::ArithmeticShare {
        -a
    }

    fn mul_with_public(
        public: P::ScalarField,
        shared: Self::ArithmeticShare,
    ) -> Self::ArithmeticShare {
        shared * public
    }

    fn mul_assign_with_public(shared: &mut Self::ArithmeticShare, public: P::ScalarField) {
        *shared *= public;
    }

    fn add_assign_public_half_share(
        share: &mut P::ScalarField,
        public: P::ScalarField,
        _id: <Self::State as MpcState>::PartyID,
    ) {
        *share += public
    }

    fn mul_with_public_to_half_share(
        public: P::ScalarField,
        shared: Self::ArithmeticShare,
    ) -> P::ScalarField {
        <Self as NoirUltraHonkProver<P>>::mul_with_public(public, shared)
    }

    fn local_mul_vec(
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        _state: &mut Self::State,
    ) -> Vec<P::ScalarField> {
        debug_assert_eq!(a.len(), b.len());
        // Element-wise and thus order-independent: the parallel map computes exactly the same
        // products as the serial one.
        a.par_iter()
            .zip(b.par_iter())
            .map(|(a, b)| *a * b)
            .collect()
    }

    fn reshare<N: Network>(
        a: Vec<P::ScalarField>,
        _net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        Ok(a)
    }

    fn mul<N: Network>(
        a: Self::ArithmeticShare,
        b: Self::ArithmeticShare,
        _net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<Self::ArithmeticShare> {
        Ok(a * b)
    }

    fn mul_many<N: Network>(
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        _net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        debug_assert_eq!(a.len(), b.len());
        // Element-wise and thus order-independent: the parallel map computes exactly the same
        // products as the serial one.
        Ok(a.par_iter()
            .zip(b.par_iter())
            .map(|(a, b)| *a * b)
            .collect())
    }

    fn add_with_public(
        public: P::ScalarField,
        shared: Self::ArithmeticShare,
        _id: <Self::State as MpcState>::PartyID,
    ) -> Self::ArithmeticShare {
        shared + public
    }

    fn promote_to_trivial_share(
        _id: <Self::State as MpcState>::PartyID,
        public_value: P::ScalarField,
    ) -> Self::ArithmeticShare {
        public_value
    }

    fn promote_to_trivial_shares(
        _id: <Self::State as MpcState>::PartyID,
        public_values: &[P::ScalarField],
    ) -> Vec<Self::ArithmeticShare> {
        public_values.to_vec()
    }

    fn open_point<N: Network>(
        a: Self::PointShare,
        _net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<P> {
        Ok(a)
    }

    fn open_point_many<N: Network>(
        a: &[Self::PointShare],
        _net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<Vec<P>> {
        Ok(a.to_vec())
    }

    fn open_many<N: Network>(
        a: &[Self::ArithmeticShare],
        _net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<Vec<P::ScalarField>> {
        Ok(a.to_vec())
    }

    fn open_point_and_field<N: Network>(
        a: Self::PointShare,
        b: Self::ArithmeticShare,
        _net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<(P, P::ScalarField)> {
        Ok((a, b))
    }

    fn open_point_and_field_many<N: Network>(
        a: &[Self::PointShare],
        b: &[Self::ArithmeticShare],
        _net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<(Vec<P>, Vec<P::ScalarField>)> {
        Ok((a.to_vec(), b.to_vec()))
    }

    fn mul_open_many<N: Network>(
        a: &[Self::ArithmeticShare],
        b: &[Self::ArithmeticShare],
        _net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<Vec<P::ScalarField>> {
        debug_assert_eq!(a.len(), b.len());
        // Element-wise and thus order-independent: the parallel map computes exactly the same
        // products as the serial one.
        Ok(a.par_iter()
            .zip(b.par_iter())
            .map(|(a, b)| *a * b)
            .collect())
    }

    fn inv_many<N: Network>(
        a: &[Self::ArithmeticShare],
        _net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        if a.par_iter().any(|a| a.is_zero()) {
            eyre::bail!("Cannot invert zero");
        }
        let mut res = a.to_vec();
        // Montgomery batch inversion (parallelized over chunks via ark's `parallel` feature).
        // Each element's inverse is uniquely determined by the field, so the chunking/grouping
        // of the Montgomery trick cannot change the outputs: they are exactly the per-element
        // inverses the previous serial loop computed, just cheaper.
        ark_ff::batch_inversion(&mut res);
        Ok(res)
    }

    fn inv_many_in_place<N: Network>(
        a: &mut [Self::ArithmeticShare],
        _net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<()> {
        if a.par_iter().any(|a| a.is_zero()) {
            eyre::bail!("Cannot invert zero");
        }
        // See `inv_many`: batch inversion is exact, outputs are identical to per-element
        // inversion.
        ark_ff::batch_inversion(a);
        Ok(())
    }

    fn inv_many_in_place_leaking_zeros<N: Network>(
        a: &mut [Self::ArithmeticShare],
        _net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<()> {
        // `ark_ff::batch_inversion` skips zero elements (they stay zero), which is exactly the
        // "leaking zeros" semantics of the previous serial loop; nonzero elements get their
        // exact field inverse.
        ark_ff::batch_inversion(a);
        Ok(())
    }

    fn msm_public_points(
        points: &[P::Affine],
        scalars: &[Self::ArithmeticShare],
    ) -> Self::PointShare {
        P::msm_unchecked(points, scalars)
    }

    fn eval_poly(coeffs: &[Self::ArithmeticShare], point: P::ScalarField) -> Self::ArithmeticShare {
        // TACEO TODO: here we clone...
        let poly = DensePolynomial::from_coefficients_slice(coeffs);
        poly.evaluate(&point)
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
        _net: &N,
        _state: &mut Self::State,
    ) -> eyre::Result<Vec<Self::ArithmeticShare>> {
        let mut res = Vec::with_capacity(a.len());
        for a in a {
            if a.is_zero() {
                res.push(Self::ArithmeticShare::one());
            } else {
                res.push(Self::ArithmeticShare::zero());
            }
        }
        Ok(res)
    }

    fn point_add(a: &Self::PointShare, b: &Self::PointShare) -> Self::PointShare {
        *a + b
    }

    fn point_sub(a: &Self::PointShare, b: &Self::PointShare) -> Self::PointShare {
        *a - b
    }

    fn promote_to_trivial_point_share(
        _id: <Self::State as MpcState>::PartyID,
        public_value: P,
    ) -> Self::PointShare {
        public_value
    }

    fn scalar_mul_public_point(a: &P, b: Self::ArithmeticShare) -> Self::PointShare {
        *a * b
    }

    fn poseidon_permutation_in_place<const T: usize, const D: u64, N: Network>(
        poseidon: &mpc_core::gadgets::poseidon2::Poseidon2<<P>::ScalarField, T, D>,
        state: &mut [Self::ArithmeticShare; T],
        _net: &N,
        _mpc_state: &mut Self::State,
    ) -> eyre::Result<()> {
        poseidon.permutation_in_place(state);
        Ok(())
    }

    fn pointshare_to_field_shares_many<F: PrimeField, N: Network>(
        points: &[Self::PointShare],
        _net: &N,
        _state: &mut Self::State,
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
        Ok(points
            .iter()
            .flat_map(|p| {
                let (x, y) = if let Some((out_x, out_y)) = p.into_affine().xy() {
                    (out_x, out_y)
                } else {
                    (P::BaseField::zero(), P::BaseField::zero())
                };
                let res0 = P::convert_basefield_into(&x);
                let res1 = P::convert_basefield_into(&y);
                let res0_0: P::ScalarField = *downcast(&res0[0]).expect("We checked types");
                let res0_1: P::ScalarField = *downcast(&res0[1]).expect("We checked types");
                let res1_0: P::ScalarField = *downcast(&res1[0]).expect("We checked types");
                let res1_1: P::ScalarField = *downcast(&res1[1]).expect("We checked types");
                [res0_0, res0_1, res1_0, res1_1]
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::PlainUltraHonkDriver;
    use crate::mpc::NoirUltraHonkProver;
    use ark_ff::{Field, UniformRand};
    use num_traits::Zero;
    use rand::{SeedableRng, rngs::StdRng};

    type Driver = PlainUltraHonkDriver;
    type P = ark_bn254::G1Projective;
    type F = ark_bn254::Fr;

    /// The plain driver's inversions are now Montgomery-batched (and chunked in parallel by
    /// ark's `parallel` feature). Batching/chunking must not change the outputs: every element
    /// has a unique field inverse. This asserts bit-exact equality with the per-element serial
    /// reference the old implementation computed, for all three inversion entry points.
    #[test]
    fn batched_inversion_matches_serial_reference() {
        let mut rng = StdRng::seed_from_u64(0xC0DEC0DE);
        let mut state = Default::default();
        let net = ();

        // Length deliberately not a multiple of any chunk size.
        let a: Vec<F> = (0..1027).map(|_| F::rand(&mut rng)).collect();
        let expected: Vec<F> = a.iter().map(|x| x.inverse().unwrap()).collect();

        let res = <Driver as NoirUltraHonkProver<P>>::inv_many(&a, &net, &mut state).unwrap();
        assert_eq!(res, expected);

        let mut b = a.clone();
        <Driver as NoirUltraHonkProver<P>>::inv_many_in_place(&mut b, &net, &mut state).unwrap();
        assert_eq!(b, expected);

        // Leaking-zeros variant: zeros stay zero, nonzero elements get their exact inverse.
        let mut with_zeros = a.clone();
        for i in (0..with_zeros.len()).step_by(5) {
            with_zeros[i] = F::zero();
        }
        let expected_lz: Vec<F> = with_zeros
            .iter()
            .map(|x| {
                if x.is_zero() {
                    F::zero()
                } else {
                    x.inverse().unwrap()
                }
            })
            .collect();
        let mut c = with_zeros.clone();
        <Driver as NoirUltraHonkProver<P>>::inv_many_in_place_leaking_zeros(
            &mut c, &net, &mut state,
        )
        .unwrap();
        assert_eq!(c, expected_lz);

        // The strict variants must still reject zeros.
        assert!(
            <Driver as NoirUltraHonkProver<P>>::inv_many(&with_zeros, &net, &mut state).is_err()
        );
        let mut d = with_zeros.clone();
        assert!(
            <Driver as NoirUltraHonkProver<P>>::inv_many_in_place(&mut d, &net, &mut state)
                .is_err()
        );
    }
}

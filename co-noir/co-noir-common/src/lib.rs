use crate::barycentric::Barycentric;
use crate::crs::ProverCrs;
use crate::honk_curve::HonkCurve;
use crate::honk_proof::HonkProofResult;
use crate::utils::Utils;
use crate::{
    honk_proof::TranscriptFieldType,
    mpc::NoirUltraHonkProver,
    transcript::{Transcript, TranscriptHasher},
};
use ark_ec::CurveGroup;
use ark_ff::{One, Zero};
use ark_serialize::CanonicalSerialize;
use itertools::izip;
use mpc_net::Network;

pub mod barycentric;
pub mod co_shplemini;
pub mod constants;
pub mod crs;
pub mod honk_curve;
pub mod honk_proof;
pub mod keccak_hash;
pub mod keys;
pub mod mpc;
pub mod polynomials;
pub mod serialize;
pub mod shplemini;
pub mod sponge_hasher;
pub mod transcript;
pub mod types;
pub mod utils;

pub fn compute_opening_proof<
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
>(
    opening_claim: shplemini::ShpleminiOpeningClaim<P::ScalarField>,
    transcript: &mut Transcript<TranscriptFieldType, H>,
    crs: &ProverCrs<P>,
) -> HonkProofResult<()> {
    let mut quotient = opening_claim.polynomial;
    let pair = opening_claim.opening_pair;
    quotient[0] -= pair.evaluation;
    // Computes the coefficients for the quotient polynomial q(X) = (p(X) - v) / (X - r) through an FFT
    quotient.factor_roots(&pair.challenge);
    let quotient_commitment = Utils::commit(&quotient.coefficients, crs)?;
    // AZTEC TODO(#479): compute_opening_proof
    // future we might need to adjust this to use the incoming alternative to work queue (i.e. variation of
    // pthreads) or even the work queue itself
    transcript.send_point_to_verifier::<P>("KZG:W".to_string(), quotient_commitment.into());
    Ok(())
}

pub fn compute_co_opening_proof<
    T: NoirUltraHonkProver<P>,
    P: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
    N: Network,
>(
    net: &N,
    state: &mut T::State,
    opening_claim: co_shplemini::ShpleminiOpeningClaim<T, P>,
    transcript: &mut Transcript<TranscriptFieldType, H>,
    crs: &ProverCrs<P>,
) -> HonkProofResult<()> {
    let mut quotient = opening_claim.polynomial;
    let pair = opening_claim.opening_pair;

    quotient[0] = T::sub(quotient[0], pair.evaluation);
    // Computes the coefficients for the quotient polynomial q(X) = (p(X) - v) / (X - r) through an FFT
    quotient.factor_roots(&pair.challenge);
    let quotient_commitment = CoUtils::commit::<T, P>(&quotient.coefficients, crs);
    // AZTEC TODO(#479): for now we compute the KZG commitment directly to unify the KZG and IPA interfaces but in the
    // future we might need to adjust this to use the incoming alternative to work queue (i.e. variation of
    // pthreads) or even the work queue itself

    let quotient_commitment = T::open_point(quotient_commitment, net, state)?;
    transcript.send_point_to_verifier::<P>("KZG:W".to_string(), quotient_commitment.into());

    Ok(())
}

pub struct CoUtils {}

impl CoUtils {
    pub fn commit<T: NoirUltraHonkProver<P>, P: CurveGroup>(
        poly: &[T::ArithmeticShare],
        crs: &ProverCrs<P>,
    ) -> T::PointShare {
        Self::msm::<T, P>(poly, &crs.monomials)
    }

    pub fn msm<T: NoirUltraHonkProver<P>, P: CurveGroup>(
        poly: &[T::ArithmeticShare],
        crs: &[P::Affine],
    ) -> T::PointShare {
        let len = poly.len();
        T::msm_public_points(&crs[..len], poly)
    }

    pub fn batch_invert<T: NoirUltraHonkProver<P>, P: CurveGroup, N: Network>(
        poly: &mut [T::ArithmeticShare],
        net: &N,
        state: &mut T::State,
    ) -> eyre::Result<()> {
        T::inv_many_in_place(poly, net, state)
    }

    pub fn batch_invert_leaking_zeros<T: NoirUltraHonkProver<P>, P: CurveGroup, N: Network>(
        poly: &mut [T::ArithmeticShare],
        net: &N,
        state: &mut T::State,
    ) -> eyre::Result<()> {
        T::inv_many_in_place_leaking_zeros(poly, net, state)
    }

    /// The largest number of field elements [`CoUtils::mul_many_bounded`] multiplies in one
    /// [`NoirUltraHonkProver::mul_many`] call: one such call sends one vector of `len` field
    /// elements per message (REP3 resharing, Shamir degree reduction), which is kept within
    /// [`mpc_net::DEFAULT_MAX_FRAME_LENGTH`] (an 8-byte length prefix plus the elements).
    pub fn max_mul_many_len<F: CanonicalSerialize + Zero>() -> usize {
        (mpc_net::DEFAULT_MAX_FRAME_LENGTH - 8) / F::zero().uncompressed_size()
    }

    /// [`NoirUltraHonkProver::mul_many`] for batches that are built by combining independent
    /// multiplications into one round. Batches longer than
    /// [`CoUtils::max_mul_many_len`] are multiplied in consecutive chunks, so that no message
    /// exceeds the default frame length of the network.
    pub fn mul_many_bounded<T: NoirUltraHonkProver<P>, P: CurveGroup, N: Network>(
        a: &[T::ArithmeticShare],
        b: &[T::ArithmeticShare],
        net: &N,
        state: &mut T::State,
    ) -> eyre::Result<Vec<T::ArithmeticShare>> {
        debug_assert_eq!(a.len(), b.len());
        let max_len = Self::max_mul_many_len::<P::ScalarField>();
        if a.len() <= max_len {
            return T::mul_many(a, b, net, state);
        }
        let mut res = Vec::with_capacity(a.len());
        for (a, b) in a.chunks(max_len).zip(b.chunks(max_len)) {
            res.extend(T::mul_many(a, b, net, state)?);
        }
        Ok(res)
    }

    // To reduce the number of communication rounds, we implement the array_prod_mul macro according to https://www.usenix.org/system/files/sec22-ozdemir.pdf, p11 first paragraph.
    pub fn array_prod_mul<T: NoirUltraHonkProver<P>, P: CurveGroup, N: Network>(
        net: &N,
        state: &mut T::State,
        inp: &[T::ArithmeticShare],
    ) -> eyre::Result<Vec<T::ArithmeticShare>> {
        // Do the multiplications of inp[i] * inp[i-1] in constant rounds
        let len = inp.len();

        let r = (0..=len)
            .map(|_| T::rand(net, state))
            .collect::<Result<Vec<_>, _>>()?;
        let r_inv = T::inv_many(&r, net, state)?;
        let r_inv0 = vec![r_inv[0]; len];

        // The unblinding factors r_0^-1 * r_i and the blinded inputs r_(i-1) * inp_(i-1) are
        // independent products, so they share one multiplication round.
        let mut lhs = r_inv0;
        lhs.extend_from_slice(&r[..len]);
        let mut rhs = r[1..].to_vec();
        rhs.extend_from_slice(inp);
        let mut unblind = Self::mul_many_bounded::<T, P, N>(&lhs, &rhs, net, state)?;
        let mul = unblind.split_off(len);

        let mut open = T::mul_open_many(&mul, &r_inv[1..], net, state)?;

        for i in 1..open.len() {
            open[i] = open[i] * open[i - 1];
        }

        for (unblind, open) in unblind.iter_mut().zip(open.iter()) {
            *unblind = T::mul_with_public(*open, *unblind);
        }
        Ok(unblind)
    }

    // To reduce the number of communication rounds, we implement the array_prod_mul macro according to https://www.usenix.org/system/files/sec22-ozdemir.pdf, p11 first paragraph.
    // Batched version of the above, multiplies every inner array separately
    pub fn array_prod_inner_mul_many<T: NoirUltraHonkProver<P>, P: CurveGroup, N: Network>(
        net: &N,
        state: &mut T::State,
        inp: &[Vec<T::ArithmeticShare>],
    ) -> eyre::Result<Vec<Vec<T::ArithmeticShare>>> {
        // Do the multiplications of inp[i] * inp[i-1] in constant rounds
        let depth = inp.len();
        let width = inp[0].len();
        debug_assert!(
            inp.iter().all(|v| v.len() == width),
            "All input slices must have the same length"
        );

        let r = (0..(width + 1) * depth)
            .map(|_| T::rand(net, state))
            .collect::<Result<Vec<_>, _>>()?;
        let r_inv = T::inv_many(&r, net, state)?;
        let mut r_inv0s = Vec::with_capacity(depth * width);
        let mut r_chunks = Vec::with_capacity(depth * width);
        let mut mul_r = Vec::with_capacity(depth * width);
        let mut r_invs_mul = Vec::with_capacity(depth * width);

        for (r_, r_inv_) in izip!(r.chunks(width + 1), r_inv.chunks(width + 1)) {
            r_inv0s.extend(vec![r_inv_[0]; width]);
            r_chunks.extend(r_[1..].to_vec());
            mul_r.extend(r_[..width].to_vec());
            r_invs_mul.extend(r_inv_[1..].to_vec());
        }

        let input = inp.iter().flatten().cloned().collect::<Vec<_>>();

        // The unblinding factors and the blinded inputs are independent products, so they
        // share one multiplication round.
        let mut lhs = r_inv0s;
        lhs.extend_from_slice(&mul_r);
        let mut rhs = r_chunks;
        rhs.extend_from_slice(&input);
        let mut unblind = Self::mul_many_bounded::<T, P, N>(&lhs, &rhs, net, state)?;
        let mul = unblind.split_off(depth * width);

        let mut open = T::mul_open_many(&mul, &r_invs_mul, net, state)?;

        for open_ in open.chunks_mut(width) {
            for i in 1..open_.len() {
                open_[i] *= open_[i - 1];
            }
        }

        for (unblind, open) in unblind.iter_mut().zip(open.iter()) {
            *unblind = T::mul_with_public(*open, *unblind);
        }

        let mut out = Vec::with_capacity(depth);
        for chunk in unblind.chunks(width) {
            out.push(chunk.to_vec());
        }

        Ok(out)
    }

    pub fn evaluate<T: NoirUltraHonkProver<P>, P: CurveGroup>(
        evaluations: &[T::ArithmeticShare],
        u: P::ScalarField,
    ) -> T::ArithmeticShare {
        if u == P::ScalarField::zero() {
            return evaluations[0];
        }
        let size = evaluations.len();

        let mut full_numerator_value = P::ScalarField::one();
        for i in 0..size {
            full_numerator_value *= u - P::ScalarField::from(i as u64);
        }

        let big_domain = Barycentric::construct_big_domain(evaluations.len(), size);
        let lagrange_denominators = Barycentric::construct_lagrange_denominators(size, &big_domain);

        let mut denominator_inverses = vec![P::ScalarField::zero(); size];
        for i in 0..size {
            let mut inv = lagrange_denominators[i];

            inv *= u - big_domain[i];
            inv = P::ScalarField::one() / inv;
            denominator_inverses[i] = inv;
        }

        let mut result = T::ArithmeticShare::default();
        // Compute each term v_j / (d_j*(x-x_j)) of the sum
        for (i, &inverse) in denominator_inverses.iter().enumerate() {
            let mut term = evaluations[i];
            T::mul_assign_with_public(&mut term, inverse);
            T::add_assign(&mut result, term);
        }

        // Scale the sum by the value of B(x)
        T::mul_assign_with_public(&mut result, full_numerator_value);
        result
    }
}

#[cfg(test)]
mod tests {
    use crate::{CoUtils, mpc::plain::PlainUltraHonkDriver};
    use ark_ff::UniformRand;
    use rand::thread_rng;

    // This is only for the plaindriver
    #[test]
    fn array_prod_inner_mul_many_test() {
        let vec_size = 4;
        let entries = 3;
        let mut rng = thread_rng();
        let mut input = Vec::with_capacity(vec_size);
        for _ in 0..vec_size {
            let mut tmp = Vec::with_capacity(entries);
            for _ in 0..entries {
                tmp.push(ark_bn254::Fr::rand(&mut rng));
            }
            input.push(tmp);
        }
        let is_result = CoUtils::array_prod_inner_mul_many::<
            PlainUltraHonkDriver,
            ark_bn254::G1Projective,
            _,
        >(&(), &mut Default::default(), &input)
        .unwrap();
        let should_result = {
            let mut out = Vec::with_capacity(vec_size);
            for inp in input.iter() {
                let mut tmp = Vec::with_capacity(entries);
                let mut acc = ark_bn254::Fr::from(1u64);
                for &i in inp.iter() {
                    acc *= i;
                    tmp.push(acc);
                }
                out.push(tmp);
            }
            out
        };
        assert_eq!(is_result, should_result);
    }
}

#[cfg(test)]
mod round_tests {
    use crate::{CoUtils, mpc::NoirUltraHonkProver, mpc::rep3::Rep3UltraHonkDriver};
    use ark_bn254::{Fr, G1Projective};
    use ark_ff::{One, UniformRand};
    use bytes::Bytes;
    use mpc_core::protocols::rep3::{self, Rep3State, conversion::A2BType};
    use mpc_net::{ConnectionStats, Network, local::LocalNetwork};
    use std::sync::atomic::{AtomicUsize, Ordering};

    type Driver = Rep3UltraHonkDriver;
    type Share = <Driver as NoirUltraHonkProver<G1Projective>>::ArithmeticShare;

    /// Counts the messages a party sends and records the largest one.
    struct CountingNetwork {
        inner: LocalNetwork,
        sent: AtomicUsize,
        max_frame: AtomicUsize,
    }

    impl CountingNetwork {
        fn sent(&self) -> usize {
            self.sent.load(Ordering::SeqCst)
        }
    }

    impl Network for CountingNetwork {
        fn id(&self) -> usize {
            self.inner.id()
        }

        fn send(&self, to: usize, data: Bytes) -> eyre::Result<()> {
            self.sent.fetch_add(1, Ordering::SeqCst);
            self.max_frame.fetch_max(data.len(), Ordering::SeqCst);
            self.inner.send(to, data)
        }

        fn recv(&self, from: usize) -> eyre::Result<Bytes> {
            self.inner.recv(from)
        }

        fn get_connection_stats(&self) -> ConnectionStats {
            self.inner.get_connection_stats()
        }
    }

    /// Runs `array_prod_mul` and `array_prod_inner_mul_many` in three parties and returns the
    /// reconstructed results, together with the messages party 0 sent for each of them and
    /// for one `mul_many`, `inv_many` and `mul_open_many` of the same length.
    fn run(inp: &[Fr]) -> (Vec<Fr>, Vec<Fr>, [usize; 5]) {
        let mut rng = rand::thread_rng();
        let [s0, s1, s2] = rep3::share_field_elements(inp, &mut rng);
        let results: Vec<_> = LocalNetwork::new_3_parties()
            .into_iter()
            .zip([s0, s1, s2])
            .map(|(inner, shares)| {
                std::thread::spawn(move || {
                    let net = CountingNetwork {
                        inner,
                        sent: AtomicUsize::new(0),
                        max_frame: AtomicUsize::new(0),
                    };
                    let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                    let mut sent = [0; 5];

                    let before = net.sent();
                    let prod = CoUtils::array_prod_mul::<Driver, G1Projective, _>(
                        &net, &mut state, &shares,
                    )
                    .unwrap();
                    sent[0] = net.sent() - before;

                    let before = net.sent();
                    let inner_prod = CoUtils::array_prod_inner_mul_many::<Driver, G1Projective, _>(
                        &net,
                        &mut state,
                        &[shares.clone(), shares.clone()],
                    )
                    .unwrap();
                    sent[1] = net.sent() - before;

                    let before = net.sent();
                    <Driver as NoirUltraHonkProver<G1Projective>>::mul_many(
                        &shares, &shares, &net, &mut state,
                    )
                    .unwrap();
                    sent[2] = net.sent() - before;

                    let before = net.sent();
                    <Driver as NoirUltraHonkProver<G1Projective>>::inv_many(
                        &shares, &net, &mut state,
                    )
                    .unwrap();
                    sent[3] = net.sent() - before;

                    let before = net.sent();
                    <Driver as NoirUltraHonkProver<G1Projective>>::mul_open_many(
                        &shares, &shares, &net, &mut state,
                    )
                    .unwrap();
                    sent[4] = net.sent() - before;

                    (prod, inner_prod, sent)
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|t| t.join().unwrap())
            .collect();
        let combine =
            |f: &dyn Fn(usize) -> Vec<Share>| rep3::combine_field_elements(&f(0), &f(1), &f(2));
        let prod = combine(&|i| results[i].0.clone());
        let inner = combine(&|i| results[i].1.concat());
        (prod, inner, results[0].2)
    }

    #[test]
    fn array_prod_mul_uses_one_multiplication_round() {
        let mut rng = rand::thread_rng();
        let inp: Vec<Fr> = (0..17).map(|_| Fr::rand(&mut rng)).collect();
        let (prod, inner, sent) = run(&inp);

        let mut acc = Fr::one();
        let expected: Vec<Fr> = inp
            .iter()
            .map(|x| {
                acc *= x;
                acc
            })
            .collect();
        assert_eq!(prod, expected);
        assert_eq!(inner, [expected.clone(), expected].concat());

        // One multiplication round for the unblinding factors and the blinded inputs together,
        // one inversion of the masks and one opening.
        let [array_prod, inner_prod, mul, inv, open] = sent;
        assert!(mul > 0);
        assert_eq!(array_prod, mul + inv + open);
        assert_eq!(inner_prod, mul + inv + open);
    }

    #[test]
    fn mul_many_bounded_keeps_messages_within_the_default_frame() {
        let max_len = CoUtils::max_mul_many_len::<Fr>();
        let len = max_len + 3;
        let a: Vec<Fr> = (0..len as u64).map(Fr::from).collect();
        let b: Vec<Fr> = (0..len as u64).map(|i| Fr::from(i + 7)).collect();
        let mut rng = rand::thread_rng();
        let a_shares = rep3::share_field_elements(&a, &mut rng);
        let b_shares = rep3::share_field_elements(&b, &mut rng);
        let results: Vec<_> = LocalNetwork::new_3_parties()
            .into_iter()
            .zip(a_shares.into_iter().zip(b_shares))
            .map(|(inner, (a, b))| {
                std::thread::spawn(move || {
                    let net = CountingNetwork {
                        inner,
                        sent: AtomicUsize::new(0),
                        max_frame: AtomicUsize::new(0),
                    };
                    let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                    let before = net.sent();
                    let c = CoUtils::mul_many_bounded::<Driver, G1Projective, _>(
                        &a, &b, &net, &mut state,
                    )
                    .unwrap();
                    (c, net.sent() - before, net.max_frame.load(Ordering::SeqCst))
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|t| t.join().unwrap())
            .collect();
        let c = rep3::combine_field_elements(&results[0].0, &results[1].0, &results[2].0);
        assert!(
            c.iter()
                .zip(a.iter().zip(&b))
                .all(|(c, (a, b))| *c == *a * b)
        );
        for (_, sent, max_frame) in &results {
            assert_eq!(*sent, 2);
            assert!(*max_frame <= mpc_net::DEFAULT_MAX_FRAME_LENGTH);
        }
    }
}

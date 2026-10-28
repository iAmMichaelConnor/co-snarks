//! Private BN254 non-native witness arithmetic. Integer operations deliberately
//! accept unreduced Fr limbs: the circuit, not this witness adapter, constrains
//! their eventual ranges. No value-dependent widths or unmasked openings occur.
use super::{Rep3AcvmType, downcast};
use ark_bn254::{Fq, Fr};
use ark_ff::{Field, One, PrimeField, Zero};
use mpc_core::protocols::rep3::{
    Rep3PrimeFieldShare as Share, Rep3State, Rep3UintShare, arithmetic, conversion,
};
use mpc_core::protocols::rep3_ring::ring::{int_ring::IntRing2k, ring_impl::RingElement};
use mpc_core::protocols::rep3_ring::{
    Rep3RingShare, arithmetic as ring, conversion as ring_conversion,
};
use mpc_core::uint::{U256, U512, UintBackend};
use mpc_net::Network;
use rand::{distributions::Standard, prelude::Distribution};

pub(super) fn ensure_bn254<
    F: PrimeField,
    C: ark_ec::CurveGroup<ScalarField = F, BaseField: PrimeField>,
>() -> eyre::Result<()> {
    eyre::ensure!(
        std::any::TypeId::of::<F>() == std::any::TypeId::of::<Fr>()
            && std::any::TypeId::of::<C::BaseField>() == std::any::TypeId::of::<Fq>(),
        "Private non-native arithmetic supports only BN254 Fr/Fq"
    );
    Ok(())
}
pub(super) fn cast<A: 'static, B: Clone + 'static>(value: &A) -> eyre::Result<B> {
    downcast(value)
        .cloned()
        .ok_or_else(|| eyre::eyre!("Private non-native arithmetic supports only BN254 Fr/Fq"))
}
fn share<F: PrimeField>(value: &Rep3AcvmType<F>, state: &Rep3State) -> Share<F> {
    match value {
        Rep3AcvmType::Public(x) => arithmetic::promote_to_trivial_share(state.id, *x),
        Rep3AcvmType::Shared(x) => *x,
    }
}
pub(super) fn reconstruct<const L: usize, const B: usize, N: Network>(
    limbs: &[Rep3AcvmType<Fr>; L],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Share<Fq>> {
    eyre::ensure!(
        B > 0 && B <= 253,
        "Private limb width must be between 1 and 253 bits"
    );
    if L == 0 {
        return Ok(Share::zero_share());
    }
    let input: Vec<_> = limbs.iter().map(|v| share(v, state)).collect();
    let bits = conversion::a2b_many(&input, net, state)?;
    // Every canonical Fr integer is below Fq, so this cross-field b2a is exact.
    let bits: Vec<_> = bits
        .into_iter()
        .map(|v| Rep3UintShare::<Fq>::new(v.a, v.b))
        .collect();
    let values = conversion::b2a_many(&bits, net, state)?;
    let radix = Fq::from(2u64).pow([B as u64]);
    let mut power = Fq::one();
    let mut sum = Share::zero_share();
    for v in values {
        sum = arithmetic::add(sum, arithmetic::mul_public(v, power));
        power *= radix;
    }
    Ok(sum)
}
pub(super) fn decompose<const L: usize, const B: usize, N: Network>(
    value: Share<Fq>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<[Rep3AcvmType<Fr>; L]> {
    eyre::ensure!(
        B > 0 && B <= 253,
        "Private limb width must be between 1 and 253 bits"
    );
    let value = conversion::a2b_selector(value, net, state)?;
    let mask = (U256::from(1u64) << B) - U256::from(1u64);
    let bits: Vec<_> = (0..L)
        .map(|i| {
            let shift = i.saturating_mul(B);
            if shift >= 256 {
                Rep3UintShare::<Fr>::new(U256::zero(), U256::zero())
            } else {
                Rep3UintShare::<Fr>::new((value.a >> shift) & mask, (value.b >> shift) & mask)
            }
        })
        .collect();
    Ok(conversion::b2a_many(&bits, net, state)?
        .into_iter()
        .map(Rep3AcvmType::Shared)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap_or_else(|_| panic!("fixed limb count")))
}
fn raw_many<T: IntRing2k, N: Network>(
    values: &[[Rep3AcvmType<Fr>; 4]],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3RingShare<T>>>
where
    Standard: Distribution<T>,
{
    if values.is_empty() {
        return Ok(Vec::new());
    }
    let inputs: Vec<_> = values.iter().flatten().map(|v| share(v, state)).collect();
    let limbs = mpc_core::protocols::rep3_ring::casts::field_to_ring_a2b_many::<Fr, T, _>(
        &inputs, net, state,
    )?;
    Ok(limbs
        .chunks_exact(4)
        .map(|limbs| {
            let mut result = Rep3RingShare::zero_share();
            for (i, limb) in limbs.iter().enumerate() {
                result = ring::add(
                    result,
                    ring::mul_public(*limb, RingElement(T::one() << (68 * i))),
                );
            }
            result
        })
        .collect())
}
fn raw_limbs<T: IntRing2k, N: Network>(
    value: Rep3RingShare<T>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<[Rep3AcvmType<Fr>; 4]>
where
    Standard: Distribution<T>,
{
    let bits = ring_conversion::a2b(value, net, state)?;
    let mask = (U256::from(1u64) << 68) - U256::from(1u64);
    let limbs: Vec<_> = (0..4)
        .map(|i| {
            Rep3UintShare::<Fr>::new(
                (bits.a.0 >> (68 * i)).cast_to_uint::<U256>() & mask,
                (bits.b.0 >> (68 * i)).cast_to_uint::<U256>() & mask,
            )
        })
        .collect();
    Ok(conversion::b2a_many(&limbs, net, state)?
        .into_iter()
        .map(Rep3AcvmType::Shared)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap_or_else(|_| panic!("four limbs")))
}
pub(super) fn add<N: Network>(
    a: &[Rep3AcvmType<Fr>; 4],
    b: &[Rep3AcvmType<Fr>; 4],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<[Rep3AcvmType<Fr>; 4]> {
    // Each raw four-limb integer is <2^459, so addition cannot wrap U512.
    let raw = raw_many::<U512, _>(&[a.clone(), b.clone()], net, state)?;
    raw_limbs(ring::add(raw[0], raw[1]), net, state)
}
pub(super) fn sub<N: Network>(
    a: &[Rep3AcvmType<Fr>; 4],
    b: &[Rep3AcvmType<Fr>; 4],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<[Rep3AcvmType<Fr>; 4]> {
    let raw = raw_many::<U512, _>(&[a.clone(), b.clone()], net, state)?;
    let negative = ring::lt(raw[0], raw[1], net, state)?;
    let negative =
        ring_conversion::bit_inject_from_bits_to_field_many::<Fr, _>(&[negative], net, state)?[0];
    let positive = raw_limbs(ring::sub(raw[0], raw[1]), net, state)?;
    let aq = reconstruct::<4, 68, _>(a, net, state)?;
    let bq = reconstruct::<4, 68, _>(b, net, state)?;
    let reduced = decompose::<4, 68, _>(arithmetic::sub(aq, bq), net, state)?;
    let positive = positive.map(|v| share(&v, state));
    let reduced = reduced.map(|v| share(&v, state));
    Ok(
        arithmetic::cmux_vec(negative, &reduced, &positive, net, state)?
            .into_iter()
            .map(Rep3AcvmType::Shared)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap_or_else(|_| panic!("four selected limbs")),
    )
}
// Preserve each original canonical Fr limb in both domains. In particular, the
// Fq value must not be reconstructed from the truncated U512 integer: products
// can exceed 900 bits, and their high bits affect the canonical Fq remainder.
#[allow(clippy::type_complexity)]
fn dual_raw_many<N: Network>(
    values: &[[Rep3AcvmType<Fr>; 4]],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<(Vec<Rep3RingShare<U512>>, Vec<Share<Fq>>)> {
    if values.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    let inputs: Vec<_> = values.iter().flatten().map(|v| share(v, state)).collect();
    let bits = conversion::a2b_many(&inputs, net, state)?;
    let ring_bits: Vec<_> = bits
        .iter()
        .map(|v| Rep3RingShare {
            a: RingElement(U512::cast_from_uint(&v.a)),
            b: RingElement(U512::cast_from_uint(&v.b)),
        })
        .collect();
    let field_bits: Vec<_> = bits
        .iter()
        .map(|v| Rep3UintShare::<Fq>::new(v.a, v.b))
        .collect();
    // Each conversion draws fresh masks; only the original binary shares are
    // reused. Canonical Fr integers fit Fq because Fr::MODULUS < Fq::MODULUS.
    let rings = ring_conversion::b2a_many(&ring_bits, net, state)?;
    let fields = conversion::b2a_many(&field_bits, net, state)?;
    let rings = rings
        .chunks_exact(4)
        .map(|limbs| {
            limbs
                .iter()
                .enumerate()
                .fold(Rep3RingShare::zero_share(), |sum, (i, limb)| {
                    ring::add(
                        sum,
                        ring::mul_public(*limb, RingElement(U512::one() << (68 * i))),
                    )
                })
        })
        .collect();
    let fields = fields
        .chunks_exact(4)
        .map(|limbs| {
            limbs
                .iter()
                .enumerate()
                .fold(Share::zero_share(), |sum, (i, limb)| {
                    arithmetic::add(
                        sum,
                        arithmetic::mul_public(*limb, Fq::from(2u64).pow([(68 * i) as u64])),
                    )
                })
        })
        .collect();
    Ok((rings, fields))
}
fn quotient<N: Network>(
    value: Rep3RingShare<U512>,
    remainder: Share<Fq>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<([Rep3AcvmType<Fr>; 4], Rep3AcvmType<Fq>)> {
    // For the unbounded nonnegative integer X = q*p + r, odd p is invertible
    // modulo 2^512. Thus (Xlow512 - canonical(r))*p^-1 recovers q mod 2^512,
    // even if X is much wider. raw_limbs retains precisely the API's low272 q.
    let inverse = *std::sync::LazyLock::force(&MODULUS_INVERSE);
    let remainder_ring = mpc_core::protocols::rep3_ring::casts::field_to_ring_a2b::<Fq, U512, _>(
        remainder, net, state,
    )?;
    let quotient = ring::mul_public(ring::sub(value, remainder_ring), inverse);
    Ok((
        raw_limbs(quotient, net, state)?,
        Rep3AcvmType::Shared(remainder),
    ))
}
static MODULUS_INVERSE: std::sync::LazyLock<RingElement<U512>> = std::sync::LazyLock::new(|| {
    let modulus = RingElement(U512::from_limbs_truncating(Fq::MODULUS.as_ref()));
    let mut inverse = RingElement(U512::one());
    // Newton iteration doubles the correct bit count from one to 512.
    for _ in 0..9 {
        inverse = inverse * (RingElement(U512::from(2u64)) - modulus * inverse);
    }
    assert_eq!(modulus * inverse, RingElement(U512::one()));
    inverse
});
pub(super) fn divmod<N: Network>(
    a: &[Rep3AcvmType<Fr>; 4],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<([Rep3AcvmType<Fr>; 4], Rep3AcvmType<Fq>)> {
    let (raw, reduced) = dual_raw_many(std::slice::from_ref(a), net, state)?;
    quotient(raw[0], reduced[0], net, state)
}
pub(super) fn madd<N: Network>(
    a: &[[Rep3AcvmType<Fr>; 4]],
    b: &[[Rep3AcvmType<Fr>; 4]],
    add: &[[Rep3AcvmType<Fr>; 4]],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<([Rep3AcvmType<Fr>; 4], Rep3AcvmType<Fq>)> {
    eyre::ensure!(
        a.len() == b.len(),
        "Non-native product vectors must have equal lengths"
    );
    let inputs: Vec<_> = a.iter().chain(b).chain(add).cloned().collect();
    let (raw, reduced) = dual_raw_many(&inputs, net, state)?;
    let n = a.len();
    let (products, reduced_products) = if n == 0 {
        (Vec::new(), Vec::new())
    } else {
        (
            ring::mul_vec(&raw[..n], &raw[n..2 * n], net, state)?,
            arithmetic::mul_vec(&reduced[..n], &reduced[n..2 * n], net, state)?,
        )
    };
    let value = products
        .into_iter()
        .chain(raw[2 * n..].iter().copied())
        .fold(Rep3RingShare::zero_share(), ring::add);
    let remainder = reduced_products
        .into_iter()
        .chain(reduced[2 * n..].iter().copied())
        .fold(Share::zero_share(), arithmetic::add);
    quotient(value, remainder, net, state)
}
pub(super) fn inv0<N: Network>(
    value: Share<Fq>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Share<Fq>> {
    let zero = arithmetic::eq_public(value, Fq::zero(), net, state)?;
    // Invert a guaranteed nonzero secret, so the masked opening in inv reveals
    // neither whether the original value was zero nor any other predicate.
    let safe = arithmetic::add(value, zero);
    let inverse = arithmetic::inv(safe, net, state)?;
    arithmetic::mul(
        inverse,
        arithmetic::sub_public_by_shared(Fq::one(), zero, state.id),
        net,
        state,
    )
}

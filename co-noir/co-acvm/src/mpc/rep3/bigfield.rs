//! Secret-shared BN254 non-native field arithmetic on the 4 × 68-bit limb representation used by
//! the circuit builder's `BigField`.
//!
//! As in the plain driver, the limbs are canonical `Fr` values and need not be reduced 68-bit
//! limbs: the circuit constrains their ranges. All conversions have a fixed, public width, and
//! nothing is opened.
use super::super::downcast;
use super::Rep3AcvmType;
use ark_bn254::{Fq, Fr};
use ark_ec::CurveGroup;
use ark_ff::{Field, One, PrimeField};
use mpc_core::protocols::rep3::{
    Rep3PrimeFieldShare, Rep3State, Rep3UintShare, arithmetic, conversion,
};
use mpc_core::protocols::rep3_ring::ring::{int_ring::IntRing2k, ring_impl::RingElement};
use mpc_core::protocols::rep3_ring::{
    Rep3RingShare, arithmetic as ring, casts as ring_casts, conversion as ring_conversion,
};
use mpc_core::uint::{U256, U512, UintBackend};
use mpc_net::Network;
use std::sync::LazyLock;

const LIMB_BITS: usize = 68;

/// The limbs of a `BigField` element.
pub(super) type Limbs = [Rep3AcvmType<Fr>; 4];

/// Fails unless the driver works on BN254's scalar field and the non-native field is BN254's
/// base field, the only combination used by the recursive verifier.
pub(super) fn ensure_bn254<F: PrimeField, C: CurveGroup<ScalarField = F, BaseField: PrimeField>>()
-> eyre::Result<()> {
    eyre::ensure!(
        std::any::TypeId::of::<F>() == std::any::TypeId::of::<Fr>()
            && std::any::TypeId::of::<C::BaseField>() == std::any::TypeId::of::<Fq>(),
        "Secret-shared non-native field arithmetic is only supported for BN254"
    );
    Ok(())
}

/// Converts between a generic type and its BN254 instance, see [`ensure_bn254`].
pub(super) fn cast<A: 'static, B: Clone + 'static>(value: &A) -> eyre::Result<B> {
    downcast(value).cloned().ok_or_else(|| {
        eyre::eyre!("Secret-shared non-native field arithmetic is only supported for BN254")
    })
}

fn to_share<F: PrimeField>(
    value: &Rep3AcvmType<F>,
    id: mpc_core::protocols::rep3::id::PartyID,
) -> Rep3PrimeFieldShare<F> {
    match value {
        Rep3AcvmType::Public(x) => arithmetic::promote_to_trivial_share(id, *x),
        Rep3AcvmType::Shared(x) => *x,
    }
}

fn shares<const L: usize>(
    values: &[[Rep3AcvmType<Fr>; L]],
    state: &Rep3State,
) -> Vec<Rep3PrimeFieldShare<Fr>> {
    values
        .iter()
        .flatten()
        .map(|v| to_share(v, state.id))
        .collect()
}

/// Bit-composes `Fr` binary shares into `Fq` arithmetic shares. Canonical `Fr` integers are
/// smaller than the `Fq` modulus, so the value is the same integer.
fn fr_bits_to_fq<N: Network>(
    bits: &[Rep3UintShare<Fr>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<Fq>>> {
    let bits: Vec<_> = bits
        .iter()
        .map(|v| Rep3UintShare::<Fq>::new(v.a, v.b))
        .collect();
    conversion::b2a_many(&bits, net, state)
}

/// sum_i limbs[i] * 2^(i * B) in `Fq`, i.e. reduced modulo the `Fq` modulus.
pub(super) fn limbs_to_fq<const L: usize, const B: usize, N: Network>(
    limbs: &[Rep3AcvmType<Fr>; L],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Rep3PrimeFieldShare<Fq>> {
    let bits = conversion::a2b_many(&shares(std::slice::from_ref(limbs), state), net, state)?;
    let values = fr_bits_to_fq(&bits, net, state)?;
    let radix = Fq::from(2u64).pow([B as u64]);
    let mut power = Fq::one();
    let mut sum = Rep3PrimeFieldShare::zero_share();
    for value in values {
        sum = arithmetic::add(sum, arithmetic::mul_public(value, power));
        power *= radix;
    }
    Ok(sum)
}

/// The `L` limbs of `B` bits of the canonical integer of `value`; bits beyond `L * B` are
/// dropped.
pub(super) fn fq_to_limbs<const L: usize, const B: usize, N: Network>(
    value: Rep3PrimeFieldShare<Fq>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<[Rep3AcvmType<Fr>; L]> {
    eyre::ensure!(
        B > 0 && B < Fr::MODULUS_BIT_SIZE as usize,
        "Limbs of {B} bits do not fit into the scalar field"
    );
    let bits = conversion::a2b_selector(value, net, state)?;
    let mask = (U256::from(1u64) << B) - U256::from(1u64);
    let limbs: Vec<_> = (0..L)
        .map(|i| match i.checked_mul(B).filter(|shift| *shift < 256) {
            Some(shift) => {
                Rep3UintShare::<Fr>::new((bits.a >> shift) & mask, (bits.b >> shift) & mask)
            }
            None => Rep3UintShare::<Fr>::new(U256::zero(), U256::zero()),
        })
        .collect();
    let limbs = conversion::b2a_many(&limbs, net, state)?;
    Ok(std::array::from_fn(|i| Rep3AcvmType::Shared(limbs[i])))
}

/// The 4 × 68-bit limbs of the low 272 bits of `value`.
fn ring_to_limbs<N: Network>(
    value: Rep3RingShare<U512>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Limbs> {
    let bits = ring_conversion::a2b(value, net, state)?;
    let mask = (U256::from(1u64) << LIMB_BITS) - U256::from(1u64);
    let limbs: Vec<_> = (0..4)
        .map(|i| {
            let shift = LIMB_BITS * i;
            Rep3UintShare::<Fr>::new(
                (bits.a.0 >> shift).cast_to_uint::<U256>() & mask,
                (bits.b.0 >> shift).cast_to_uint::<U256>() & mask,
            )
        })
        .collect();
    let limbs = conversion::b2a_many(&limbs, net, state)?;
    Ok(std::array::from_fn(|i| Rep3AcvmType::Shared(limbs[i])))
}

/// The integers sum_i limbs[i] * 2^(68 * i) of the given limbs, as shares in Z_(2^512). A limb is
/// below 2^254, so such an integer is below 2^459 and sums of two do not wrap.
fn limbs_to_ring<N: Network>(
    values: &[Limbs],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3RingShare<U512>>> {
    let limbs =
        ring_casts::field_to_ring_a2b_many::<Fr, U512, _>(&shares(values, state), net, state)?;
    Ok(limbs.as_chunks::<4>().0.iter().map(compose_ring).collect())
}

fn compose_ring(limbs: &[Rep3RingShare<U512>; 4]) -> Rep3RingShare<U512> {
    limbs
        .iter()
        .enumerate()
        .fold(Rep3RingShare::zero_share(), |sum, (i, limb)| {
            ring::add(
                sum,
                ring::mul_public(*limb, RingElement(U512::one() << (LIMB_BITS * i))),
            )
        })
}

fn compose_fq(limbs: &[Rep3PrimeFieldShare<Fq>; 4]) -> Rep3PrimeFieldShare<Fq> {
    limbs
        .iter()
        .enumerate()
        .fold(Rep3PrimeFieldShare::zero_share(), |sum, (i, limb)| {
            arithmetic::add(
                sum,
                arithmetic::mul_public(*limb, Fq::from(2u64).pow([(LIMB_BITS * i) as u64])),
            )
        })
}

type RingAndFq = (Vec<Rep3RingShare<U512>>, Vec<Rep3PrimeFieldShare<Fq>>);

/// The integers of the given limbs both in Z_(2^512) and reduced in `Fq`. The `Fq` values come
/// from the limbs, not from the ring values: products of ring values can exceed 2^512.
fn limbs_to_ring_and_fq<N: Network>(
    values: &[Limbs],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<RingAndFq> {
    let bits = conversion::a2b_many(&shares(values, state), net, state)?;
    let ring_bits: Vec<_> = bits
        .iter()
        .map(|v| Rep3RingShare {
            a: RingElement(U512::cast_from_uint(&v.a)),
            b: RingElement(U512::cast_from_uint(&v.b)),
        })
        .collect();
    let rings = ring_conversion::b2a_many(&ring_bits, net, state)?;
    let fields = fr_bits_to_fq(&bits, net, state)?;
    Ok((
        rings.as_chunks::<4>().0.iter().map(compose_ring).collect(),
        fields.as_chunks::<4>().0.iter().map(compose_fq).collect(),
    ))
}

/// The inverse of the `Fq` modulus in Z_(2^512) (the modulus is odd).
static MODULUS_INVERSE: LazyLock<RingElement<U512>> = LazyLock::new(|| {
    let modulus = RingElement(U512::from_limbs_truncating(Fq::MODULUS.as_ref()));
    // Newton's iteration doubles the number of correct low bits, from 1 to 512.
    let mut inverse = RingElement(U512::one());
    for _ in 0..9 {
        inverse = inverse * (RingElement(U512::from(2u64)) - modulus * inverse);
    }
    assert_eq!(modulus * inverse, RingElement(U512::one()));
    inverse
});

/// For an integer x >= 0 given by its low 512 bits `value` and its residue `remainder` modulo
/// the `Fq` modulus p, returns the limbs of the low 272 bits of the quotient q = (x - r) / p and
/// r. Since x - r = q * p exactly, q mod 2^512 = (value - r) * p^-1 in Z_(2^512), even if x has
/// more than 512 bits.
fn quotient_and_remainder<N: Network>(
    value: Rep3RingShare<U512>,
    remainder: Rep3PrimeFieldShare<Fq>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<(Limbs, Rep3AcvmType<Fq>)> {
    let remainder_ring = ring_casts::field_to_ring_a2b::<Fq, U512, _>(remainder, net, state)?;
    let quotient = ring::mul_public(ring::sub(value, remainder_ring), *MODULUS_INVERSE);
    Ok((
        ring_to_limbs(quotient, net, state)?,
        Rep3AcvmType::Shared(remainder),
    ))
}

/// The limbs of a + b (no reduction).
pub(super) fn add<N: Network>(
    a: &Limbs,
    b: &Limbs,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Limbs> {
    let values = limbs_to_ring(&[a.clone(), b.clone()], net, state)?;
    ring_to_limbs(ring::add(values[0], values[1]), net, state)
}

/// The limbs of a - b if a >= b, otherwise of (a - b) mod p, as in the plain driver.
pub(super) fn sub<N: Network>(
    a: &Limbs,
    b: &Limbs,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Limbs> {
    let values = limbs_to_ring(&[a.clone(), b.clone()], net, state)?;
    let negative = ring::lt(values[0], values[1], net, state)?;
    let negative =
        ring_conversion::bit_inject_from_bits_to_field_many::<Fr, _>(&[negative], net, state)?[0];
    let difference = ring_to_limbs(ring::sub(values[0], values[1]), net, state)?;
    let a = limbs_to_fq::<4, LIMB_BITS, _>(a, net, state)?;
    let b = limbs_to_fq::<4, LIMB_BITS, _>(b, net, state)?;
    let reduced = fq_to_limbs::<4, LIMB_BITS, _>(arithmetic::sub(a, b), net, state)?;
    let selected = arithmetic::cmux_vec(
        negative,
        &reduced.map(|v| to_share(&v, state.id)),
        &difference.map(|v| to_share(&v, state.id)),
        net,
        state,
    )?;
    Ok(std::array::from_fn(|i| Rep3AcvmType::Shared(selected[i])))
}

/// The quotient limbs and the remainder of a divided by p.
pub(super) fn div_mod<N: Network>(
    a: &Limbs,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<(Limbs, Rep3AcvmType<Fq>)> {
    let (values, residues) = limbs_to_ring_and_fq(std::slice::from_ref(a), net, state)?;
    quotient_and_remainder(values[0], residues[0], net, state)
}

/// The quotient limbs and the remainder of sum_i a[i] * b[i] + sum_j to_add[j] divided by p.
pub(super) fn madd_div_mod<N: Network>(
    a: &[Limbs],
    b: &[Limbs],
    to_add: &[Limbs],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<(Limbs, Rep3AcvmType<Fq>)> {
    eyre::ensure!(a.len() == b.len(), "a and b must have the same length");
    let n = a.len();
    let inputs: Vec<_> = a.iter().chain(b).chain(to_add).cloned().collect();
    let (values, residues) = limbs_to_ring_and_fq(&inputs, net, state)?;
    let (products, residue_products) = if n == 0 {
        (Vec::new(), Vec::new())
    } else {
        (
            ring::mul_vec(&values[..n], &values[n..2 * n], net, state)?,
            arithmetic::mul_vec(&residues[..n], &residues[n..2 * n], net, state)?,
        )
    };
    let value = products
        .into_iter()
        .chain(values[2 * n..].iter().copied())
        .fold(Rep3RingShare::zero_share(), ring::add);
    let remainder = residue_products
        .into_iter()
        .chain(residues[2 * n..].iter().copied())
        .fold(Rep3PrimeFieldShare::zero_share(), arithmetic::add);
    quotient_and_remainder(value, remainder, net, state)
}

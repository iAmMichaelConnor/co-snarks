//! ECDSA signature verification (secp256k1, secp256r1) on REP3-shared inputs.
//!
//! The inputs are bytes shared over the ACVM field `F`. Every 256-bit value (message hash,
//! public key coordinates, `r`, `s`) is recomposed into two 128-bit halves over `F`, where the
//! range checks of the black box are done. The halves are then moved into the base field `Fq` or
//! the scalar field `Fr` of the curve (arithmetic to binary over `F`, binary to arithmetic over
//! the target field), where the verification equation is evaluated on shared field elements and
//! shared curve points. The resulting flags are moved back to `F` and multiplied together.
//!
//! Nothing about the inputs is opened. Invalid inputs make the verification return a shared 0:
//! an invalid public key is replaced by `2 * G` before it is used as a curve point, and `s = 0`
//! is inverted to 0 (see [`arithmetic::inv0`]).

use super::Rep3AcvmType;
use ark_ec::{
    AffineRepr,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
};
use ark_ff::{One, PrimeField, Zero};
use mpc_core::protocols::rep3::{
    Rep3PrimeFieldShare, Rep3State, Rep3UintShare, arithmetic, conversion, pointshare,
};
use mpc_core::uint::{FieldUint, UintBackend};
use mpc_net::Network;
use num_bigint::BigUint;

#[cfg(test)]
mod tests;

type Share<F> = Rep3PrimeFieldShare<F>;

/// A 256-bit value given as big-endian bytes, recomposed into two 128-bit halves over `F`.
#[derive(Clone, Copy)]
struct Halves<F: PrimeField> {
    hi: Share<F>,
    lo: Share<F>,
}

fn split_u256(value: &BigUint) -> (BigUint, BigUint) {
    let mask = (BigUint::one() << 128) - BigUint::one();
    (value >> 128, value & mask)
}

/// Recomposes 32 big-endian bytes into two 128-bit halves.
///
/// Shared bytes cannot be range checked here. A shared "byte" that is not smaller than 256 gives
/// an unspecified output bit, but never aborts the computation. As for the other black boxes,
/// soundness relies on the circuit, which constrains these inputs to be bytes when it is proven.
fn compose<F: FieldUint>(bytes: &[Rep3AcvmType<F>], state: &Rep3State) -> Halves<F> {
    debug_assert_eq!(bytes.len(), 32);
    let half = |bytes: &[Rep3AcvmType<F>]| {
        let mut acc = Share::<F>::zero_share();
        let mut public = F::zero();
        for byte in bytes {
            acc *= F::from(256u64);
            public *= F::from(256u64);
            match byte {
                Rep3AcvmType::Public(value) => public += value,
                Rep3AcvmType::Shared(value) => acc += *value,
            }
        }
        arithmetic::add_public(acc, public, state.id)
    };
    Halves {
        hi: half(&bytes[..16]),
        lo: half(&bytes[16..]),
    }
}

/// Returns shared bits over `F`: for every `(value, bound)`, 1 iff `value < bound`, where `value`
/// is a 256-bit value given by its halves; then, for every value of `zero_checks`, 1 iff it is
/// zero.
fn range_checks<F: FieldUint, N: Network>(
    checks: &[(Halves<F>, BigUint)],
    zero_checks: &[Halves<F>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Share<F>>> {
    // value < bound iff hi < bound_hi, or hi == bound_hi and lo < bound_lo. The two cases are
    // exclusive, so their sum is their disjunction.
    let mut hi_lt = Vec::with_capacity(checks.len());
    let mut lo_lt = Vec::with_capacity(checks.len());
    let mut eq_lhs = Vec::with_capacity(checks.len() + 2 * zero_checks.len());
    let mut eq_rhs = Vec::with_capacity(checks.len() + 2 * zero_checks.len());
    for (value, bound) in checks {
        let (bound_hi, bound_lo) = split_u256(bound);
        let (bound_hi, bound_lo) = (F::from(bound_hi), F::from(bound_lo));
        hi_lt.push(arithmetic::lt_public(value.hi, bound_hi, net, state)?);
        lo_lt.push(arithmetic::lt_public(value.lo, bound_lo, net, state)?);
        eq_lhs.push(value.hi);
        eq_rhs.push(bound_hi);
    }
    for value in zero_checks {
        eq_lhs.extend([value.hi, value.lo]);
        eq_rhs.extend([F::zero(); 2]);
    }
    let eq = arithmetic::eq_public_many(&eq_lhs, &eq_rhs, net, state)?;
    let (hi_eq, zero_halves) = eq.split_at(checks.len());

    let mut lhs = hi_eq.to_vec();
    let mut rhs = lo_lt;
    for &[hi_is_zero, lo_is_zero] in zero_halves.as_chunks::<2>().0 {
        lhs.push(hi_is_zero);
        rhs.push(lo_is_zero);
    }
    let products = arithmetic::mul_vec(&lhs, &rhs, net, state)?;
    let (hi_eq_lo_lt, is_zero) = products.split_at(checks.len());
    let mut result = hi_lt
        .into_iter()
        .zip(hi_eq_lo_lt)
        .map(|(hi_lt, hi_eq_lo_lt)| arithmetic::add(hi_lt, *hi_eq_lo_lt))
        .collect::<Vec<_>>();
    result.extend_from_slice(is_zero);
    Ok(result)
}

/// The binary sharings of the two halves of a 256-bit value.
type BinaryHalves<F> = [Rep3UintShare<F>; 2];

/// Converts 256-bit values, given by their halves over `F`, into binary sharings.
fn to_binary<F: FieldUint, N: Network>(
    values: &[Halves<F>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<BinaryHalves<F>>> {
    let halves = values
        .iter()
        .flat_map(|value| [value.hi, value.lo])
        .collect::<Vec<_>>();
    let bits = conversion::a2b_selector_many(&halves, net, state)?;
    let (pairs, rest) = bits.as_chunks::<2>();
    debug_assert!(rest.is_empty());
    Ok(pairs.to_vec())
}

/// Moves a 256-bit value, given by the binary sharings of its halves over `F`, into the field
/// `K`, reducing it modulo the modulus of `K`, which must have 256 bits.
fn to_field<F: FieldUint, K: FieldUint, N: Network>(
    [hi, lo]: &BinaryHalves<F>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Share<K>> {
    // b2a_mod_p reduces values below 2^MODULUS_BIT_SIZE with one subtraction of the modulus.
    const { assert!(K::MODULUS_BIT_SIZE == 256) };
    // Each half is smaller than 2^128, so cutting the binary shares to their low 128 bits keeps
    // the shared value.
    let mask = K::Uint::mask(128);
    let low_128 = |value: &F::Uint| K::Uint::from_limbs_truncating(value.as_limbs()) & mask;
    let combined = Rep3UintShare::<K>::new(
        (low_128(&hi.a) << 128) | low_128(&lo.a),
        (low_128(&hi.b) << 128) | low_128(&lo.b),
    );
    conversion::b2a_selector_mod_p(&combined, net, state)
}

/// Moves a shared bit, given as a binary sharing over `K`, into an arithmetic sharing over `L`.
fn inject_bit<K: FieldUint, L: PrimeField, N: Network>(
    bit: &Rep3UintShare<K>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Share<L>> {
    conversion::bit_inject_from_bits((bit.a.bit(0), bit.b.bit(0)), net, state)
}

/// Moves a shared bit, given as an arithmetic sharing over `K`, into an arithmetic sharing over `L`.
fn move_bit<K: FieldUint, L: PrimeField, N: Network>(
    bit: Share<K>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Share<L>> {
    // Only the lowest bit of the binary sharing is used, the others are zero in the shared value.
    let bit = conversion::a2b_selector(bit, net, state)?;
    inject_bit(&bit, net, state)
}

fn modulus<K: PrimeField>() -> BigUint {
    K::MODULUS.into()
}

/// Verifies an ECDSA signature over the curve `C` on REP3-shared inputs and returns a shared bit
/// over `F`, see [`crate::mpc::NoirWitnessExtensionProtocol::ecdsa_verify`].
pub(super) fn ecdsa_verify<F, C, N>(
    hashed_message: &[Rep3AcvmType<F>; 32],
    public_key_x: &[Rep3AcvmType<F>; 32],
    public_key_y: &[Rep3AcvmType<F>; 32],
    signature: &[Rep3AcvmType<F>; 64],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Share<F>>
where
    F: FieldUint,
    N: Network,
    C: SWCurveConfig,
    C::BaseField: FieldUint,
    C::ScalarField: FieldUint,
{
    // The ACVM field must hold the 128-bit halves.
    const { assert!(F::MODULUS_BIT_SIZE > 128) };
    let q = modulus::<C::BaseField>();
    let n = modulus::<C::ScalarField>();
    // Used when reducing R.x modulo n below.
    eyre::ensure!(
        n < q,
        "ECDSA verification needs a group order smaller than the base field modulus"
    );

    let hashed_message = compose(hashed_message, state);
    let x = compose(public_key_x, state);
    let y = compose(public_key_y, state);
    let r = compose(&signature[..32], state);
    let s = compose(&signature[32..], state);

    // Range checks on the integers given by the bytes. Low s: s <= (n - 1) / 2. r < q - n is
    // used below to reduce R.x modulo n.
    let [
        x_lt_q,
        y_lt_q,
        r_lt_n,
        s_is_low,
        r_lt_q_minus_n,
        r_is_zero,
        s_is_zero,
    ] = range_checks(
        &[
            (x, q.clone()),
            (y, q.clone()),
            (r, n.clone()),
            (s, (&n + 1u64) >> 1),
            (r, &q - &n),
        ],
        &[r, s],
        net,
        state,
    )?
    .try_into()
    .expect("seven checks");

    // r is moved into both fields from the same binary sharing.
    let [hashed_message, x, y, r, s] = to_binary(&[hashed_message, x, y, r, s], net, state)?
        .try_into()
        .expect("five values");
    let x = to_field::<F, C::BaseField, N>(&x, net, state)?;
    let y = to_field::<F, C::BaseField, N>(&y, net, state)?;
    let r_fq = to_field::<F, C::BaseField, N>(&r, net, state)?;
    let hashed_message = to_field::<F, C::ScalarField, N>(&hashed_message, net, state)?;
    let r = to_field::<F, C::ScalarField, N>(&r, net, state)?;
    let s = to_field::<F, C::ScalarField, N>(&s, net, state)?;

    // The public key must be on the curve: y^2 = x^3 + a * x + b.
    let squares = arithmetic::mul_vec(&[x, y], &[x, y], net, state)?;
    let x_cubed = arithmetic::mul(squares[0], x, net, state)?;
    let mut curve_equation = arithmetic::sub(squares[1], x_cubed);
    curve_equation = arithmetic::sub(curve_equation, arithmetic::mul_public(x, C::COEFF_A));
    curve_equation = arithmetic::sub_shared_by_public(curve_equation, C::COEFF_B, state.id);
    let on_curve = arithmetic::eq_bit_public(curve_equation, C::BaseField::zero(), net, state)?;
    let on_curve = inject_bit::<_, F, _>(&on_curve, net, state)?;
    let key_ok = arithmetic::mul(x_lt_q, y_lt_q, net, state)?;
    let key_ok = arithmetic::mul(key_ok, on_curve, net, state)?;

    // Replace an invalid public key by 2 * G, so that it can be used as a curve point.
    let double_generator: Affine<C> = (Affine::<C>::generator() + Affine::<C>::generator()).into();
    let (double_generator_x, double_generator_y) = double_generator
        .xy()
        .expect("2 * G is not the point at infinity");
    let key_ok_fq = move_bit::<F, C::BaseField, N>(key_ok, net, state)?;
    let key = arithmetic::cmux_vec(
        key_ok_fq,
        &[x, y],
        &[
            arithmetic::promote_to_trivial_share(state.id, double_generator_x),
            arithmetic::promote_to_trivial_share(state.id, double_generator_y),
        ],
        net,
        state,
    )?;
    let key = conversion::fieldshares_to_pointshare::<Projective<C>, N>(
        key[0],
        key[1],
        Share::zero_share(),
        net,
        state,
    )?;

    // u1 = H(m) / s, u2 = r / s; s = 0 gives u1 = u2 = 0.
    let s_inverse = arithmetic::inv0(s, net, state)?;
    let u = arithmetic::mul_vec(&[hashed_message, r], &[s_inverse, s_inverse], net, state)?;

    // R = u1 * G + u2 * P
    let generator = Projective::<C>::from(Affine::<C>::generator());
    let u1_g = pointshare::scalar_mul_public_point(&generator, u[0]);
    let u2_p = pointshare::scalar_mul(&key, u[1], net, state)?;
    let point = pointshare::add(&u1_g, &u2_p);
    let (point_x, _, point_is_infinity) =
        conversion::point_share_to_fieldshares(point, net, state)?;

    // R.x mod n == r. Since n < q < 2n, R.x mod n is either R.x or R.x - n, and the latter is
    // only possible if r + n < q.
    let r_plus_n = arithmetic::add_public(r_fq, C::BaseField::from(n.clone()), state.id);
    let checks = arithmetic::eq_bit_many(
        &[point_x, point_x, point_is_infinity],
        &[r_fq, r_plus_n, Share::zero_share()],
        net,
        state,
    )?;
    let x_is_r = inject_bit::<_, F, _>(&checks[0], net, state)?;
    let x_is_r_plus_n = inject_bit::<_, F, _>(&checks[1], net, state)?;
    let point_is_finite = inject_bit::<_, F, _>(&checks[2], net, state)?;
    let x_is_r_plus_n = arithmetic::mul(x_is_r_plus_n, r_lt_q_minus_n, net, state)?;
    let x_matches = arithmetic::add(x_is_r, x_is_r_plus_n);

    let r_is_nonzero = arithmetic::sub_public_by_shared(F::one(), r_is_zero, state.id);
    let s_is_nonzero = arithmetic::sub_public_by_shared(F::one(), s_is_zero, state.id);
    let mut flags = vec![
        key_ok,
        r_lt_n,
        r_is_nonzero,
        s_is_low,
        s_is_nonzero,
        x_matches,
        point_is_finite,
    ];
    while flags.len() > 1 {
        let carry = (flags.len() % 2 == 1).then(|| flags.pop().expect("odd length"));
        let (lhs, rhs): (Vec<_>, Vec<_>) = flags
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&[a, b]| (a, b))
            .unzip();
        flags = arithmetic::mul_vec(&lhs, &rhs, net, state)?;
        flags.extend(carry);
    }
    Ok(flags[0])
}

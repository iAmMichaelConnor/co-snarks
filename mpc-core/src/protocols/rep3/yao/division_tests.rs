//! Cleartext tests of the division by a public value and of the two conversions that use its
//! remainder.
use super::GarbledCircuits;
use crate::protocols::rep3::yao::cleartext_evaluator::{CleartextBinaryEvaluator, CleartextBit};
use ark_ff::PrimeField;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand::{RngCore, SeedableRng, rngs::StdRng};

fn bits(value: &BigUint, width: usize) -> Vec<bool> {
    (0..width).map(|i| value.bit(i as u64)).collect()
}

fn wires(value: &BigUint, width: usize) -> Vec<CleartextBit> {
    bits(value, width).into_iter().map(CleartextBit).collect()
}

fn integer(wires: &[CleartextBit]) -> BigUint {
    wires.iter().rev().fold(BigUint::zero(), |v, bit| {
        (v << 1) + BigUint::from(bit.0 as u8)
    })
}

/// Divides in cleartext, checks quotient and remainder and returns the number of AND gates.
fn divide(value: &BigUint, divisor: &BigUint, width: usize, divisor_width: usize) -> usize {
    let mut evaluator = CleartextBinaryEvaluator::default();
    let (quotient, remainder) = GarbledCircuits::bin_div_rem_by_public(
        &mut evaluator,
        &wires(value, width),
        &bits(divisor, divisor_width),
    )
    .unwrap();
    assert_eq!(quotient.len(), width);
    assert_eq!(integer(&quotient), value / divisor);
    assert_eq!(integer(&remainder), value % divisor);
    evaluator.num_and_gates
}

#[test]
fn division_by_public_is_exact_for_all_small_inputs() {
    for width in 1..=8 {
        for divisor in 1..1u32 << width {
            let mut expected_cost = None;
            for value in 0..1u32 << width {
                let cost = divide(&value.into(), &divisor.into(), width, width);
                // The circuit only depends on the public divisor.
                assert_eq!(*expected_cost.get_or_insert(cost), cost);
            }
        }
    }
    // A divisor wider than the dividend.
    divide(&255u32.into(), &(BigUint::one() << 15), 8, 32);
    // A zero divisor is rejected.
    for divisor in [vec![], vec![false; 8]] {
        assert!(
            GarbledCircuits::bin_div_rem_by_public(
                &mut CleartextBinaryEvaluator::default(),
                &[CleartextBit(true)],
                &divisor,
            )
            .is_err()
        );
    }
}

#[test]
fn division_by_public_is_exact_for_512_and_1024_bit_values() {
    let modulus: BigUint = ark_bn254::Fq::MODULUS.into();
    let mut rng = StdRng::seed_from_u64(0x0d17_0001);
    for width in [512usize, 1024] {
        let max = (BigUint::one() << width) - BigUint::one();
        for divisor in [
            BigUint::one(),
            BigUint::from(2u32),
            BigUint::one() << 253,
            modulus.clone(),
            BigUint::one() << (width - 1),
            max.clone(),
        ] {
            let mut values = vec![
                BigUint::zero(),
                BigUint::one(),
                &divisor - BigUint::one(),
                divisor.clone(),
                (&divisor + BigUint::one()) & &max,
                max.clone(),
            ];
            for _ in 0..3 {
                let mut bytes = vec![0; width / 8];
                rng.fill_bytes(&mut bytes);
                values.push(BigUint::from_bytes_le(&bytes));
            }
            let mut expected_cost = None;
            for value in values {
                let cost = divide(&value, &divisor, width, width);
                assert_eq!(*expected_cost.get_or_insert(cost), cost);
            }
        }
    }
}

#[test]
fn remainder_from_division_is_cheaper_than_multiply_and_subtract() {
    let modulus: BigUint = ark_bn254::Fq::MODULUS.into();
    for width in [512usize, 1024] {
        let value = (BigUint::one() << width) - BigUint::one();
        let divisor = bits(&modulus, width);
        let mut separate = CleartextBinaryEvaluator::default();
        let input = wires(&value, width);
        let quotient = GarbledCircuits::bin_div_by_public(&mut separate, &input, &divisor).unwrap();
        let product =
            GarbledCircuits::bin_mul_with_public(&mut separate, &quotient, &divisor).unwrap();
        let remainder = GarbledCircuits::bin_subtraction(&mut separate, &input, &product[..width])
            .unwrap()
            .0;
        assert_eq!(integer(&remainder), &value % &modulus);
        let combined = divide(&value, &modulus, width, width);
        assert!(
            combined < separate.num_and_gates,
            "{combined} AND gates, previously {}",
            separate.num_and_gates
        );
    }
}

#[test]
fn ring_division_conversions_return_quotient_and_remainder() {
    use ark_bn254::{Fq, Fr};
    let fr_bits = Fr::MODULUS_BIT_SIZE as usize;
    let fq_bits = Fq::MODULUS_BIT_SIZE as usize;
    let p: BigUint = Fq::MODULUS.into();
    let low = |bits: usize| (BigUint::one() << bits) - BigUint::one();
    let mut rng = StdRng::seed_from_u64(0x0d17_0002);
    for divisor in [BigUint::from(7u32), p.clone(), low(512)] {
        let mut bytes = vec![0; 64];
        rng.fill_bytes(&mut bytes);
        let value = BigUint::from_bytes_le(&bytes);
        // Split the dividend into two summands mod 2^512.
        rng.fill_bytes(&mut bytes);
        let x1 = BigUint::from_bytes_le(&bytes);
        let x2 = (&value + (BigUint::one() << 512usize) - &x1) & low(512);
        let (q, r) = (&value / &divisor, &value % &divisor);

        // Four 68-bit quotient limbs in Fr and the remainder in Fq, with zero masks.
        let mut evaluator = CleartextBinaryEvaluator::default();
        let output = GarbledCircuits::ring_div_by_public_to_fr_limbs_and_fq::<_, Fr, Fq>(
            &mut evaluator,
            &wires(&x1, 512),
            &wires(&x2, 512),
            &wires(&BigUint::zero(), 4 * fr_bits + fq_bits),
            &bits(&divisor, 512),
            512,
            68,
            4,
        )
        .unwrap();
        for (i, limb) in output[..4 * fr_bits].chunks(fr_bits).enumerate() {
            assert_eq!(integer(limb), (&q >> (68 * i)) & low(68));
        }
        assert_eq!(integer(&output[4 * fr_bits..]), (&r & low(fq_bits)) % &p);

        // Two 68-bit limbs each of the quotient and the remainder in Fr.
        let mut evaluator = CleartextBinaryEvaluator::default();
        let output = GarbledCircuits::ring_div_by_public_to_limbs::<_, Fr>(
            &mut evaluator,
            &wires(&x1, 512),
            &wires(&x2, 512),
            &wires(&BigUint::zero(), 4 * fr_bits),
            &bits(&divisor, 512),
            512,
            68,
            2,
        )
        .unwrap();
        let limbs: Vec<_> = output.chunks(fr_bits).map(integer).collect();
        for i in 0..2 {
            assert_eq!(limbs[i], (&q >> (68 * i)) & low(68));
            assert_eq!(limbs[2 + i], (&r >> (68 * i)) & low(68));
        }
    }
}

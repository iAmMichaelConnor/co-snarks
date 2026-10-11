//! Exact arithmetic and circuit-shape regressions for the private quotient adapter.
use super::{CleartextBinaryEvaluator, CleartextBit, GarbledCircuits};
use ark_ff::PrimeField;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand::{RngCore, SeedableRng, rngs::StdRng};

fn bits(value: &BigUint, width: usize) -> Vec<bool> {
    (0..width).map(|i| value.bit(i as u64)).collect()
}
fn integer(wires: &[CleartextBit]) -> BigUint {
    wires.iter().rev().fold(BigUint::zero(), |v, bit| {
        (v << 1) + BigUint::from(bit.0 as u8)
    })
}
fn divide(value: &BigUint, divisor: &BigUint, width: usize, divisor_width: usize) -> usize {
    let input: Vec<_> = bits(value, width).into_iter().map(CleartextBit).collect();
    let mut evaluator = CleartextBinaryEvaluator::default();
    let (quotient, remainder) = GarbledCircuits::bin_div_rem_by_public(
        &mut evaluator,
        &input,
        &bits(divisor, divisor_width),
    )
    .unwrap();
    assert_eq!(
        quotient.len(),
        width,
        "never truncate high input/quotient bits"
    );
    assert_eq!(integer(&quotient), value / divisor);
    assert_eq!(integer(&remainder), value % divisor);
    assert!(integer(&remainder) < *divisor);
    evaluator.num_and_gates
}

#[test]
fn bounded_public_division_exhausts_small_inputs() {
    for width in 1..=8 {
        for divisor in 1..1u32 << width {
            let mut expected_cost = None;
            for value in 0..1u32 << width {
                let cost = divide(&value.into(), &divisor.into(), width, width);
                if let Some(expected) = expected_cost {
                    assert_eq!(cost, expected, "secret inputs cannot change circuit shape");
                }
                expected_cost = Some(cost);
            }
        }
    }
    // A divisor wider than the numerator and public zero-padding have their
    // ordinary integer meanings; the quotient remains numerator-width.
    divide(&255u32.into(), &(BigUint::one() << 15), 8, 32);
    divide(&BigUint::zero(), &BigUint::one(), 0, 16);
    let mut evaluator = CleartextBinaryEvaluator::default();
    for divisor in [vec![], vec![false; 8]] {
        assert!(GarbledCircuits::bin_div_rem_by_public(
            &mut evaluator,
            &[CleartextBit(true)],
            &divisor,
        )
        .is_err());
    }
    assert_eq!(evaluator.num_and_gates, 0);
}

#[test]
fn bounded_public_division_preserves_full_512_and_1024_bit_values() {
    let modulus: BigUint = ark_bn254::Fq::MODULUS.into();
    let mut rng = StdRng::seed_from_u64(0x000D_1512_1024);
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
                BigUint::one() << (width - 1),
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
                if let Some(expected) = expected_cost {
                    assert_eq!(cost, expected, "secret inputs cannot change circuit shape");
                }
                expected_cost = Some(cost);
            }
        }
    }
}

#[test]
fn bounded_public_division_reuses_remainder_and_reduces_gc_cost() {
    let modulus: BigUint = ark_bn254::Fq::MODULUS.into();
    for width in [512usize, 1024] {
        let value = (BigUint::one() << width) - BigUint::one();
        let input: Vec<_> = bits(&value, width).into_iter().map(CleartextBit).collect();
        let divisor = bits(&modulus, width);
        let mut original = CleartextBinaryEvaluator::default();
        let quotient = GarbledCircuits::bin_div_by_public(&mut original, &input, &divisor).unwrap();
        let product =
            GarbledCircuits::bin_mul_with_public(&mut original, &quotient, &divisor).unwrap();
        let remainder = GarbledCircuits::bin_subtraction(&mut original, &input, &product[..width])
            .unwrap()
            .0;
        assert_eq!(integer(&quotient), &value / &modulus);
        assert_eq!(integer(&remainder), &value % &modulus);
        let optimized_cost = divide(&value, &modulus, width, width);
        eprintln!(
            "public division {width} bits: old ANDs {}, new ANDs {optimized_cost}",
            original.num_and_gates
        );
        assert!(optimized_cost < original.num_and_gates);
    }
}

#[test]
fn wide_remainder_is_canonical_before_high_field_masks() {
    use ark_bn254::{Fq, Fr};
    let n = Fq::MODULUS_BIT_SIZE as usize;
    let p: BigUint = Fq::MODULUS.into();
    let divisor = (BigUint::one() << 512usize) - BigUint::one();
    let low_mask = (BigUint::one() << n) - BigUint::one();
    let encode = |value: &BigUint, width| {
        bits(value, width)
            .into_iter()
            .map(CleartextBit)
            .collect::<Vec<_>>()
    };

    // Deterministic evidence of the old precondition violation: without first
    // normalizing x, a valid mask p-1 makes compose's single subtraction leave
    // a noncanonical encoded field value. Random-mask tests can miss this case.
    let x = &low_mask - BigUint::one();
    let high_mask = &p - BigUint::one();
    let legacy = GarbledCircuits::compose_field_element::<_, Fq>(
        &mut CleartextBinaryEvaluator::default(),
        &encode(&x, n),
        &encode(&high_mask, n),
    )
    .unwrap();
    assert!(integer(&legacy) >= p);

    let mut expected_cost = None;
    for value in [
        &p - BigUint::one(),
        p.clone(),
        &p + BigUint::one(),
        low_mask.clone(),
        &divisor - BigUint::one(),
    ] {
        for mask in [BigUint::zero(), BigUint::one(), high_mask.clone()] {
            let mut masks = vec![CleartextBit(false); 4 * Fr::MODULUS_BIT_SIZE as usize];
            masks.extend(encode(&mask, n));
            let mut evaluator = CleartextBinaryEvaluator::default();
            let output = GarbledCircuits::ring_div_by_public_to_fr_limbs_and_fq::<_, Fr, Fq>(
                &mut evaluator,
                &encode(&value, 512),
                &vec![CleartextBit(false); 512],
                &masks,
                &bits(&divisor, 512),
                512,
                68,
                4,
            )
            .unwrap();
            let decoded = integer(&output[4 * Fr::MODULUS_BIT_SIZE as usize..]);
            assert!(
                decoded < p,
                "masking must always emit a canonical field value"
            );
            assert_eq!(decoded, (((&value % &divisor) & &low_mask) + &mask) % &p);
            if let Some(expected) = expected_cost {
                assert_eq!(evaluator.num_and_gates, expected);
            }
            expected_cost = Some(evaluator.num_and_gates);
        }
    }
}

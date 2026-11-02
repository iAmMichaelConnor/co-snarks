//! Driver-level tests that run single `Rep3AcvmSolver` operations on three parties and compare
//! the reconstructed results with the plain driver.

use ark_bn254::{Fq, Fr};
use ark_ff::{Field, PrimeField, UniformRand, Zero};
use co_acvm::{mpc::NoirWitnessExtensionProtocol, PlainAcvmSolver, Rep3AcvmSolver, Rep3AcvmType};
use itertools::izip;
use mpc_core::protocols::rep3::{
    combine_field_element, conversion::A2BType, share_field_element, share_field_elements,
};
use mpc_net::local::LocalNetwork;
use num_bigint::BigUint;
use num_traits::One;
use rand::thread_rng;

type Rep3Driver<'a> = Rep3AcvmSolver<'a, Fr, LocalNetwork>;

/// An operand of a driver test: either public to all parties or secret-shared.
#[derive(Clone, Copy, Debug)]
enum Input<F> {
    Public(F),
    Shared(F),
}

impl<F: PrimeField> Input<F> {
    /// Splits the input into one `Rep3AcvmType` per party.
    fn to_parties(self) -> [Rep3AcvmType<F>; 3] {
        match self {
            Input::Public(x) => [x.into(), x.into(), x.into()],
            Input::Shared(x) => share_field_element(x, &mut thread_rng()).map(Rep3AcvmType::from),
        }
    }
}

/// Opens the three parties' outputs. Public outputs must agree.
fn open<F: PrimeField>(values: [Rep3AcvmType<F>; 3]) -> F {
    match values {
        [Rep3AcvmType::Public(a), Rep3AcvmType::Public(b), Rep3AcvmType::Public(c)] => {
            assert!(a == b && b == c, "public outputs differ between parties");
            a
        }
        [Rep3AcvmType::Shared(a), Rep3AcvmType::Shared(b), Rep3AcvmType::Shared(c)] => {
            combine_field_element(a, b, c)
        }
        _ => panic!("parties disagree on whether the output is shared"),
    }
}

/// Runs `op` on a fresh `Rep3AcvmSolver` for each of the three parties. `inputs[i]` is the list
/// of operands party `i` receives.
fn run_rep3<I, O>(
    inputs: [I; 3],
    op: impl Fn(&mut Rep3Driver<'_>, I) -> O + Send + Sync + Copy + 'static,
) -> [O; 3]
where
    I: Send + 'static,
    O: Send + 'static,
{
    let threads: Vec<_> = izip!(LocalNetwork::new_3_parties(), inputs)
        .map(|(net, input)| {
            std::thread::spawn(move || {
                let mut driver = Rep3Driver::new(&net, A2BType::default()).unwrap();
                op(&mut driver, input)
            })
        })
        .collect();
    threads
        .into_iter()
        .map(|t| t.join().unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap_or_else(|_| unreachable!())
}

/// All four public/shared combinations of the operands `a` and `b`.
fn binary_cases(a: Fr, b: Fr) -> [(Input<Fr>, Input<Fr>); 4] {
    [
        (Input::Public(a), Input::Public(b)),
        (Input::Public(a), Input::Shared(b)),
        (Input::Shared(a), Input::Public(b)),
        (Input::Shared(a), Input::Shared(b)),
    ]
}

fn comparison_operands() -> Vec<(Fr, Fr)> {
    let big = -Fr::from(1u64);
    vec![
        (Fr::from(5u64), Fr::from(5u64)),
        (Fr::from(4u64), Fr::from(5u64)),
        (Fr::from(5u64), Fr::from(4u64)),
        (Fr::from(0u64), Fr::from(0u64)),
        (big, big),
        (big, Fr::from(0u64)),
        (Fr::from(0u64), big),
    ]
}

#[test]
fn rep3_gt_and_lt_match_plain() {
    let mut plain = PlainAcvmSolver::<Fr>::new();
    for (a, b) in comparison_operands() {
        for (lhs, rhs) in binary_cases(a, b) {
            let expected_gt = plain.gt(a, b).unwrap();
            let expected_lt = plain.lt(a, b).unwrap();
            let inputs = izip!(lhs.to_parties(), rhs.to_parties())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap_or_else(|_| unreachable!());
            let outputs = run_rep3(inputs, |driver, (lhs, rhs)| {
                let gt = driver.gt(lhs.clone(), rhs.clone()).unwrap();
                let lt = driver.lt(lhs, rhs).unwrap();
                (gt, lt)
            });
            let [o0, o1, o2] = outputs;
            assert_eq!(
                open([o0.0, o1.0, o2.0]),
                expected_gt,
                "gt({lhs:?}, {rhs:?})"
            );
            assert_eq!(
                open([o0.1, o1.1, o2.1]),
                expected_lt,
                "lt({lhs:?}, {rhs:?})"
            );
            assert_eq!(expected_gt, Fr::from(a > b));
            assert_eq!(expected_lt, Fr::from(a < b));
        }
    }
}

#[test]
fn rep3_and_plain_slice_return_lo_then_hi() {
    let values = [
        Fr::from(0u64),
        Fr::from((BigUint::one() << 128) + BigUint::from(255u64)),
        -Fr::from(1u64),
    ];
    let (msb, lsb, bitsize) = (128u8, 0u8, 254usize);
    let expected: Vec<[Fr; 2]> = values
        .iter()
        .map(|value| {
            let x: BigUint = (*value).into();
            let lo = &x & ((BigUint::one() << msb) - BigUint::one());
            let hi = &x >> msb;
            [Fr::from(lo), Fr::from(hi)]
        })
        .collect();

    let mut plain = PlainAcvmSolver::<Fr>::new();
    for (value, expected) in values.iter().zip(&expected) {
        assert_eq!(&plain.slice(*value, msb, lsb, bitsize).unwrap(), expected);
    }
    assert_eq!(
        plain.slice_many(&values, msb, lsb, bitsize).unwrap(),
        expected
    );

    let shares = share_field_elements(&values, &mut thread_rng());
    let outputs = run_rep3(shares, move |driver, shares| {
        let single: Vec<_> = shares
            .iter()
            .map(|x| driver.slice(*x, msb, lsb, bitsize).unwrap())
            .collect();
        let many = driver.slice_many(&shares, msb, lsb, bitsize).unwrap();
        (single, many)
    });
    let open_slices = |per_party: [&Vec<[_; 2]>; 3]| -> Vec<[Fr; 2]> {
        (0..values.len())
            .map(|i| {
                [0, 1].map(|part| {
                    combine_field_element(
                        per_party[0][i][part],
                        per_party[1][i][part],
                        per_party[2][i][part],
                    )
                })
            })
            .collect()
    };
    let [p0, p1, p2] = &outputs;
    assert_eq!(open_slices([&p0.0, &p1.0, &p2.0]), expected);
    assert_eq!(open_slices([&p0.1, &p1.1, &p2.1]), expected);
}

type Bn254G1 = ark_bn254::G1Projective;

type NonNativeOp = fn(&mut Rep3Driver<'_>, Vec<Rep3AcvmType<Fq>>) -> eyre::Result<Rep3AcvmType<Fq>>;

/// Runs `op` on non-native (BN254 base field) operands, each shared or public, and opens the
/// result.
fn rep3_other(inputs: &[Input<Fq>], op: NonNativeOp) -> eyre::Result<Fq> {
    let mut per_party: [Vec<_>; 3] = Default::default();
    for input in inputs {
        for (party, value) in per_party.iter_mut().zip(input.to_parties()) {
            party.push(value);
        }
    }
    let [o0, o1, o2] = run_rep3(per_party, op);
    Ok(open([o0?, o1?, o2?]))
}

#[test]
fn rep3_non_native_inversion_of_secret_zero_returns_zero() {
    let mut rng = thread_rng();
    let x = Fq::rand(&mut rng);
    let n = Fq::rand(&mut rng);
    let inverse = |driver: &mut Rep3Driver<'_>, mut x: Vec<_>| {
        driver.inverse_other_acvm_type::<Bn254G1>(x.remove(0))
    };
    let divide = |driver: &mut Rep3Driver<'_>, mut x: Vec<_>| {
        let lhs = x.remove(0);
        driver.div_unchecked_other_acvm_types::<Bn254G1>(lhs, x.remove(0))
    };

    assert_eq!(
        rep3_other(&[Input::Shared(x)], inverse).unwrap(),
        x.inverse().unwrap()
    );
    assert_eq!(
        rep3_other(&[Input::Public(x)], inverse).unwrap(),
        x.inverse().unwrap()
    );
    // A secret zero gives zero; an error would reveal that the secret is zero.
    assert_eq!(
        rep3_other(&[Input::Shared(Fq::zero())], inverse).unwrap(),
        Fq::zero()
    );
    // A public zero is an error, as in the plain driver.
    assert!(rep3_other(&[Input::Public(Fq::zero())], inverse).is_err());
    let mut plain = PlainAcvmSolver::<Fr>::new();
    assert!(plain
        .inverse_other_acvm_type::<Bn254G1>(Fq::zero())
        .is_err());

    for numerator in [Input::Public(n), Input::Shared(n)] {
        let quotient = rep3_other(&[numerator, Input::Shared(x)], divide).unwrap();
        assert_eq!(quotient, n / x);
        let quotient = rep3_other(&[numerator, Input::Shared(Fq::zero())], divide).unwrap();
        assert_eq!(quotient, Fq::zero());
    }
    assert!(rep3_other(&[Input::Shared(n), Input::Public(Fq::zero())], divide).is_err());
    assert!(plain
        .div_unchecked_other_acvm_types::<Bn254G1>(n, Fq::zero())
        .is_err());
}

#[test]
fn rep3_inverse_of_public_zero_limbs_matches_plain() {
    let mut plain = PlainAcvmSolver::<Fr>::new();
    let x = Fq::rand(&mut thread_rng());
    for value in [Fq::zero(), x] {
        let limbs = plain
            .other_acvm_type_to_acvm_type_limbs::<4, 68, Bn254G1>(&value)
            .unwrap();
        let expected = plain.inverse_acvm_type_limbs::<Bn254G1>(&limbs).unwrap();
        let outputs = run_rep3([limbs; 3], |driver, limbs| {
            driver
                .inverse_acvm_type_limbs::<Bn254G1>(&limbs.map(Rep3AcvmType::from))
                .unwrap()
        });
        for (i, expected) in expected.into_iter().enumerate() {
            let [o0, o1, o2] = &outputs;
            assert_eq!(
                open([o0[i].clone(), o1[i].clone(), o2[i].clone()]),
                expected
            );
        }
    }
}

#[test]
fn rep3_non_native_subtraction_matches_plain() {
    let mut rng = thread_rng();
    let (a, b) = (Fq::rand(&mut rng), Fq::rand(&mut rng));
    let sub = |driver: &mut Rep3Driver<'_>, mut x: Vec<_>| {
        let lhs = x.remove(0);
        Ok(driver.sub_other_acvm_types::<Bn254G1>(lhs, x.remove(0)))
    };
    let mut plain = PlainAcvmSolver::<Fr>::new();
    let expected = plain.sub_other_acvm_types::<Bn254G1>(a, b);
    assert_eq!(expected, a - b);
    for (lhs, rhs) in [
        (Input::Public(a), Input::Public(b)),
        (Input::Public(a), Input::Shared(b)),
        (Input::Shared(a), Input::Public(b)),
        (Input::Shared(a), Input::Shared(b)),
    ] {
        assert_eq!(
            rep3_other(&[lhs, rhs], sub).unwrap(),
            expected,
            "{lhs:?} - {rhs:?}"
        );
    }
}

#[test]
fn madd_div_mod_many_rejects_mismatched_lengths() {
    let mut plain = PlainAcvmSolver::<Fr>::new();
    let one = [Fr::from(1u64), Fr::zero(), Fr::zero(), Fr::zero()];
    assert!(plain
        .madd_div_mod_many_acvm_limbs::<Bn254G1>(&[one, one], &[one], &[])
        .is_err());
    assert!(plain
        .madd_div_mod_many_acvm_limbs::<Bn254G1>(&[one], &[one], &[])
        .is_ok());
    let outputs = run_rep3([(); 3], move |driver, ()| {
        let one = one.map(Rep3AcvmType::from);
        let (a, b) = (vec![one.clone()], vec![one.clone(), one]);
        driver
            .madd_div_mod_many_acvm_limbs::<Bn254G1>(&a, &b, &[])
            .is_err()
    });
    assert_eq!(outputs, [true; 3]);
}

#[test]
fn rep3_shared_naf_entries_match_plain() {
    let mut plain = PlainAcvmSolver::<Fr>::new();
    for width in [0usize, 1, 7, 127, 128, 254] {
        let bits = if width == 0 { 254 } else { width };
        let max = if bits == 254 {
            -Fr::from(1u64)
        } else {
            Fr::from((BigUint::one() << bits) - BigUint::one())
        };
        for value in [Fr::zero(), Fr::from(1u64), Fr::from(2u64), max] {
            let expected = plain.compute_naf_entries(&value, width).unwrap();
            assert_eq!(expected.len(), bits);
            let [o0, o1, o2] = run_rep3(Input::Shared(value).to_parties(), move |driver, x| {
                driver.compute_naf_entries(&x, width).unwrap()
            });
            assert!(o0.iter().all(|x| matches!(x, Rep3AcvmType::Shared(_))));
            let entries: Vec<_> = izip!(o0, o1, o2).map(|(a, b, c)| open([a, b, c])).collect();
            assert_eq!(entries, expected, "width {width}, value {value}");
        }
    }
}

/// The limbs (68 bits each, the last one unbounded) of `value`.
fn bigfield_limbs(value: &BigUint) -> [Fr; 4] {
    let mask = (BigUint::one() << 68) - BigUint::one();
    std::array::from_fn(|i| {
        if i == 3 {
            Fr::from(value >> 204)
        } else {
            Fr::from((value >> (68 * i)) & &mask)
        }
    })
}

/// Runs every non-native limb operation of the driver on the given limbs (taken in pairs) and
/// returns the outputs.
fn bigfield_ops<T: NoirWitnessExtensionProtocol<Fr>>(
    driver: &mut T,
    x: &[[T::AcvmType; 4]],
) -> (Vec<T::AcvmType>, Vec<T::OtherAcvmType<Bn254G1>>) {
    let mut limbs = Vec::new();
    let mut others = Vec::new();
    for [a, b] in x.as_chunks::<2>().0 {
        limbs.extend(driver.add_acvm_type_limbs::<Bn254G1>(a, b).unwrap());
        limbs.extend(driver.sub_acvm_type_limbs::<Bn254G1>(a, b).unwrap());
        limbs.extend(driver.sub_acvm_type_limbs::<Bn254G1>(b, a).unwrap());
        limbs.extend(driver.mul_mod_acvm_type_limbs::<Bn254G1>(a, b).unwrap());
        limbs.extend(driver.inverse_acvm_type_limbs::<Bn254G1>(a).unwrap());
        let (quotient, remainder) = driver.div_mod_acvm_limbs::<Bn254G1>(a).unwrap();
        limbs.extend(quotient);
        others.push(remainder);
        let (quotient, remainder) = driver
            .madd_div_mod_acvm_limbs::<Bn254G1>(a, b, &[a.clone(), b.clone()])
            .unwrap();
        limbs.extend(quotient);
        others.push(remainder);
        let value = driver
            .acvm_type_limbs_to_other_acvm_type::<4, 68, Bn254G1>(a)
            .unwrap();
        limbs.extend(
            driver
                .other_acvm_type_to_acvm_type_limbs::<4, 68, Bn254G1>(&value)
                .unwrap(),
        );
        others.push(value);
        let wide = [b[0].clone(), b[1].clone()];
        let value = driver
            .acvm_type_limbs_to_other_acvm_type::<2, 136, Bn254G1>(&wide)
            .unwrap();
        limbs.extend(
            driver
                .other_acvm_type_to_acvm_type_limbs::<2, 136, Bn254G1>(&value)
                .unwrap(),
        );
        others.push(value);
    }
    let half = x.len() / 2;
    let (quotient, remainder) = driver
        .madd_div_mod_many_acvm_limbs::<Bn254G1>(&x[..half], &x[half..2 * half], &x[..2])
        .unwrap();
    limbs.extend(quotient);
    others.push(remainder);
    (limbs, others)
}

/// The secret-shared non-native limb arithmetic gives the plain driver's results, for canonical,
/// unreduced and oversized limbs (products above 2^512), negative differences and zero.
#[test]
fn rep3_shared_bigfield_limb_arithmetic_matches_plain() {
    let p: BigUint = Fq::MODULUS.into();
    let mut rng = thread_rng();
    let values: Vec<[Fr; 4]> = vec![
        bigfield_limbs(&BigUint::ZERO),
        bigfield_limbs(&(&p * 3u32 + 5u32)),
        bigfield_limbs(&p),
        bigfield_limbs(&(&p - 1u32)),
        [-Fr::from(1u64); 4],
        bigfield_limbs(&BigUint::one()),
        bigfield_limbs(&((BigUint::one() << 272) - 1u32)),
        bigfield_limbs(&Fq::rand(&mut rng).into()),
        bigfield_limbs(&Fq::rand(&mut rng).into()),
        [Fr::from(7u64); 4],
    ];
    let mut plain = PlainAcvmSolver::<Fr>::new();
    let (expected_limbs, expected_others) = bigfield_ops(&mut plain, &values);

    for mixed in [false, true] {
        // All limbs shared, or the odd limbs public.
        let mut per_party: [Vec<[Rep3AcvmType<Fr>; 4]>; 3] = Default::default();
        for value in &values {
            let limbs = value.map(|limb| {
                if mixed && limb.into_bigint().0[0] % 2 == 1 {
                    Input::Public(limb).to_parties()
                } else {
                    Input::Shared(limb).to_parties()
                }
            });
            for (party, party_values) in per_party.iter_mut().enumerate() {
                party_values.push(limbs.clone().map(|limb| limb[party].clone()));
            }
        }
        let [o0, o1, o2] = run_rep3(per_party, |driver, x| bigfield_ops(driver, &x));
        if !mixed {
            assert!(o0.0.iter().all(|x| matches!(x, Rep3AcvmType::Shared(_))));
            assert!(o0.1.iter().all(|x| matches!(x, Rep3AcvmType::Shared(_))));
        }
        let limbs: Vec<_> = izip!(o0.0, o1.0, o2.0)
            .map(|(a, b, c)| open([a, b, c]))
            .collect();
        let others: Vec<_> = izip!(o0.1, o1.1, o2.1)
            .map(|(a, b, c)| open([a, b, c]))
            .collect();
        assert_eq!(limbs, expected_limbs, "mixed: {mixed}");
        assert_eq!(others, expected_others, "mixed: {mixed}");
    }
}

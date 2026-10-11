//! Real-party boundary regressions for private BN254 non-native adapters.
//! Opening occurs only in this test referee, after each operation has finished.
use ark_bn254::{Fq, Fr, G1Projective};
use ark_ff::{Field, One, PrimeField, Zero};
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_acvm::{Rep3AcvmSolver, Rep3AcvmType};
use mpc_core::protocols::rep3::{conversion::A2BType, share_field_elements};
use mpc_net::local::LocalNetwork;
use num_bigint::BigUint;
use rand::{SeedableRng, rngs::StdRng};

type Value = Rep3AcvmType<Fr>;
type Driver<'a> = Rep3AcvmSolver<'a, Fr, LocalNetwork>;
fn raw(limbs: &[Fr; 4]) -> BigUint {
    limbs
        .iter()
        .enumerate()
        .fold(BigUint::zero(), |sum, (i, v)| {
            sum + (BigUint::from(v.into_bigint()) << (68 * i))
        })
}
fn limbs(value: &BigUint) -> [Fr; 4] {
    let mask = (BigUint::one() << 68) - BigUint::one();
    std::array::from_fn(|i| Fr::from((value >> (68 * i)) & &mask))
}
fn open_limbs(driver: &mut Driver<'_>, values: [Value; 4]) -> [Fr; 4] {
    let shares: Vec<_> = values.iter().map(|v| driver.get_as_shared(v)).collect();
    driver.open_many(&shares).unwrap().try_into().unwrap()
}
fn run(values: Vec<Fr>, body: impl Fn(&mut Driver<'_>, &[Value], &[Fr]) + Send + Sync + 'static) {
    let shares = share_field_elements(&values, &mut StdRng::seed_from_u64(0xB16F1E1D));
    let body = std::sync::Arc::new(body);
    let handles: Vec<_> = LocalNetwork::new_3_parties()
        .into_iter()
        .zip(shares)
        .map(|(net, shares)| {
            let values = values.clone();
            let body = body.clone();
            std::thread::spawn(move || {
                let mut driver = Driver::new(&net, A2BType::default()).unwrap();
                let input: Vec<_> = shares.into_iter().map(Value::Shared).collect();
                body(&mut driver, &input, &values);
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}
#[test]
fn private_cross_field_conversion_canonical_and_oversized_limbs() {
    let q: BigUint = Fq::MODULUS.into();
    let cases = [
        [Fr::zero(); 4],
        limbs(&(q.clone() - BigUint::one())),
        limbs(&q),
        [Fr::from(-1i64); 4],
    ];
    run(
        cases.into_iter().flatten().collect(),
        move |driver, input, values| {
            for (case, plain) in input.chunks_exact(4).zip(values.chunks_exact(4)) {
                let plain: [Fr; 4] = plain.try_into().unwrap();
                let expected = Fq::from(raw(&plain));
                let public = driver
                    .acvm_type_limbs_to_other_acvm_type::<4, 68, G1Projective>(
                        &plain.map(Value::Public),
                    )
                    .unwrap();
                assert!(matches!(public, Rep3AcvmType::Public(v) if v == expected));
                for mixed in [false, true] {
                    let case: [Value; 4] = std::array::from_fn(|i| {
                        if mixed && i % 2 == 1 {
                            Value::Public(plain[i])
                        } else {
                            case[i].clone()
                        }
                    });
                    let fq = driver
                        .acvm_type_limbs_to_other_acvm_type::<4, 68, G1Projective>(&case)
                        .unwrap();
                    assert!(matches!(fq, Rep3AcvmType::Shared(_)));
                    let product = driver
                        .mul_mod_acvm_type_limbs::<G1Projective>(&case, &case)
                        .unwrap();
                    assert_eq!(
                        open_limbs(driver, product),
                        limbs(&BigUint::from(expected.square().into_bigint()))
                    );
                    let back = driver
                        .other_acvm_type_to_acvm_type_limbs::<4, 68, G1Projective>(&fq)
                        .unwrap();
                    assert_eq!(
                        driver.open_many_other::<G1Projective>(&[fq]).unwrap(),
                        vec![expected]
                    );
                    assert_eq!(
                        open_limbs(driver, back),
                        limbs(&BigUint::from(expected.into_bigint()))
                    );
                }
            }
            let input: [Value; 4] = input[..4].to_vec().try_into().unwrap();
            assert!(
                driver
                    .acvm_type_limbs_to_other_acvm_type::<4, 0, G1Projective>(&input)
                    .is_err()
            );
            assert!(
                driver
                    .acvm_type_limbs_to_other_acvm_type::<4, 254, G1Projective>(&input)
                    .is_err()
            );
        },
    );
}
#[test]
fn private_integer_add_sub_divmod_preserve_lazy_limbs() {
    let q: BigUint = Fq::MODULUS.into();
    let cases = [
        (
            [Fr::zero(); 4],
            limbs(&(q.clone() * 3u32 + BigUint::from(5u32))),
        ),
        (
            limbs(&(q.clone() * 3u32 + BigUint::from(5u32))),
            [Fr::zero(); 4],
        ),
        ([Fr::zero(); 4], limbs(&(q.clone() * 3u32))),
        (limbs(&q), limbs(&q)),
        ([Fr::from(-1i64); 4], [Fr::from(1u64); 4]),
        ([Fr::from(1u64); 4], [Fr::from(-1i64); 4]),
        (
            limbs(&((BigUint::one() << 272) - BigUint::one())),
            limbs(&BigUint::one()),
        ),
    ];
    run(
        cases
            .into_iter()
            .flat_map(|(a, b)| a.into_iter().chain(b))
            .collect(),
        move |driver, input, values| {
            for (case, plain) in input.chunks_exact(8).zip(values.chunks_exact(8)) {
                let a: [Value; 4] = case[..4].to_vec().try_into().unwrap();
                let b: [Value; 4] = case[4..].to_vec().try_into().unwrap();
                let av = raw(&plain[..4].try_into().unwrap());
                let bv = raw(&plain[4..].try_into().unwrap());
                let sum = driver.add_acvm_type_limbs::<G1Projective>(&a, &b).unwrap();
                assert_eq!(open_limbs(driver, sum), limbs(&(&av + &bv)));
                let difference = driver.sub_acvm_type_limbs::<G1Projective>(&a, &b).unwrap();
                let expected = if av >= bv {
                    &av - &bv
                } else {
                    (&q - ((&bv - &av) % &q)) % &q
                };
                assert_eq!(open_limbs(driver, difference), limbs(&expected));
                let (quotient, remainder) = driver.div_mod_acvm_limbs::<G1Projective>(&a).unwrap();
                assert_eq!(open_limbs(driver, quotient), limbs(&(&av / &q)));
                assert_eq!(
                    driver
                        .open_many_other::<G1Projective>(&[remainder])
                        .unwrap(),
                    vec![Fq::from(&av % &q)]
                );
            }
        },
    );
}
#[test]
fn private_products_and_sums_do_not_wrap_at_512_bits() {
    let values = vec![Fr::from(-1i64); 16];
    run(values, |driver, input, values| {
        let a: [Value; 4] = input[..4].to_vec().try_into().unwrap();
        let b: [Value; 4] = input[4..8].to_vec().try_into().unwrap();
        let c: [Value; 4] = input[8..12].to_vec().try_into().unwrap();
        let av = raw(&values[..4].try_into().unwrap());
        let q: BigUint = Fq::MODULUS.into();
        let expected = &av * &av + &av;
        assert!(expected.bits() > 900);
        let (quotient, remainder) = driver
            .madd_div_mod_acvm_limbs::<G1Projective>(&a, &b, std::slice::from_ref(&c))
            .unwrap();
        assert_eq!(open_limbs(driver, quotient), limbs(&(&expected / &q)));
        assert_eq!(
            driver
                .open_many_other::<G1Projective>(&[remainder])
                .unwrap(),
            vec![Fq::from(&expected % &q)]
        );
        let (quotient, remainder) = driver
            .madd_div_mod_many_acvm_limbs::<G1Projective>(
                &[a.clone(), b.clone()],
                &[b, a.clone()],
                &[c],
            )
            .unwrap();
        let expected = &av * &av * 2u32 + &av;
        assert_eq!(open_limbs(driver, quotient), limbs(&(&expected / &q)));
        assert_eq!(
            driver
                .open_many_other::<G1Projective>(&[remainder])
                .unwrap(),
            vec![Fq::from(&expected % &q)]
        );
        assert!(
            driver
                .madd_div_mod_many_acvm_limbs::<G1Projective>(&[a], &[], &[])
                .is_err()
        );
    });
}
#[test]
fn private_zero_inverse_and_mixed_subtraction_order() {
    run(vec![Fr::zero(), Fr::from(7u64)], |driver, input, _| {
        for x in input {
            let a = [
                x.clone(),
                Value::Public(Fr::zero()),
                Value::Public(Fr::zero()),
                Value::Public(Fr::zero()),
            ];
            let fq = driver
                .acvm_type_limbs_to_other_acvm_type::<4, 68, G1Projective>(&a)
                .unwrap();
            let inverse = driver.inverse_acvm_type_limbs::<G1Projective>(&a).unwrap();
            let value = driver
                .open_many_other::<G1Projective>(std::slice::from_ref(&fq))
                .unwrap()[0];
            assert_eq!(
                open_limbs(driver, inverse),
                limbs(&BigUint::from(
                    value.inverse().unwrap_or_default().into_bigint()
                ))
            );
            let lhs = driver.sub_other_acvm_types::<G1Projective>(
                fq.clone(),
                Rep3AcvmType::Public(Fq::from(3u64)),
            );
            let rhs = driver.sub_other_acvm_types::<G1Projective>(
                Rep3AcvmType::Public(Fq::from(3u64)),
                fq.clone(),
            );
            let selected = driver
                .cmux_other_acvm_type::<G1Projective>(
                    Rep3AcvmType::Public(Fq::one()),
                    lhs.clone(),
                    rhs.clone(),
                )
                .unwrap();
            assert_eq!(
                driver
                    .open_many_other::<G1Projective>(&[lhs, rhs, selected])
                    .unwrap(),
                vec![
                    value - Fq::from(3u64),
                    Fq::from(3u64) - value,
                    value - Fq::from(3u64)
                ]
            );
            let (_, condition) = driver
                .equals_other_acvm_type::<G1Projective>(&fq, &Rep3AcvmType::Public(Fq::zero()))
                .unwrap();
            let selected = driver
                .cmux_other_acvm_type::<G1Projective>(
                    condition,
                    fq.clone(),
                    Rep3AcvmType::Public(Fq::from(3u64)),
                )
                .unwrap();
            assert_eq!(
                driver.open_many_other::<G1Projective>(&[selected]).unwrap(),
                vec![if value.is_zero() {
                    value
                } else {
                    Fq::from(3u64)
                }]
            );
            let divided = driver
                .div_unchecked_other_acvm_types::<G1Projective>(
                    Rep3AcvmType::Public(Fq::from(9u64)),
                    fq,
                )
                .unwrap();
            assert_eq!(
                driver.open_many_other::<G1Projective>(&[divided]).unwrap(),
                vec![Fq::from(9u64) * value.inverse().unwrap_or_default()]
            );
        }
    });
}

#[test]
fn strict_greater_than_handles_equality_and_all_visibilities() {
    run(
        vec![Fr::zero(), Fr::one(), Fr::from(7u64), -Fr::one()],
        |driver, input, values| {
            for a in 0..values.len() {
                for b in 0..values.len() {
                    for public_a in [false, true] {
                        for public_b in [false, true] {
                            let lhs = if public_a {
                                Value::Public(values[a])
                            } else {
                                input[a].clone()
                            };
                            let rhs = if public_b {
                                Value::Public(values[b])
                            } else {
                                input[b].clone()
                            };
                            let result = driver.gt(lhs, rhs).unwrap();
                            assert_eq!(matches!(result, Value::Shared(_)), !(public_a && public_b));
                            let share = driver.get_as_shared(&result);
                            assert_eq!(
                                driver.open_many(&[share]).unwrap(),
                                vec![Fr::from(values[a] > values[b])]
                            );
                        }
                    }
                }
            }
        },
    );
}

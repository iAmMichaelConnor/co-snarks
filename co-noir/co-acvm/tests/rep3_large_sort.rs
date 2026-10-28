//! Protocol-composition checks: private conversions must not desynchronize
//! later sorting or public common randomness. Referee openings occur in tests only.
use ark_bn254::{Fr, G1Projective};
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_acvm::{Rep3AcvmSolver, Rep3AcvmType};
use mpc_core::protocols::rep3::{conversion::A2BType, share_field_elements};
use mpc_net::local::LocalNetwork;
use rand::{SeedableRng, rngs::StdRng};
#[test]
fn large_shared_range_sort_composes_with_private_arithmetic() {
    for n in [25043usize] {
        let values: Vec<_> = (0..n)
            .map(|i| Fr::from(((i * 127 + 71) % 16384) as u64))
            .collect();
        let shares = share_field_elements(&values, &mut StdRng::seed_from_u64(0x5027));
        let mut expected = values.clone();
        expected.sort();
        let workers: Vec<_> = LocalNetwork::new_3_parties()
            .into_iter()
            .zip(shares)
            .map(|(net, shares)| {
                let values = values.clone();
                let expected = expected.clone();
                std::thread::spawn(move || {
                    let mut driver =
                        Rep3AcvmSolver::<Fr, _>::new(&net, A2BType::default()).unwrap();
                    let inputs: Vec<_> = shares.into_iter().map(Rep3AcvmType::Shared).collect();
                    let a: [Rep3AcvmType<Fr>; 4] = inputs[..4].to_vec().try_into().unwrap();
                    for width in [0, 128, 254, 1, 127, 254] {
                        let random: Rep3AcvmType<Fr> = driver.rand().unwrap().into();
                        let inverse = driver.invert(random.clone()).unwrap();
                        let _ = driver.compute_naf_entries(&random, width).unwrap();
                        let _ = driver.compute_naf_entries(&inverse, width).unwrap();
                    }
                    for _ in 0..16 {
                        let _ = driver
                            .madd_div_mod_many_acvm_limbs::<G1Projective>(
                                std::slice::from_ref(&a),
                                std::slice::from_ref(&a),
                                std::slice::from_ref(&a),
                            )
                            .unwrap();
                        let f = driver
                            .acvm_type_limbs_to_other_acvm_type::<4, 68, G1Projective>(&a)
                            .unwrap();
                        let _ = driver
                            .other_acvm_type_to_acvm_type_limbs::<4, 68, G1Projective>(&f)
                            .unwrap();
                    }
                    for round in 0..4 {
                        let prefix: Vec<_> = inputs[..37]
                            .iter()
                            .enumerate()
                            .map(|(i, v)| {
                                if round == 0 {
                                    Rep3AcvmType::Public(values[i])
                                } else {
                                    v.clone()
                                }
                            })
                            .collect();
                        let _ = driver.sort(&prefix, 14).unwrap();
                    }
                    let sorted = driver.sort(&inputs, 14).unwrap();
                    assert_eq!(driver.open_many(&sorted).unwrap(), expected);
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
    }
}

#[test]
fn common_public_seed_agrees_after_private_modular_arithmetic() {
    let values = vec![Fr::from(123456u64); 4];
    let shares = share_field_elements(&values, &mut StdRng::seed_from_u64(0x5028));
    let workers: Vec<_> = LocalNetwork::new_3_parties()
        .into_iter()
        .zip(shares)
        .map(|(net, shares)| {
            std::thread::spawn(move || {
                let mut driver = Rep3AcvmSolver::<Fr, _>::new(&net, A2BType::default()).unwrap();
                let a: [Rep3AcvmType<Fr>; 4] = shares
                    .into_iter()
                    .map(Rep3AcvmType::Shared)
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();
                let _ = driver
                    .madd_div_mod_many_acvm_limbs::<G1Projective>(
                        std::slice::from_ref(&a),
                        std::slice::from_ref(&a),
                        &[],
                    )
                    .unwrap();
                driver.common_rng_seed().unwrap()
            })
        })
        .collect();
    let seeds: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
    // Never include seed contents in failure output.
    assert!(
        seeds.windows(2).all(|w| w[0] == w[1]),
        "Public offset seeds must agree after private conversions"
    );
}

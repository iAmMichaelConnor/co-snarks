use ark_bn254::Fr;
use ark_ff::{One, PrimeField, Zero};
use co_acvm::{PlainAcvmSolver, Rep3AcvmSolver, Rep3AcvmType, mpc::NoirWitnessExtensionProtocol};
use mpc_core::protocols::rep3::{conversion::A2BType, share_field_elements};
use mpc_net::local::LocalNetwork;
use num_bigint::BigUint;
use rand::{SeedableRng, rngs::StdRng};

#[test]
fn private_naf_matches_fixed_width_reference_including_zero() {
    let mut cases = Vec::new();
    for width in [1usize, 7, 127, 128, 254] {
        let upper = if width == 254 {
            -Fr::one()
        } else {
            Fr::from((BigUint::one() << width) - BigUint::one())
        };
        for value in [Fr::zero(), Fr::one(), upper] {
            cases.push((width, value));
        }
        if width > 1 {
            cases.push((width, Fr::from(2u64)));
        }
    }
    let values: Vec<_> = cases.iter().map(|(_, v)| *v).collect();
    let shares = share_field_elements(&values, &mut StdRng::seed_from_u64(0x4e4146));
    let nets = LocalNetwork::new_3_parties();
    let threads: Vec<_> = nets
        .into_iter()
        .zip(shares)
        .map(|(net, shares)| {
            let widths: Vec<_> = cases.iter().map(|(w, _)| *w).collect();
            std::thread::spawn(move || {
                let mut driver = Rep3AcvmSolver::<Fr, _>::new(&net, A2BType::default()).unwrap();
                widths
                    .into_iter()
                    .zip(shares)
                    .map(|(width, share)| {
                        driver
                            .compute_naf_entries(&Rep3AcvmType::Shared(share), width)
                            .unwrap()
                            .into_iter()
                            .map(|v| match v {
                                Rep3AcvmType::Shared(s) => s.a,
                                Rep3AcvmType::Public(_) => {
                                    panic!("Private NAF digit became public")
                                }
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    let outputs: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    for (case, (width, value)) in cases.into_iter().enumerate() {
        let expected = PlainAcvmSolver::<Fr>::new()
            .compute_naf_entries(&value, width)
            .unwrap();
        assert_eq!(expected.len(), width);
        let entries: Vec<_> = (0..width)
            .map(|i| outputs.iter().map(|o| o[case][i]).sum::<Fr>())
            .collect();
        assert_eq!(entries, expected);
        assert!(entries.iter().all(|v| v.is_zero() || v.is_one()));
        let mut reconstructed = Fr::from(BigUint::one() << (width - 1)) - entries[0];
        for (i, sign) in entries.iter().skip(1).enumerate() {
            reconstructed += (Fr::one() - Fr::from(2u64) * sign) * Fr::from(BigUint::one() << i);
        }
        assert_eq!(reconstructed, value, "width={width}");
    }
    assert!(
        PlainAcvmSolver::<Fr>::new()
            .compute_naf_entries(&Fr::zero(), Fr::MODULUS_BIT_SIZE as usize + 1)
            .is_err()
    );
}

use super::*;
use ark_bn254::{Fr, G1Projective};
use co_acvm::{Rep3AcvmSolver, Rep3AcvmType};
use mpc_core::protocols::rep3::{conversion::A2BType, share_field_elements};
use mpc_net::local::LocalNetwork;

#[test]
fn shared_naf_width_constraints_and_zero_have_identical_keys() {
    for width in [1usize, 127, 128, 254] {
        let max = if width == 254 {
            -Fr::one()
        } else {
            Fr::from((BigUint::one() << width) - 1u32)
        };
        let mut cases = vec![(Fr::zero(), true), (max, true)];
        if width < 254 {
            cases.push((Fr::from(BigUint::one() << width), false));
        }
        let mut reference_key = None;
        for (value, expected) in cases {
            let shares = share_field_elements(&[value], &mut rand::thread_rng());
            let workers: Vec<_> = LocalNetwork::new_3_parties()
                .into_iter()
                .zip(shares)
                .map(|(net, shares)| {
                    std::thread::spawn(move || {
                        let mut driver =
                            Rep3AcvmSolver::<Fr, _>::new(&net, A2BType::default()).unwrap();
                        let mut builder =
                            GenericUltraCircuitBuilder::<G1Projective, _>::new_minimal(0);
                        let scalar =
                            FieldCT::from_witness(Rep3AcvmType::Shared(shares[0]), &mut builder);
                        BigGroup::compute_naf(&scalar, width, &mut builder, &mut driver).unwrap();
                        crate::ultra_builder::private_range_tests::prove_shared_builder(
                            &net,
                            builder,
                            &mut driver,
                        )
                    })
                })
                .collect();
            for worker in workers {
                let (accepted, key) = worker.join().unwrap();
                assert_eq!(
                    accepted, expected,
                    "width {width}: actual constraints reject out-of-width scalar"
                );
                if let Some(reference) = &reference_key {
                    assert_eq!(
                        &key, reference,
                        "NAF key shape cannot depend on secret zero or scalar bits"
                    );
                } else {
                    reference_key = Some(key);
                }
            }
        }
    }
}

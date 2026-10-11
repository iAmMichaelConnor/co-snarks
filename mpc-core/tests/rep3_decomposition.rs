//! Real-party regressions for the documented partial-final-limb decomposition contract.
use ark_bn254::{Fq, Fr};
use mpc_core::protocols::rep3::{Rep3State, arithmetic, share_field_elements, yao};
use mpc_net::local::LocalNetwork;
use rand::{SeedableRng, rngs::StdRng};

#[test]
fn decomposition_allows_a_single_short_limb() {
    let integers = [0u64, 1, 255, 16383, 1048575];
    let values: Vec<_> = integers.iter().copied().map(Fr::from).collect();
    let shares = share_field_elements(&values, &mut StdRng::seed_from_u64(0xdec08));
    let parties: Vec<_> = LocalNetwork::new_3_parties()
        .into_iter()
        .zip(shares)
        .map(|(net, shares)| {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, Default::default()).unwrap();
                for total_bits in [1, 8, 14, 20] {
                    let actual =
                        yao::decompose_arithmetic_many(&shares, &net, &mut state, total_bits, 14)
                            .unwrap();
                    let expected: Vec<_> = integers
                        .iter()
                        .flat_map(|value| {
                            let truncated = value & ((1u64 << total_bits) - 1);
                            (0..total_bits.div_ceil(14)).map(move |limb| {
                                Fr::from((truncated >> (14 * limb)) & ((1 << 14) - 1))
                            })
                        })
                        .collect();
                    assert_eq!(arithmetic::open_vec(&actual, &net).unwrap(), expected);
                }
                let scalar = yao::decompose_arithmetic(shares[2], &net, &mut state, 8, 14).unwrap();
                assert_eq!(
                    arithmetic::open_vec(&scalar, &net).unwrap(),
                    [Fr::from(255)]
                );
                let other = yao::decompose_arithmetic_to_other_field_many::<Fr, Fq, _>(
                    &shares, &net, &mut state, 8, 14,
                )
                .unwrap();
                let expected: Vec<_> = integers.iter().map(|value| Fq::from(value & 255)).collect();
                assert_eq!(arithmetic::open_vec(&other, &net).unwrap(), expected);
            })
        })
        .collect();
    for party in parties {
        party.join().unwrap();
    }
}

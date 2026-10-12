//! Real-party integer-oracle and RNG-composition checks for limb decomposition.
use ark_bn254::{Fq, Fr};
use ark_ff::BigInteger;
use mpc_core::protocols::rep3::{
    Rep3State, arithmetic, conversion, network::Rep3NetworkExt, share_field_elements,
};
use mpc_core::uint::FieldUint;
use mpc_net::{Network, local::LocalNetwork};
use num_bigint::BigUint;
use rand::{SeedableRng, rngs::StdRng};

fn exercise<F: FieldUint>() {
    for backend in [conversion::A2BType::Direct, conversion::A2BType::Yao] {
        let mut rng = StdRng::seed_from_u64(0xdec_c0de);
        let mut values = vec![F::from(0u64), F::from(1u64), -F::from(1u64), -F::from(2u64)];
        for bit in [13usize, 14, 56, 68, 69, 70, 136, 253] {
            let boundary = BigUint::from(1u64) << bit;
            values.push(F::from_le_bytes_mod_order(&boundary.to_bytes_le()));
            values.push(F::from_le_bytes_mod_order(
                &(boundary - BigUint::from(1u64)).to_bytes_le(),
            ));
        }
        values.extend((0..5).map(|_| F::rand(&mut rng)));
        let integers: Vec<_> = values
            .iter()
            .map(|v| BigUint::from_bytes_le(&v.into_bigint().to_bytes_le()))
            .collect();
        let shares = share_field_elements(&values, &mut rng);
        let workers: Vec<_> = LocalNetwork::new_3_parties()
            .into_iter()
            .zip(shares)
            .map(|(net, shares)| {
                let integers = integers.clone();
                std::thread::spawn(move || {
                    let mut state = Rep3State::new(&net, backend).unwrap();
                    for (total, width) in [
                        (0usize, 14usize),
                        (1, 14),
                        (8, 14),
                        (14, 14),
                        (20, 14),
                        (70, 14),
                        (254, 68),
                        (254, 254),
                        (254, 1),
                    ] {
                        let result = conversion::decompose_arithmetic_many(
                            &shares, &net, &mut state, total, width,
                        )
                        .unwrap();
                        let expected: Vec<_> = integers
                            .iter()
                            .flat_map(|value| {
                                (0..total.div_ceil(width)).map(move |limb| {
                                    let size = width.min(total - limb * width);
                                    let mask = (BigUint::from(1u64) << size) - BigUint::from(1u64);
                                    F::from_le_bytes_mod_order(
                                        &((value >> (limb * width)) & mask).to_bytes_le(),
                                    )
                                })
                            })
                            .collect();
                        assert_eq!(arithmetic::open_vec(&result, &net).unwrap(), expected);
                        let seed: [u8; 32] = state.rngs.generate_shared(state.id);
                        assert_eq!(net.reshare(seed).unwrap(), seed);
                        // Common randomness is separate from pairwise masks.
                        // A following private multiplication checks those too.
                        let squared =
                            arithmetic::mul_vec(&shares, &shares, &net, &mut state).unwrap();
                        let expected_squares: Vec<_> = integers
                            .iter()
                            .map(|value| {
                                let value = F::from_le_bytes_mod_order(&value.to_bytes_le());
                                value * value
                            })
                            .collect();
                        assert_eq!(
                            arithmetic::open_vec(&squared, &net).unwrap(),
                            expected_squares
                        );
                    }
                    let before: usize = net
                        .get_connection_stats()
                        .iter()
                        .map(|(_, (sent, received))| sent + received)
                        .sum();
                    assert!(
                        conversion::decompose_arithmetic_many(&shares, &net, &mut state, 70, 0)
                            .is_err()
                    );
                    assert!(
                        conversion::decompose_arithmetic_many(&shares, &net, &mut state, 255, 14)
                            .is_err()
                    );
                    assert!(
                        conversion::decompose_arithmetic_many::<F, _>(
                            &[],
                            &net,
                            &mut state,
                            70,
                            14
                        )
                        .unwrap()
                        .is_empty()
                    );
                    let after: usize = net
                        .get_connection_stats()
                        .iter()
                        .map(|(_, (sent, received))| sent + received)
                        .sum();
                    assert_eq!(
                        before, after,
                        "invalid public parameters and empty inputs must not communicate"
                    );
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
    }
}

#[test]
fn decomposition_matches_fr_integer_oracle_and_preserves_common_rng() {
    exercise::<Fr>();
}

#[test]
fn decomposition_matches_fq_integer_oracle_and_preserves_common_rng() {
    exercise::<Fq>();
}

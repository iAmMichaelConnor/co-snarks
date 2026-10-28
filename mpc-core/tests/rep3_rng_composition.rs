//! Actual-party regressions for RNG composition across conversion domains and forks.
use ark_bn254::{Fq, Fr};
use ark_ff::{PrimeField, Zero};
use mpc_core::MpcState;
use mpc_core::protocols::rep3::{
    Rep3PrimeFieldShare, Rep3State, Rep3UintShare, arithmetic, conversion, share_field_elements,
    yao,
};
use mpc_core::protocols::rep3_ring::{arithmetic as ring, casts, conversion as ring_conversion};
use mpc_core::uint::{U512, UintBackend};
use mpc_net::local::LocalNetwork;
use rand::{SeedableRng, rngs::StdRng};

fn exercise(
    state: &mut Rep3State,
    net: &LocalNetwork,
    input: &[Rep3PrimeFieldShare<Fr>],
    expected: &[Fr],
) -> Vec<[u8; 32]> {
    let mut common = Vec::new();
    for len in [1, 7, 2] {
        let input = &input[..len];
        let expected = &expected[..len];
        // Direct conversion deliberately advances bitcomp masks asymmetrically
        // across roles, even if the state's selected backend is Yao.
        let bits = conversion::a2b_many(input, net, state).unwrap();
        let roundtrip = conversion::b2a_many(&bits, net, state).unwrap();
        let fq_bits: Vec<_> = bits
            .iter()
            .map(|x| Rep3UintShare::<Fq>::new(x.a, x.b))
            .collect();
        let fq = conversion::b2a_many(&fq_bits, net, state).unwrap();
        let fq_squared = arithmetic::mul_vec(&fq, &fq, net, state).unwrap();
        let wide = casts::field_to_ring_a2b_many::<Fq, U512, _>(&fq_squared, net, state).unwrap();
        let wide_bits = ring_conversion::a2b_many(&wide, net, state).unwrap();
        let wide_roundtrip = ring_conversion::b2a_many(&wide_bits, net, state).unwrap();
        let wide_squared = ring::mul_vec(&wide_roundtrip, &wide_roundtrip, net, state).unwrap();
        common.push(state.rngs.generate_shared(state.id));

        // This low-level Yao joint-input path also consumes common randomness.
        // Recombine its three additive components privately before the referee
        // opens the final fixture value; no component is publicly opened.
        let delta = state.rngs.generate_random_garbler_delta(state.id);
        let joint_index = if len > 2 { 2 } else { len - 1 };
        let joint = yao::joint_input_arithmetic(input[joint_index], delta, net, state).unwrap();
        let joint_bits =
            conversion::y2b_many::<Fr, _>(joint.into_iter().collect(), net, state).unwrap();
        let joint_fields = conversion::b2a_many(&joint_bits, net, state).unwrap();
        let recombined = joint_fields
            .into_iter()
            .fold(Rep3PrimeFieldShare::zero_share(), arithmetic::add);
        let selected_bits = conversion::a2b_selector(recombined, net, state).unwrap();
        let selected_roundtrip = conversion::b2a_selector(&selected_bits, net, state).unwrap();
        common.push(state.rngs.generate_shared(state.id));

        // Only known test-fixture results are opened after each private chain.
        assert!(arithmetic::open_vec(&roundtrip, net).unwrap() == expected);
        assert!(
            arithmetic::open_vec(&[selected_roundtrip], net).unwrap() == [expected[joint_index]]
        );
        let expected_fq: Vec<_> = expected
            .iter()
            .map(|x| {
                let x = Fq::from(x.into_bigint());
                x * x
            })
            .collect();
        assert!(arithmetic::open_vec(&fq_squared, net).unwrap() == expected_fq);
        let expected_ring: Vec<_> = expected_fq
            .iter()
            .map(|x| {
                let x = U512::from_limbs_truncating(x.into_bigint().as_ref());
                x * x
            })
            .collect();
        let actual_ring: Vec<_> = ring::open_vec(&wide_squared, net)
            .unwrap()
            .into_iter()
            .map(|x| x.0)
            .collect();
        assert!(actual_ring == expected_ring);
    }
    common
}

#[test]
fn mixed_conversions_and_joint_yao_inputs_compose_across_rng_forks() {
    for backend in [conversion::A2BType::Direct, conversion::A2BType::Yao] {
        let values = [
            Fr::zero(),
            Fr::from(1u64),
            Fr::from(-1i64),
            Fr::from(7u64),
            Fr::from(1234567u64),
            Fr::from(-2i64),
            Fr::from(2u64),
        ];
        let shares = share_field_elements(&values, &mut StdRng::seed_from_u64(0xC011F04));
        let workers: Vec<_> = LocalNetwork::new_3_parties()
            .into_iter()
            .zip(shares)
            .map(|(net, mut shares)| {
                std::thread::spawn(move || {
                    let mut parent = Rep3State::new(&net, backend).unwrap();
                    // Mix in a public fixture using the actual party-aware
                    // trivial-share representation, without changing shape.
                    shares[4] = arithmetic::promote_to_trivial_share(parent.id, values[4]);
                    let mut seeds = exercise(&mut parent, &net, &shares, &values);
                    let mut child = parent.fork(0).unwrap();
                    seeds.extend(exercise(&mut child, &net, &shares, &values));
                    let mut grandchild = child.fork(0).unwrap();
                    seeds.extend(exercise(&mut grandchild, &net, &shares, &values));
                    // Resume both ancestors after their children have consumed
                    // unrelated conversions and common outputs.
                    seeds.extend(exercise(&mut child, &net, &shares, &values));
                    seeds.extend(exercise(&mut parent, &net, &shares, &values));
                    seeds
                })
            })
            .collect();
        let results: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
        assert!(results[0] == results[1] && results[1] == results[2]);
        // First outputs of parent, child, and grandchild must be independent.
        assert!(results[0][0] != results[0][6]);
        assert!(results[0][6] != results[0][12]);
    }
}

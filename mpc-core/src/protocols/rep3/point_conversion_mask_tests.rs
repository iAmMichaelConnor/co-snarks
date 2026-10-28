//! A single-party attack regression for masks used when converting point shares.
use super::*;
use crate::protocols::rep3::{combine_field_elements, rngs::Rep3Rand, share_curve_points};
use ark_bn254::{Fq, Fr, G1Affine, G1Projective};
use ark_ec::PrimeGroup;
use ark_ff::{One, Zero};
use mpc_net::local::LocalNetwork;

#[test]
fn point_conversion_public_canary_does_not_reveal_next_private_point() {
    let canary = G1Projective::generator();
    let secret = canary * Fr::from(73u64);
    let shares = share_curve_points(&[canary, secret], &mut rand::thread_rng());
    let workers: Vec<_> = LocalNetwork::new_3_parties()
        .into_iter()
        .zip(shares)
        .map(|(net, shares)| {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let (masked_x, masked_y, _, _) =
                    point_share_to_fieldshares_pre_many(&shares, &net, &mut state).unwrap();
                if state.id != PartyID::ID2 {
                    return None;
                }
                // Party 2 knows its own point component and the first public
                // input. Its b field is exactly the masked message from party 1.
                let (known_x, known_y) = (canary - shares[0].a).into_affine().xy().unwrap();
                let guessed_x = masked_x[1].b - masked_x[0].b + known_x;
                let guessed_y = masked_y[1].b - masked_y[0].b + known_y;
                // No other party's private state or the secret point is used.
                Some((guessed_x, guessed_y, shares[1].a))
            })
        })
        .collect();
    let (guessed_x, guessed_y, own_component) = workers
        .into_iter()
        .filter_map(|worker| worker.join().unwrap())
        .next()
        .unwrap();
    let actual_hidden = (secret - own_component).into_affine().xy().unwrap();
    assert_ne!(
        (guessed_x, guessed_y),
        actual_hidden,
        "party 2 recovered a private point using one public batch input"
    );
    let guessed_point = G1Affine::new_unchecked(guessed_x, guessed_y).into_group() + own_component;
    assert_ne!(guessed_point, secret);
}

#[test]
fn point_conversion_fresh_masks_preserve_coordinates_and_infinity() {
    let generator = G1Projective::generator();
    let points = [generator, generator * Fr::from(73u64), G1Projective::zero()];
    let shares = share_curve_points(&points, &mut rand::thread_rng());
    let workers: Vec<_> = LocalNetwork::new_3_parties()
        .into_iter()
        .zip(shares)
        .map(|(net, shares)| {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                point_share_to_fieldshares_many(&shares, &net, &mut state).unwrap()
            })
        })
        .collect();
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    let xs = combine_field_elements(&results[0].0, &results[1].0, &results[2].0);
    let ys = combine_field_elements(&results[0].1, &results[1].1, &results[2].1);
    let infinity = combine_field_elements(&results[0].2, &results[1].2, &results[2].2);
    for (i, point) in points.iter().enumerate() {
        if point.is_zero() {
            assert_eq!(infinity[i], Fq::one());
        } else {
            assert!(infinity[i].is_zero());
            assert_eq!((xs[i], ys[i]), point.into_affine().xy().unwrap());
        }
    }
}

#[test]
fn point_conversion_empty_batch_consumes_no_masks() {
    let workers: Vec<_> = LocalNetwork::new_3_parties()
        .into_iter()
        .map(|net| {
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let id = net.id();
                let seeds = [[11u8; 32], [22u8; 32], [33u8; 32]];
                state.rngs.rand = Rep3Rand::new(seeds[id], seeds[(id + 2) % 3]);
                let mut untouched = Rep3Rand::new(seeds[id], seeds[(id + 2) % 3]);
                let result =
                    point_share_to_fieldshares_pre_many::<G1Projective, _>(&[], &net, &mut state)
                        .unwrap();
                assert!(
                    result.0.is_empty()
                        && result.1.is_empty()
                        && result.2.is_empty()
                        && result.3.is_empty()
                );
                assert_eq!(
                    state.rngs.rand.masking_field_element::<Fq>(),
                    untouched.masking_field_element::<Fq>()
                );
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
}

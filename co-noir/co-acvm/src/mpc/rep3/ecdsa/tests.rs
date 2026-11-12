//! Compares the REP3 ECDSA verification with the plain one on test vectors, for both
//! arithmetic/binary conversion types and for mixes of public and secret-shared inputs.

use super::super::{Rep3AcvmSolver, Rep3AcvmType};
use crate::mpc::{NoirWitnessExtensionProtocol, plain::PlainAcvmSolver};
use ark_bn254::Fr;
use itertools::izip;
use mpc_core::protocols::rep3::{self, conversion::A2BType};
use mpc_net::local::LocalNetwork;
use rand::thread_rng;
use std::array;
use vectors::{VECTORS, Vector};

mod vectors;

fn bytes<const N: usize>(hex: &str) -> [Fr; N] {
    assert_eq!(hex.len(), 2 * N);
    array::from_fn(|i| Fr::from(u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex byte")))
}

/// Which of the hashed message, public key x, public key y and signature are secret-shared.
const VISIBILITIES: [[bool; 4]; 5] = [
    [true, true, true, true],
    [true, false, false, true],
    [false, true, true, false],
    [false, false, false, true],
    [false, false, false, false],
];

/// The inputs of the three parties, each public or shared.
fn share<const N: usize>(values: [Fr; N], shared: bool) -> [[Rep3AcvmType<Fr>; N]; 3] {
    if shared {
        let shares = rep3::share_field_elements(&values, &mut thread_rng());
        shares.map(|shares| array::from_fn(|i| Rep3AcvmType::Shared(shares[i])))
    } else {
        array::from_fn(|_| values.map(Rep3AcvmType::Public))
    }
}

type PartyInputs = (
    [Rep3AcvmType<Fr>; 32],
    [Rep3AcvmType<Fr>; 32],
    [Rep3AcvmType<Fr>; 32],
    [Rep3AcvmType<Fr>; 64],
);

fn plain_verify(vector: &Vector) -> bool {
    let result = PlainAcvmSolver::<Fr>::new()
        .ecdsa_verify(
            vector.curve,
            &bytes(vector.hashed_message),
            &bytes(vector.public_key_x),
            &bytes(vector.public_key_y),
            &bytes(vector.signature),
        )
        .expect("plain verification");
    assert!(result == Fr::from(0u64) || result == Fr::from(1u64));
    result == Fr::from(1u64)
}

#[test]
fn plain_matches_vectors() {
    for vector in VECTORS {
        assert_eq!(
            plain_verify(vector),
            vector.is_valid,
            "{:?}: {}",
            vector.curve,
            vector.case
        );
    }
}

#[test]
fn rep3_matches_plain() {
    for a2b_type in [A2BType::Yao, A2BType::Direct] {
        let mut inputs: [Vec<PartyInputs>; 3] = Default::default();
        for (i, vector) in VECTORS.iter().enumerate() {
            let [hashed, x, y, signature] = VISIBILITIES[i % VISIBILITIES.len()];
            let hashed = share(bytes(vector.hashed_message), hashed);
            let x = share(bytes(vector.public_key_x), x);
            let y = share(bytes(vector.public_key_y), y);
            let signature = share(bytes(vector.signature), signature);
            for (party, inputs) in inputs.iter_mut().enumerate() {
                inputs.push((
                    hashed[party].clone(),
                    x[party].clone(),
                    y[party].clone(),
                    signature[party].clone(),
                ));
            }
        }

        let nets = LocalNetwork::new_3_parties();
        let threads = izip!(nets, inputs)
            .map(|(net, inputs)| {
                std::thread::spawn(move || {
                    let mut solver = Rep3AcvmSolver::<Fr, _>::new(&net, a2b_type).unwrap();
                    izip!(VECTORS, inputs)
                        .map(|(vector, (hashed, x, y, signature))| {
                            solver
                                .ecdsa_verify(vector.curve, &hashed, &x, &y, &signature)
                                .unwrap()
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>();
        let results = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();

        for (i, (vector, a, b, c)) in
            izip!(VECTORS, &results[0], &results[1], &results[2]).enumerate()
        {
            let is_valid = match (a, b, c) {
                (Rep3AcvmType::Public(a), Rep3AcvmType::Public(b), Rep3AcvmType::Public(c)) => {
                    assert!(a == b && b == c);
                    assert_eq!(VISIBILITIES[i % VISIBILITIES.len()], [false; 4]);
                    *a
                }
                (Rep3AcvmType::Shared(a), Rep3AcvmType::Shared(b), Rep3AcvmType::Shared(c)) => {
                    rep3::combine_field_element(*a, *b, *c)
                }
                _ => panic!("parties disagree on the visibility of the result"),
            };
            assert_eq!(
                is_valid,
                Fr::from(plain_verify(vector)),
                "{a2b_type:?}, {:?}: {}",
                vector.curve,
                vector.case
            );
        }
    }
}

//! Tests the disclosure policy at the recursive witness-generation boundary.
use super::*;
use crate::types::types::WitnessOrConstant;
use ark_bn254::{Fr, G1Projective};
use co_acvm::{Rep3AcvmSolver, Rep3AcvmType};
use mpc_core::protocols::rep3::{conversion::A2BType, share_field_elements};
use mpc_net::{Network, local::LocalNetwork};

#[test]
fn explicit_reveal_recursion_opens_inputs_and_predicate_but_not_other_witnesses() {
    let values = [101u64, 103, 107, 109, 0, 113].map(Fr::from);
    let shares = share_field_elements(&values, &mut rand::thread_rng());
    let workers: Vec<_> = LocalNetwork::new_3_parties()
        .into_iter()
        .zip(shares)
        .map(|(net, shares)| {
            std::thread::spawn(move || {
                let mut driver = Rep3AcvmSolver::<Fr, _>::new(&net, A2BType::default()).unwrap();
                for proof_type in [ProofType::Honk, ProofType::HonkZk] {
                    let mut builder = GenericUltraCircuitBuilder::<G1Projective, _>::new_minimal(0);
                    builder.recursion_input_visibility =
                        RecursionInputVisibility::RevealToParticipants;
                    let indices: Vec<_> = shares
                        .iter()
                        .map(|share| builder.add_variable(Rep3AcvmType::Shared(*share)))
                        .collect();
                    let input = RecursionConstraint {
                        proof: vec![indices[0]],
                        key: vec![indices[1]],
                        key_hash: indices[2],
                        public_inputs: vec![indices[3]],
                        predicate: WitnessOrConstant::from_index(indices[4]),
                        proof_type: proof_type as u32,
                    };
                    builder
                        .prepare_recursion_inputs(&input, &mut driver)
                        .unwrap();
                    // Each party checks only its own view, including a false predicate.
                    for (index, expected) in indices[..5].iter().zip(&values[..5]) {
                        match builder.get_variable(*index as usize) {
                            Rep3AcvmType::Public(actual) => assert_eq!(actual, *expected),
                            Rep3AcvmType::Shared(_) => panic!("explicit opening did not occur"),
                        }
                    }
                    assert!(matches!(
                        builder.get_variable(indices[5] as usize),
                        Rep3AcvmType::Shared(_)
                    ));
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
}

#[test]
fn keep_secret_preserves_each_shared_recursion_input_without_opening() {
    let values = [101u64, 103, 107, 109, 0, 113].map(Fr::from);
    let shares = share_field_elements(&values, &mut rand::thread_rng());
    let workers: Vec<_> = LocalNetwork::new_3_parties()
        .into_iter()
        .zip(shares)
        .map(|(net, shares)| {
            std::thread::spawn(move || {
                let net = RecordingNetwork::new(net);
                let mut driver = Rep3AcvmSolver::<Fr, _>::new(&net, A2BType::default()).unwrap();
                for proof_type in [ProofType::Honk, ProofType::HonkZk] {
                    for private_role in 0..6 {
                        let mut builder =
                            GenericUltraCircuitBuilder::<G1Projective, _>::new_minimal(0);
                        assert_eq!(
                            builder.recursion_input_visibility,
                            RecursionInputVisibility::KeepSecret
                        );
                        let indices: Vec<_> = values
                            .iter()
                            .enumerate()
                            .map(|(role, value)| {
                                builder.add_variable(if role == private_role {
                                    Rep3AcvmType::Shared(shares[role])
                                } else {
                                    Rep3AcvmType::Public(*value)
                                })
                            })
                            .collect();
                        let fixed_size = if matches!(proof_type, ProofType::Honk) {
                            ULTRA_PROOF_LENGTH_WITHOUT_PUB_INPUTS
                        } else {
                            ULTRA_PROOF_LENGTH_WITHOUT_PUB_INPUTS_ZK
                        };
                        let input = RecursionConstraint {
                            proof: vec![indices[0]; PUBLIC_INPUTS_SIZE + fixed_size],
                            key: vec![indices[1]; ULTRA_VERIFICATION_KEY_LENGTH],
                            key_hash: indices[2],
                            public_inputs: vec![indices[3]],
                            predicate: WitnessOrConstant::from_index(indices[4]),
                            proof_type: proof_type as u32,
                        };
                        net.clear_frames();
                        builder
                            .prepare_recursion_inputs(&input, &mut driver)
                            .unwrap();
                        net.assert_only_policy_frames(false);
                        assert!(matches!(
                            builder.get_variable(indices[private_role] as usize),
                            Rep3AcvmType::Shared(_)
                        ));
                    }
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
}

#[test]
fn unsupported_shamir_private_recursion_rejects_before_secret_opening() {
    use co_acvm::{ShamirAcvmSolver, ShamirAcvmType};
    use mpc_core::protocols::shamir::{self, ShamirPreprocessing, ShamirState};
    let values = [101u64, 103, 107, 109, 0, 113].map(Fr::from);
    let mut shares: [Vec<_>; 3] = std::array::from_fn(|_| Vec::new());
    for value in values {
        for (party, share) in shamir::share_field_element(value, 1, 3, &mut rand::thread_rng())
            .into_iter()
            .enumerate()
        {
            shares[party].push(share);
        }
    }
    let workers: Vec<_> =
        LocalNetwork::new_3_parties()
            .into_iter()
            .zip(shares)
            .map(|(net, shares)| {
                std::thread::spawn(move || {
                    let net = RecordingNetwork::new(net);
                    let preprocessing = ShamirPreprocessing::new(3, 1, 0, &net).unwrap();
                    let mut driver =
                        ShamirAcvmSolver::<Fr, _>::new(&net, ShamirState::from(preprocessing));
                    for proof_type in [ProofType::Honk, ProofType::HonkZk] {
                        for private_role in 0..6 {
                            let mut builder =
                                GenericUltraCircuitBuilder::<G1Projective, _>::new_minimal(0);
                            assert_eq!(
                                builder.recursion_input_visibility,
                                RecursionInputVisibility::KeepSecret
                            );
                            let indices: Vec<_> = values
                                .iter()
                                .enumerate()
                                .map(|(role, value)| {
                                    builder.add_variable(if role == private_role {
                                        ShamirAcvmType::Shared(shares[role])
                                    } else {
                                        ShamirAcvmType::Public(*value)
                                    })
                                })
                                .collect();
                            let fixed_size = if matches!(proof_type, ProofType::Honk) {
                                ULTRA_PROOF_LENGTH_WITHOUT_PUB_INPUTS
                            } else {
                                ULTRA_PROOF_LENGTH_WITHOUT_PUB_INPUTS_ZK
                            };
                            let input = RecursionConstraint {
                                proof: vec![indices[0]; PUBLIC_INPUTS_SIZE + fixed_size],
                                key: vec![indices[1]; ULTRA_VERIFICATION_KEY_LENGTH],
                                key_hash: indices[2],
                                public_inputs: vec![indices[3]],
                                predicate: WitnessOrConstant::from_index(indices[4]),
                                proof_type: proof_type as u32,
                            };
                            net.clear_frames();
                            {
                                // Exercise the real boundary with correct public vector lengths.
                                // Rejection must precede predicate conversion and proof arithmetic.
                                let error = builder
                                    .create_honk_recursion_constraints(
                                        &input,
                                        &ProverCrs::default(),
                                        &mut driver,
                                    )
                                    .err()
                                    .expect("shared recursive input must be rejected");
                                assert!(error.to_string().contains(
                                    "Private recursive witness generation is not supported"
                                ));
                            }
                            net.assert_only_policy_frames(false);
                            assert!(matches!(
                                builder.get_variable(indices[private_role] as usize),
                                ShamirAcvmType::Shared(_)
                            ));
                        }
                    }
                })
            })
            .collect();
    for worker in workers {
        worker.join().unwrap();
    }
}

#[test]
fn recursion_visibility_handles_overlapping_roles_and_canonical_witness_aliases() {
    let values = [Fr::from(127u64), Fr::from(131u64)];
    let shares = share_field_elements(&values, &mut rand::thread_rng());
    let workers: Vec<_> = LocalNetwork::new_3_parties()
        .into_iter()
        .zip(shares)
        .map(|(net, shares)| {
            std::thread::spawn(move || {
                let mut driver = Rep3AcvmSolver::<Fr, _>::new(&net, A2BType::default()).unwrap();
                for proof_type in [ProofType::Honk, ProofType::HonkZk] {
                    for visibility in [
                        RecursionInputVisibility::KeepSecret,
                        RecursionInputVisibility::RevealToParticipants,
                    ] {
                        let mut builder =
                            GenericUltraCircuitBuilder::<G1Projective, _>::new_minimal(0);
                        builder.recursion_input_visibility = visibility;
                        let original = builder.add_variable(Rep3AcvmType::Shared(shares[0]));
                        let alias = builder.add_variable(Rep3AcvmType::Shared(shares[0]));
                        let unrelated = builder.add_variable(Rep3AcvmType::Shared(shares[1]));
                        builder.assert_equal(alias as usize, original as usize);
                        assert_ne!(builder.real_variable_index[original as usize], original);
                        let input = RecursionConstraint {
                            proof: vec![original, alias, original],
                            key: vec![alias, original],
                            key_hash: alias,
                            public_inputs: vec![original, alias],
                            // Its sentinel index must never be treated as a witness.
                            predicate: WitnessOrConstant::from_constant(Fr::zero()),
                            proof_type: proof_type as u32,
                        };
                        let result = builder.prepare_recursion_inputs(&input, &mut driver);
                        match visibility {
                            RecursionInputVisibility::KeepSecret => {
                                result.unwrap();
                                assert!(matches!(
                                    builder.get_variable(original as usize),
                                    Rep3AcvmType::Shared(_)
                                ));
                            }
                            RecursionInputVisibility::RevealToParticipants => {
                                result.unwrap();
                                for index in [original, alias] {
                                    assert_eq!(
                                        builder.get_variable(index as usize),
                                        Rep3AcvmType::Public(values[0])
                                    );
                                }
                            }
                        }
                        assert_eq!(
                            builder.get_variable(unrelated as usize),
                            Rep3AcvmType::Shared(shares[1]),
                            "overlapping recursion inputs must not open unrelated data"
                        );
                    }
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
}

struct RecordingNetwork {
    inner: LocalNetwork,
    frames: std::sync::Mutex<Vec<Vec<u8>>>,
}
impl RecordingNetwork {
    fn new(inner: LocalNetwork) -> Self {
        Self {
            inner,
            frames: Default::default(),
        }
    }
    fn clear_frames(&self) {
        self.frames.lock().unwrap().clear();
    }
    fn assert_only_policy_frames(&self, reveal: bool) {
        let mut expected = b"co-noir-recursion-visibility-v1".to_vec();
        expected.push(u8::from(reveal));
        let frames = self.frames.lock().unwrap();
        assert_eq!(
            frames.len(),
            2,
            "only the two public policy messages may be sent"
        );
        assert!(
            frames.iter().all(|frame| frame == &expected),
            "no witness-derived data may be sent before agreement or on rejection"
        );
    }
}
impl Network for RecordingNetwork {
    fn id(&self) -> usize {
        self.inner.id()
    }
    fn send(&self, to: usize, data: mpc_net::bytes::Bytes) -> eyre::Result<()> {
        self.frames.lock().unwrap().push(data.to_vec());
        self.inner.send(to, data)
    }
    fn recv(&self, from: usize) -> eyre::Result<mpc_net::bytes::Bytes> {
        self.inner.recv(from)
    }
    fn get_connection_stats(&self) -> mpc_net::ConnectionStats {
        self.inner.get_connection_stats()
    }
}

fn check_mismatched_modes<T: NoirWitnessExtensionProtocol<Fr>>(
    driver: &mut T,
    net: &RecordingNetwork,
    shared: T::AcvmType,
) {
    for lone_party in 0..3 {
        for lone_reveals in [false, true] {
            let reveal = if net.id() == lone_party {
                lone_reveals
            } else {
                !lone_reveals
            };
            let mut builder = GenericUltraCircuitBuilder::<G1Projective, T>::new_minimal(0);
            builder.recursion_input_visibility = if reveal {
                RecursionInputVisibility::RevealToParticipants
            } else {
                RecursionInputVisibility::KeepSecret
            };
            let index = builder.add_variable(shared.clone());
            let input = RecursionConstraint {
                proof: vec![index],
                key: vec![index],
                key_hash: index,
                public_inputs: vec![index],
                predicate: WitnessOrConstant::from_index(index),
                proof_type: ProofType::HonkZk as u32,
            };
            net.clear_frames();
            let error = builder
                .prepare_recursion_inputs(&input, driver)
                .unwrap_err();
            assert!(error.to_string().contains("participants disagree"));
            net.assert_only_policy_frames(reveal);
            assert!(T::is_shared(&builder.get_variable(index as usize)));
        }
    }
    // A mismatch is fully drained: a later unanimous exchange can reuse this network.
    net.clear_frames();
    driver.agree_recursion_input_visibility(false).unwrap();
    net.assert_only_policy_frames(false);
}

#[test]
fn rep3_mismatched_visibility_rejects_without_secret_traffic() {
    let shares = share_field_elements(&[Fr::from(101u64)], &mut rand::thread_rng());
    let workers: Vec<_> = LocalNetwork::new_3_parties()
        .into_iter()
        .zip(shares)
        .map(|(net, shares)| {
            std::thread::spawn(move || {
                let net = RecordingNetwork::new(net);
                let mut driver = Rep3AcvmSolver::<Fr, _>::new(&net, A2BType::default()).unwrap();
                check_mismatched_modes(&mut driver, &net, Rep3AcvmType::Shared(shares[0]));
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
}

#[test]
fn shamir_mismatched_visibility_rejects_without_secret_traffic() {
    use co_acvm::{ShamirAcvmSolver, ShamirAcvmType};
    use mpc_core::protocols::shamir::{self, ShamirPreprocessing, ShamirState};
    let shares = shamir::share_field_element(Fr::from(101u64), 1, 3, &mut rand::thread_rng());
    let workers: Vec<_> = LocalNetwork::new_3_parties()
        .into_iter()
        .zip(shares)
        .map(|(net, share)| {
            std::thread::spawn(move || {
                let net = RecordingNetwork::new(net);
                let preprocessing = ShamirPreprocessing::new(3, 1, 0, &net).unwrap();
                let mut driver =
                    ShamirAcvmSolver::<Fr, _>::new(&net, ShamirState::from(preprocessing));
                check_mismatched_modes(&mut driver, &net, ShamirAcvmType::Shared(share));
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
}

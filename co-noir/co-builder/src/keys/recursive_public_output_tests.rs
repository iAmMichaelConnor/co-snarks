use super::*;
use ark_bn254::{Fr, G1Projective};
use ark_ff::{BigInteger, PrimeField};
use co_acvm::{Rep3AcvmSolver, Rep3AcvmType};
use mpc_core::protocols::rep3::{conversion::A2BType, id::PartyID, share_field_elements};
use mpc_net::{Network, bytes::Bytes, local::LocalNetwork};
use std::sync::Mutex;
struct RecordingNetwork {
    inner: LocalNetwork,
    sent: Mutex<Vec<Bytes>>,
}
impl Network for RecordingNetwork {
    fn id(&self) -> usize {
        self.inner.id()
    }
    fn send(&self, to: usize, data: Bytes) -> eyre::Result<()> {
        self.sent.lock().unwrap().push(data.clone());
        self.inner.send(to, data)
    }
    fn recv(&self, from: usize) -> eyre::Result<Bytes> {
        self.inner.recv(from)
    }
    fn get_connection_stats(&self) -> mpc_net::ConnectionStats {
        self.inner.get_connection_stats()
    }
}
#[test]
fn private_recursion_key_opens_only_designated_final_outputs() {
    let values: Vec<_> = (100..109u64).map(Fr::from).collect();
    let shares = share_field_elements(&values, &mut rand::thread_rng());
    let workers: Vec<_> = LocalNetwork::new_3_parties()
        .into_iter()
        .zip(shares)
        .map(|(inner, shares)| {
            let values = values.clone();
            std::thread::spawn(move || {
                let net = RecordingNetwork {
                    inner,
                    sent: Mutex::new(Vec::new()),
                };
                let mut driver = Rep3AcvmSolver::<Fr, _>::new(&net, A2BType::default()).unwrap();
                for declare_inner_public in [false, true] {
                    let mut builder = GenericUltraCircuitBuilder::<G1Projective, _>::new_minimal(0);
                    let indices: Vec<_> = shares
                        .iter()
                        .map(|s| builder.add_variable(Rep3AcvmType::Shared(*s)))
                        .collect();
                    // Index zero here represents an inner public input that remains
                    // secret in the outer computation; the other eight are outputs.
                    builder.recursion_public_output_indices = indices[1..].to_vec();
                    builder.public_inputs = if declare_inner_public {
                        indices.clone()
                    } else {
                        indices[1..].to_vec()
                    };
                    assert!(matches!(
                        builder.get_variable(indices[0] as usize),
                        Rep3AcvmType::Shared(_)
                    ));
                    builder.finalize_circuit(&mut driver).unwrap();
                    net.sent.lock().unwrap().clear();
                    let result = create_prover_instance::<G1Projective, Rep3UltraHonkDriver, _>(
                        PartyID::try_from(net.id()).unwrap(),
                        builder,
                        &mut driver,
                    );
                    if declare_inner_public {
                        assert!(matches!(result, Err(HonkProofError::ExpectedPublicWitness)));
                        assert!(
                            net.sent.lock().unwrap().is_empty(),
                            "reject undesignated shared public input before opening"
                        );
                    } else {
                        assert_eq!(result.unwrap().public_inputs, values[1..]);
                        let frames = net.sent.lock().unwrap();
                        assert_eq!(frames.len(), 1, "exactly one designated output opening");
                        // reshare(Vec) encodes one outer vector containing eight fields.
                        let mut expected = Vec::new();
                        expected.extend_from_slice(&1u64.to_le_bytes());
                        expected.extend_from_slice(&8u64.to_le_bytes());
                        for share in &shares[1..] {
                            expected.extend_from_slice(&share.b.into_bigint().to_bytes_le());
                        }
                        assert_eq!(
                            frames[0].as_ref(),
                            expected.as_slice(),
                            "the wire contains exactly the final eight output shares"
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

use super::*;
use ark_bn254::{Fr, G1Projective};
use ark_ff::Field;
use ark_serialize::CanonicalDeserialize;
use bytes::Bytes;
use co_noir_common::mpc::rep3::Rep3UltraHonkDriver;
use co_noir_common::polynomials::entities::Polynomials;
use co_noir_common::transcript::Poseidon2Sponge;
use mpc_core::protocols::rep3::{Rep3State, conversion::A2BType, share_field_element};
use mpc_net::{ConnectionStats, local::LocalNetwork};
use std::sync::Mutex;

// A participant can reconstruct each broadcast from its own outgoing value and
// its two received values. No other participant's private state is inspected.
struct RecordingNetwork {
    inner: LocalNetwork,
    events: Mutex<Vec<(bool, Bytes)>>,
}

impl Network for RecordingNetwork {
    fn id(&self) -> usize {
        self.inner.id()
    }

    fn send(&self, to: usize, data: Bytes) -> eyre::Result<()> {
        self.events.lock().unwrap().push((true, data.clone()));
        self.inner.send(to, data)
    }

    fn recv(&self, from: usize) -> eyre::Result<Bytes> {
        let data = self.inner.recv(from)?;
        self.events.lock().unwrap().push((false, data.clone()));
        Ok(data)
    }

    fn get_connection_stats(&self) -> ConnectionStats {
        self.inner.get_connection_stats()
    }
}

#[test]
fn lookup_inversion_openings_do_not_reveal_secret_read_tags() {
    const N: usize = 8;
    // q_lookup is zero on table rows. A secret read tag still enables their
    // inverses. These four tags model a witness using two private table entries.
    let tags = [Fr::zero(), Fr::one(), Fr::zero(), Fr::one()];
    let mut rng = rand::thread_rng();
    let shared_tags = tags.map(|tag| share_field_element(tag, &mut rng));
    let threads: Vec<_> = LocalNetwork::new_3_parties()
        .into_iter()
        .enumerate()
        .map(|(id, inner)| {
            std::thread::spawn(move || {
                let net = RecordingNetwork {
                    inner,
                    events: Mutex::new(Vec::new()),
                };
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let mut pk = ProvingKey::<Rep3UltraHonkDriver, G1Projective> {
                    circuit_size: N as u32,
                    polynomials: Polynomials::new(N),
                    ..Default::default()
                };
                for (row, shares) in (TRACE_OFFSET..N).zip(shared_tags) {
                    pk.polynomials.witness.lookup_read_tags_mut()[row] = shares[id];
                }
                let mut oink =
                    CoOink::<_, _, Poseidon2Sponge, _>::new(&net, &mut state, ZeroKnowledge::No);
                // Both compressed terms equal gamma; all denominators outside
                // the publicly disabled head are 49, independently of the tags.
                oink.memory.challenges.gamma = Fr::from(7u64);
                net.events.lock().unwrap().clear();
                oink.compute_logderivative_inverses(&pk).unwrap();
                (
                    oink.memory.lookup_inverses.coefficients,
                    net.events.into_inner().unwrap(),
                )
            })
        })
        .collect();
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();

    // Correctness is separate from the privacy assertion: each enabled row
    // must contain 1/49, and each disabled row must contain zero.
    for row in 0..N {
        let inverse: Fr = results.iter().map(|(values, _)| values[row].a).sum();
        let expected = if row < TRACE_OFFSET {
            Fr::zero()
        } else {
            tags[row - TRACE_OFFSET] * Fr::from(49u64).inverse().unwrap()
        };
        assert_eq!(inverse, expected, "incorrect lookup inverse at row {row}");
    }

    let events = &results[0].1; // Exactly one participant's view.
    let broadcasts: Vec<_> = events
        .windows(4)
        .filter(|w| w[0].0 && w[1].0 && !w[2].0 && !w[3].0 && w[0].1 == w[1].1)
        .collect();
    assert_eq!(broadcasts.len(), 1, "expected one masked inversion opening");
    let frames = broadcasts[0];
    let mut opened = Vec::<Fr>::deserialize_uncompressed(frames[0].1.as_ref()).unwrap();
    for frame in &frames[2..] {
        let received = Vec::<Fr>::deserialize_uncompressed(frame.1.as_ref()).unwrap();
        assert_eq!(received.len(), N);
        for (value, share) in opened.iter_mut().zip(received) {
            *value += share;
        }
    }
    assert_eq!(opened.len(), N);
    let zero_pattern: Vec<_> = opened.iter().map(Zero::is_zero).collect();
    assert_eq!(
        zero_pattern,
        (0..N).map(|row| row < TRACE_OFFSET).collect::<Vec<_>>(),
        "inversion opening exposed private read tags: only the public disabled head may be zero"
    );
}

#[test]
fn lookup_inverse_activation_preserves_boolean_and_zero_cases() {
    use co_noir_common::mpc::plain::PlainUltraHonkDriver;
    let mut pk = ProvingKey::<PlainUltraHonkDriver, G1Projective> {
        circuit_size: 16,
        polynomials: Polynomials::new(16),
        ..Default::default()
    };
    let gamma = Fr::from(7u64);
    for case in 0..8 {
        let row = TRACE_OFFSET + case;
        pk.polynomials.precomputed.q_lookup_mut()[row] = Fr::from((case & 1) as u64);
        pk.polynomials.witness.lookup_read_tags_mut()[row] = Fr::from(((case >> 1) & 1) as u64);
        if case & 4 != 0 {
            pk.polynomials.precomputed.table_1_mut()[row] = -gamma;
        }
    }
    let mut state = Default::default();
    let mut oink = CoOink::<_, _, Poseidon2Sponge, _>::new(&(), &mut state, ZeroKnowledge::No);
    oink.memory.challenges.gamma = gamma;
    oink.compute_logderivative_inverses(&pk).unwrap();
    for row in 0..16 {
        let expected = if (TRACE_OFFSET..TRACE_OFFSET + 8).contains(&row) {
            let case = row - TRACE_OFFSET;
            if case & 4 == 0 && case & 3 != 0 {
                (gamma * gamma).inverse().unwrap()
            } else {
                Fr::zero()
            }
        } else {
            Fr::zero()
        };
        assert_eq!(oink.memory.lookup_inverses[row], expected, "row {row}");
    }
}

#[test]
fn rom_inversion_opens_every_public_record_without_revealing_multiplicities() {
    const N: usize = 8;
    let counts = [Fr::zero(), Fr::from(2u64), Fr::one(), Fr::zero()];
    let mut rng = rand::thread_rng();
    let shared_counts = counts.map(|count| share_field_element(count, &mut rng));
    let threads: Vec<_> = LocalNetwork::new_3_parties()
        .into_iter()
        .enumerate()
        .map(|(id, inner)| {
            std::thread::spawn(move || {
                let net = RecordingNetwork {
                    inner,
                    events: Mutex::new(Vec::new()),
                };
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let mut pk = ProvingKey::<Rep3UltraHonkDriver, G1Projective> {
                    circuit_size: N as u32,
                    polynomials: Polynomials::new(N),
                    rom_logup_records: (TRACE_OFFSET as u32..N as u32).collect(),
                    ..Default::default()
                };
                for (row, shares) in (TRACE_OFFSET..N).zip(shared_counts) {
                    pk.polynomials.witness.w_o_mut()[row] = shares[id];
                    pk.polynomials.precomputed.q_c_mut()[row] = Fr::from(3u64);
                }
                let mut oink =
                    CoOink::<_, _, Poseidon2Sponge, _>::new(&net, &mut state, ZeroKnowledge::No);
                oink.memory.w_4 = Polynomial::new_default(N);
                oink.memory.challenges.eta_1 = Fr::from(5u64);
                oink.memory.challenges.eta_2 = Fr::from(25u64);
                oink.memory.challenges.rom_logup_gamma = Fr::from(7u64);
                net.events.lock().unwrap().clear();
                oink.add_rom_logup_inverses_to_wire_4(&pk).unwrap();
                (
                    oink.memory.w_4.coefficients,
                    net.events.into_inner().unwrap(),
                )
            })
        })
        .collect();
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    for row in 0..N {
        let inverse: Fr = results.iter().map(|(values, _)| values[row].a).sum();
        assert_eq!(
            inverse,
            if row < TRACE_OFFSET {
                Fr::zero()
            } else {
                // gamma + index + eta*value + eta^2*array_id = 7 + 25*3.
                Fr::from(82u64).inverse().unwrap()
            }
        );
    }
    let broadcasts: Vec<_> = results[0]
        .1
        .windows(4)
        .filter(|w| w[0].0 && w[1].0 && !w[2].0 && !w[3].0 && w[0].1 == w[1].1)
        .collect();
    assert_eq!(
        broadcasts.len(),
        1,
        "expected one masked ROM inversion opening"
    );
    let frames = broadcasts[0];
    let mut opened = Vec::<Fr>::deserialize_uncompressed(frames[0].1.as_ref()).unwrap();
    for frame in &frames[2..] {
        let received = Vec::<Fr>::deserialize_uncompressed(frame.1.as_ref()).unwrap();
        assert_eq!(received.len(), N - TRACE_OFFSET);
        for (value, share) in opened.iter_mut().zip(received) {
            *value += share;
        }
    }
    assert_eq!(
        opened.len(),
        N - TRACE_OFFSET,
        "must include unused table rows"
    );
    assert!(
        opened.iter().all(|value| !value.is_zero()),
        "masked ROM denominators must not expose zero private multiplicities"
    );
}

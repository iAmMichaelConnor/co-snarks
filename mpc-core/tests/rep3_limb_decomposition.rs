//! REP3 limb decomposition against an integer reference, and its communication compared with the
//! garbled-circuit decomposition.
use ark_bn254::{Fq, Fr};
use ark_ff::{BigInteger, UniformRand};
use bytes::Bytes;
use mpc_core::protocols::rep3::{
    Rep3PrimeFieldShare, Rep3State, arithmetic, conversion, network::Rep3NetworkExt,
    share_field_elements, yao,
};
use mpc_core::uint::FieldUint;
use mpc_net::{ConnectionStats, Network, local::LocalNetwork};
use num_bigint::BigUint;
use rand::{SeedableRng, rngs::StdRng};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Counts the messages and bytes a party sends and records the largest message.
#[derive(Default)]
struct Counts {
    messages: AtomicUsize,
    bytes: AtomicUsize,
    max_message: AtomicUsize,
}

struct CountingNetwork {
    inner: LocalNetwork,
    counts: Counts,
}

impl CountingNetwork {
    fn snapshot(&self) -> [usize; 3] {
        [
            self.counts.messages.load(Ordering::SeqCst),
            self.counts.bytes.load(Ordering::SeqCst),
            self.counts.max_message.swap(0, Ordering::SeqCst),
        ]
    }
}

impl Network for CountingNetwork {
    fn id(&self) -> usize {
        self.inner.id()
    }

    fn send(&self, to: usize, data: Bytes) -> eyre::Result<()> {
        self.counts.messages.fetch_add(1, Ordering::SeqCst);
        self.counts.bytes.fetch_add(data.len(), Ordering::SeqCst);
        self.counts
            .max_message
            .fetch_max(data.len(), Ordering::SeqCst);
        self.inner.send(to, data)
    }

    fn recv(&self, from: usize) -> eyre::Result<Bytes> {
        self.inner.recv(from)
    }

    fn get_connection_stats(&self) -> ConnectionStats {
        self.inner.get_connection_stats()
    }
}

fn to_integer<F: FieldUint>(value: &F) -> BigUint {
    BigUint::from_bytes_le(&value.into_bigint().to_bytes_le())
}

fn from_integer<F: FieldUint>(value: &BigUint) -> F {
    F::from_le_bytes_mod_order(&value.to_bytes_le())
}

fn exercise<F: FieldUint>() {
    for backend in [conversion::A2BType::Direct, conversion::A2BType::Yao] {
        let mut rng = StdRng::seed_from_u64(0xdec0);
        let mut values = vec![F::from(0u64), F::from(1u64), -F::from(1u64), -F::from(2u64)];
        for bit in [13usize, 14, 56, 68, 69, 70, 136, 253] {
            let boundary = BigUint::from(1u64) << bit;
            values.push(from_integer(&boundary));
            values.push(from_integer(&(boundary - BigUint::from(1u64))));
        }
        values.extend((0..5).map(|_| F::rand(&mut rng)));
        let integers: Vec<_> = values.iter().map(to_integer).collect();
        let shares = share_field_elements(&values, &mut rng);
        let workers: Vec<_> = LocalNetwork::new_3_parties()
            .into_iter()
            .zip(shares)
            .map(|(net, shares)| {
                let integers = integers.clone();
                std::thread::spawn(move || {
                    let mut state = Rep3State::new(&net, backend).unwrap();
                    // Includes a single short limb, a short last limb and 70 bits in five
                    // 14-bit limbs.
                    for (total, limb_size) in [
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
                            &shares, &net, &mut state, total, limb_size,
                        )
                        .unwrap();
                        let expected: Vec<F> = integers
                            .iter()
                            .flat_map(|value| {
                                (0..total.div_ceil(limb_size)).map(move |limb| {
                                    let size = limb_size.min(total - limb * limb_size);
                                    let mask = (BigUint::from(1u64) << size) - BigUint::from(1u64);
                                    from_integer(&((value >> (limb * limb_size)) & mask))
                                })
                            })
                            .collect();
                        assert_eq!(arithmetic::open_vec(&result, &net).unwrap(), expected);
                        // The parties' random streams stay in sync.
                        let seed: [u8; 32] = state.rngs.generate_shared(state.id);
                        assert_eq!(net.reshare(seed).unwrap(), seed);
                        let squares =
                            arithmetic::mul_vec(&shares, &shares, &net, &mut state).unwrap();
                        let expected: Vec<F> = integers
                            .iter()
                            .map(|value| from_integer::<F>(value).square())
                            .collect();
                        assert_eq!(arithmetic::open_vec(&squares, &net).unwrap(), expected);
                    }
                    // Invalid sizes and empty inputs fail or return without communicating.
                    let net = CountingNetwork {
                        inner: net,
                        counts: Counts::default(),
                    };
                    assert!(
                        conversion::decompose_arithmetic_many(&shares, &net, &mut state, 70, 0)
                            .is_err()
                    );
                    assert!(
                        conversion::decompose_arithmetic_many(&shares, &net, &mut state, 255, 14)
                            .is_err()
                    );
                    let empty: &[Rep3PrimeFieldShare<F>] = &[];
                    assert!(
                        conversion::decompose_arithmetic_many(empty, &net, &mut state, 70, 14)
                            .unwrap()
                            .is_empty()
                    );
                    assert_eq!(net.snapshot()[0], 0);
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
    }
}

#[test]
fn decomposition_matches_fr_integer_reference() {
    exercise::<Fr>();
}

#[test]
fn decomposition_matches_fq_integer_reference() {
    exercise::<Fq>();
}

/// The bit-injection decomposition gives the same limbs as the garbled-circuit one, sends fewer
/// bytes and smaller messages, and one more message.
#[test]
fn decomposition_sends_fewer_bytes_than_garbled_circuit() {
    const N: usize = 64;
    let mut rng = StdRng::seed_from_u64(0xdec1);
    let values: Vec<Fr> = (0..N).map(|_| Fr::rand(&mut rng)).collect();
    let shares = share_field_elements(&values, &mut rng);
    let workers: Vec<_> = LocalNetwork::new_3_parties()
        .into_iter()
        .zip(shares)
        .map(|(inner, shares)| {
            std::thread::spawn(move || {
                let net = CountingNetwork {
                    inner,
                    counts: Counts::default(),
                };
                let mut state = Rep3State::new(&net, Default::default()).unwrap();
                let mut run = |gc: bool| {
                    let before = net.snapshot();
                    let limbs = if gc {
                        yao::decompose_arithmetic_many(&shares, &net, &mut state, 70, 14)
                    } else {
                        conversion::decompose_arithmetic_many(&shares, &net, &mut state, 70, 14)
                    }
                    .unwrap();
                    let after = net.snapshot();
                    let opened = arithmetic::open_vec(&limbs, &net).unwrap();
                    net.snapshot();
                    (
                        opened,
                        [after[0] - before[0], after[1] - before[1], after[2]],
                    )
                };
                (run(true), run(false))
            })
        })
        .collect();
    let results: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
    let mut gc_total = [0; 3];
    let mut total = [0; 3];
    for ((gc_limbs, gc), (limbs, counts)) in &results {
        assert_eq!(limbs, gc_limbs);
        for i in 0..2 {
            gc_total[i] += gc[i];
            total[i] += counts[i];
        }
        gc_total[2] = gc_total[2].max(gc[2]);
        total[2] = total[2].max(counts[2]);
    }
    let [gc_messages, gc_bytes, gc_max] = gc_total;
    let [messages, bytes, max] = total;
    assert!(
        bytes < gc_bytes,
        "{bytes} bytes, garbled circuit {gc_bytes}"
    );
    assert!(
        max < gc_max,
        "largest message {max} bytes, garbled circuit {gc_max}"
    );
    // One more message per party: the bit injection.
    assert_eq!(
        messages,
        gc_messages + 3,
        "{messages} messages, garbled circuit {gc_messages}"
    );
}

//! Tests of the SHA-256 sparse-trace circuit against a cleartext SHA-256 compression that records
//! the same values, and of its 3-party evaluation.
use super::GarbledCircuits;
use crate::protocols::rep3::{
    Rep3State, combine_field_elements,
    conversion::A2BType,
    share_field_elements, yao,
    yao::{
        GCUtils,
        cleartext_evaluator::{CleartextBinaryEvaluator, CleartextBit},
        fancy::BinaryBundle,
    },
};
use ark_ff::UniformRand;
use mpc_net::local::LocalNetwork;
use rand::{Rng, SeedableRng, rngs::StdRng};

type F = ark_bn254::Fr;

const ROUND_CONSTANTS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const INITIAL_STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

fn bit(x: u32, i: usize) -> u32 {
    (x >> i) & 1
}

/// Records the 32 bits of a read key.
fn push_word(trace: &mut Vec<bool>, x: u32) {
    trace.extend((0..32).map(|i| bit(x, i) == 1));
}

/// Records the digits of a normalization read and their table values; `digit` and `value` give
/// both for bit position k.
fn push_digits(
    trace: &mut Vec<bool>,
    digit_bits: usize,
    digit: impl Fn(usize) -> u32,
    value: impl Fn(usize) -> u32,
) {
    for k in 0..32 {
        let (d, v) = (digit(k), value(k));
        trace.extend((0..digit_bits).map(|i| bit(d, i) == 1));
        assert!(v <= 2);
        trace.push(v & 1 == 1);
        trace.push(v >> 1 == 1);
    }
}

/// SHA-256 compression of `state` and `message` in cleartext. Returns the new state and the
/// values the sparse-trace circuit outputs, recorded in the order of the gadget's reads.
fn compress(state: [u32; 8], message: [u32; 16]) -> ([u32; 8], Vec<bool>) {
    let mut trace = Vec::with_capacity(GarbledCircuits::SHA256_SPARSE_TRACE_BITS);
    for reg in [1, 2, 5, 6] {
        push_word(&mut trace, state[reg]);
    }

    let mut w = message.to_vec();
    let mut has_sparse_limbs = [false; 64];
    for i in 16..64 {
        for j in [i - 15, i - 2] {
            if !has_sparse_limbs[j] {
                push_word(&mut trace, w[j]);
                has_sparse_limbs[j] = true;
            }
        }
        let (l, r) = (w[i - 15], w[i - 2]);
        let shr = |x: u32, s: usize, k: usize| if k + s < 32 { bit(x, k + s) } else { 0 };
        let left = |k| bit(l, (k + 7) % 32) + bit(l, (k + 18) % 32) + shr(l, 3, k);
        let right = |k| bit(r, (k + 17) % 32) + bit(r, (k + 19) % 32) + shr(r, 10, k);
        let sigma0 = l.rotate_right(7) ^ l.rotate_right(18) ^ (l >> 3);
        let sigma1 = r.rotate_right(17) ^ r.rotate_right(19) ^ (r >> 10);
        push_digits(
            &mut trace,
            4,
            |k| right(k) + 4 * left(k),
            |k| bit(sigma0, k) + bit(sigma1, k),
        );
        w.push(
            sigma0
                .wrapping_add(sigma1)
                .wrapping_add(w[i - 16])
                .wrapping_add(w[i - 7]),
        );
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
    for (w_i, k_i) in w.iter().zip(ROUND_CONSTANTS) {
        push_word(&mut trace, e);
        let big_sigma1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let choose = (e & f) ^ (!e & g);
        push_digits(
            &mut trace,
            5,
            |k| {
                let rot = bit(e, (k + 6) % 32) + bit(e, (k + 11) % 32) + bit(e, (k + 25) % 32);
                bit(e, k) + 2 * bit(f, k) + 3 * bit(g, k) + 7 * rot
            },
            |k| bit(big_sigma1, k) + bit(choose, k),
        );

        push_word(&mut trace, a);
        let big_sigma0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        push_digits(
            &mut trace,
            4,
            |k| {
                let rot = bit(a, (k + 2) % 32) + bit(a, (k + 13) % 32) + bit(a, (k + 22) % 32);
                bit(a, k) + bit(b, k) + bit(c, k) + 4 * rot
            },
            |k| bit(big_sigma0, k) + bit(majority, k),
        );

        let temp1 = h
            .wrapping_add(big_sigma1)
            .wrapping_add(choose)
            .wrapping_add(k_i)
            .wrapping_add(*w_i);
        let temp2 = big_sigma0.wrapping_add(majority);
        (h, g, f, e, d, c, b, a) = (
            g,
            f,
            e,
            d.wrapping_add(temp1),
            c,
            b,
            a,
            temp1.wrapping_add(temp2),
        );
    }

    let new_state = [a, b, c, d, e, f, g, h];
    (
        std::array::from_fn(|i| state[i].wrapping_add(new_state[i])),
        trace,
    )
}

/// Evaluates the sparse-trace circuit in cleartext on the given summands of the 24 inputs and
/// returns its output bits and the number of AND gates.
fn evaluate(x1: &[F], x2: &[F]) -> (Vec<bool>, usize) {
    let encode = |xs: &[F]| {
        BinaryBundle::new(
            xs.iter()
                .flat_map(|x| GCUtils::field_to_bits(*x))
                .map(CleartextBit)
                .collect(),
        )
    };
    let mut evaluator = CleartextBinaryEvaluator::default();
    let output = GarbledCircuits::sha256_compression_sparse_trace::<_, F>(
        &mut evaluator,
        &encode(x1),
        &encode(x2),
    )
    .unwrap();
    (
        output.wires().iter().map(|bit| bit.0).collect(),
        evaluator.num_and_gates,
    )
}

fn inputs(state: [u32; 8], message: [u32; 16]) -> Vec<F> {
    state.iter().chain(&message).map(|x| F::from(*x)).collect()
}

/// The cleartext reference is SHA-256: one compression of the padded message "abc" from the
/// initial state gives its digest.
#[test]
fn reference_compression_is_sha256() {
    let mut message = [0; 16];
    message[0] = 0x61626380;
    message[15] = 0x18;
    let (digest, trace) = compress(INITIAL_STATE, message);
    assert_eq!(
        digest,
        [
            0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223, 0xb00361a3, 0x96177a9c, 0xb410ff61,
            0xf20015ad
        ]
    );
    assert_eq!(trace.len(), GarbledCircuits::SHA256_SPARSE_TRACE_BITS);
}

/// The circuit outputs the reference trace for edge and random inputs, with the inputs split
/// into two field summands in different ways, and its size does not depend on the inputs.
#[test]
fn sparse_trace_matches_cleartext_sha256() {
    let mut rng = StdRng::seed_from_u64(0x5348_4132_3536);
    let mut abc = [0; 16];
    abc[0] = 0x61626380;
    abc[15] = 0x18;
    let mut cases = vec![
        (INITIAL_STATE, abc),
        ([0; 8], [0; 16]),
        ([u32::MAX; 8], [u32::MAX; 16]),
    ];
    for _ in 0..8 {
        cases.push((rng.r#gen(), rng.r#gen()));
    }

    let mut and_gates = None;
    for (state, message) in cases {
        let (_, expected) = compress(state, message);
        let values = inputs(state, message);
        // One summand zero, a random split, and a split whose summands add up to more than p.
        let zero = vec![F::from(0u64); 24];
        let random = (0..24).map(|_| F::rand(&mut rng)).collect::<Vec<_>>();
        let minus_one = vec![-F::from(1u64); 24];
        for x1 in [zero, random, minus_one] {
            let x2 = values
                .iter()
                .zip(&x1)
                .map(|(v, x1)| *v - x1)
                .collect::<Vec<_>>();
            let (trace, num_and_gates) = evaluate(&x1, &x2);
            assert_eq!(trace.len(), expected.len());
            if let Some(i) = trace.iter().zip(&expected).position(|(a, b)| a != b) {
                panic!("output bit {i} differs for state {state:x?}, message {message:x?}");
            }
            assert_eq!(*and_gates.get_or_insert(num_and_gates), num_and_gates);
        }
    }
}

/// The 3-party evaluation (garbled circuit, conversion to binary and then arithmetic shares)
/// opens to the cleartext trace and yields consistent replicated shares.
#[test]
fn sparse_trace_kernel_opens_to_cleartext_trace() {
    let mut rng = StdRng::seed_from_u64(0x5348_4132_3537);
    let state: [u32; 8] = rng.r#gen();
    let message: [u32; 16] = rng.r#gen();
    let (_, expected) = compress(state, message);
    // The output spans several conversion chunks and ends in a partial one.
    let width = 256;
    assert_ne!(expected.len() % width, 0);

    let shares = share_field_elements(&inputs(state, message), &mut rng);
    let outputs = std::thread::scope(|s| {
        let threads = LocalNetwork::new_3_parties()
            .into_iter()
            .zip(shares)
            .map(|(net, inputs)| {
                s.spawn(move || {
                    let mut rep3_state = Rep3State::new(&net, A2BType::default()).unwrap();
                    yao::sha256_compression_sparse_trace(
                        &std::array::from_fn(|i| inputs[i]),
                        &std::array::from_fn(|i| inputs[8 + i]),
                        &net,
                        &mut rep3_state,
                    )
                    .unwrap()
                })
            })
            .collect::<Vec<_>>();
        threads
            .into_iter()
            .map(|t| t.join().unwrap())
            .collect::<Vec<_>>()
    });

    let opened = combine_field_elements(&outputs[0], &outputs[1], &outputs[2]);
    assert_eq!(opened.len(), expected.len());
    for (i, (opened, expected)) in opened.iter().zip(&expected).enumerate() {
        assert_eq!(*opened, F::from(*expected), "output bit {i}");
        for party in 0..3 {
            assert_eq!(outputs[party][i].a, outputs[(party + 1) % 3][i].b);
        }
    }
}

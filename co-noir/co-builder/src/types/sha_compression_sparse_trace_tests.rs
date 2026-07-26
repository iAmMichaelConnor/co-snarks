//! Referee tests (L0e unit U1) for `GarbledCircuits::sha256_block_sparse_trace` (mpc-core).
//!
//! The reference trace mirrors, read by read, the VALUE flow of `sha256_block` in the parent
//! module for the all-shared case (where every plookup read reaches the MPC driver): every read
//! key and every read value is computed with the REAL plain-path table machinery — the
//! `get_table_values` function pointers and column step sizes of the real multi-tables
//! (`Plookup::new`, plookup.rs), i.e. `BasicTableId::get_sparse_table_with_rotation_values` /
//! `get_sparse_normalization_values` (plookup.rs:269-303) — and the real rotation-multiplier
//! functions of the parent module. The only transcriptions from the gadget are its inline linear
//! recombination constants (cited per line below); the final compression state is additionally
//! cross-checked against the independent `sha2` crate, so a transcription error cannot pass
//! silently.
//!
//! Verified per input (>= 20 random + all-zero + all-ones):
//! - every one of the 42,016 circuit output bits equals the reference trace bit;
//! - carry-freeness: for every normalization read, the carry-generic base-B digit decomposition
//!   of the actual (field-accumulated) read key has <= 32 digits, each digit is within its table
//!   bound (28/16/16), and equals the linear-in-register-bits digit form the garbled circuit
//!   computes;
//! - the per-digit Moebius bits recombine to the exact normalized lookup VALUE the plain path
//!   emits (accumulator column C2[0]);
//! - rotation-read sparse accumulators equal `Utils::map_into_sparse_form` of the key.
//!
//! A separate test re-verifies the ChInput C3 row-coefficient linearity
//! (`get_choose_rotation_multipliers`) and its majority counterpart coefficient-by-coefficient.

use super::{get_choose_rotation_multipliers, get_majority_rotation_multipliers};
use crate::types::plookup::{BasicTableId, MultiTableId, Plookup, PlookupMultiTable};
use ark_bn254::Fr;
use ark_ff::{Field, One, Zero};
use co_noir_common::utils::Utils;
use mpc_core::protocols::rep3::yao::circuits::GarbledCircuits;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

type Bn254 = ark_bn254::G1Projective;

/// Copy of the gadget's round constants (sha_compression.rs:113-124); any transcription error is
/// caught by the sha2 cross-check of the final state.
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

fn fr_to_u64(x: &Fr) -> u64 {
    let b: BigUint = (*x).into();
    b.to_u64().expect("value fits into u64")
}

fn bit(x: u32, i: usize) -> u64 {
    ((x >> (i % 32)) & 1) as u64
}

/// Carry-generic key slicing; mirrors `Plookup::slice_input_using_variable_bases`
/// (plookup.rs:1282-1293) including the last-slice range assert.
fn slice_key(key: &BigUint, bases: &[u64]) -> Vec<u64> {
    let mut target = key.clone();
    let mut slices = Vec::with_capacity(bases.len());
    for (i, &base) in bases.iter().enumerate() {
        if i == bases.len() - 1 {
            assert!(
                target < BigUint::from(base),
                "last key slice greater than {base}"
            );
        }
        slices.push((&target % base).to_u64().expect("slice fits u64"));
        target /= base;
    }
    slices
}

/// Column accumulation exactly as `Plookup::get_lookup_accumulators` (plookup.rs:1844-1872).
fn accumulate(raw: &[Fr], step_sizes: &[Fr]) -> Vec<Fr> {
    let n = raw.len();
    let mut acc = vec![Fr::zero(); n];
    acc[n - 1] = raw[n - 1];
    for i in (1..n).rev() {
        acc[i - 1] = raw[i - 1] + step_sizes[i] * acc[i];
    }
    acc
}

struct RotationRead {
    /// C2 column accumulators (sparse forms); index 0 is the full sparse form of the key
    c2: Vec<Fr>,
    /// C3 column accumulators (rotated sparse forms)
    c3: Vec<Fr>,
}

/// Reference for one rotation-kind read (Sha256MajInput/ChInput/WitnessInput): computes the C2/C3
/// accumulators with the real table functions and pushes the expected circuit output (the 32 key
/// bits, LSB first).
fn rotation_read(
    mt: &PlookupMultiTable<Fr>,
    key: u32,
    expected_bits: &mut Vec<bool>,
) -> RotationRead {
    let slices = slice_key(&BigUint::from(key), &mt.slice_sizes);
    let mut c2_raw = Vec::with_capacity(slices.len());
    let mut c3_raw = Vec::with_capacity(slices.len());
    for (i, s) in slices.iter().enumerate() {
        let values = (mt.get_table_values[i])([*s, 0]);
        c2_raw.push(values[0]);
        c3_raw.push(values[1]);
    }
    let c2 = accumulate(&c2_raw, &mt.column_2_step_sizes);
    let c3 = accumulate(&c3_raw, &mt.column_3_step_sizes);
    for k in 0..32 {
        expected_bits.push(bit(key, k) == 1);
    }
    RotationRead { c2, c3 }
}

struct NormalizationSpec {
    /// base of the digits (28 for ChOutput, 16 for Maj/WitnessOutput) == the table bound
    base: u64,
    /// bits per digit group emitted by the circuit (5 for ChOutput, 4 otherwise)
    digit_bits: usize,
    /// the REAL per-digit normalization map (plookup.rs:287-324); on a single-digit key it
    /// returns exactly table[digit]
    table_fn: fn([u64; 2]) -> [Fr; 2],
}

/// Reference for one normalization-kind read: slices the key with the real machinery, asserts
/// carry-freeness (<= 32 digits, digit < base, digit == predicted linear form), pushes the
/// expected circuit output bits ([digit bits, f1, f2] per digit) and returns the normalized
/// value (C2 accumulator index 0), asserting it equals the recombination of the emitted bits.
fn normalization_read(
    mt: &PlookupMultiTable<Fr>,
    key: &Fr,
    spec: &NormalizationSpec,
    predicted_digits: &[u64; 32],
    expected_bits: &mut Vec<bool>,
) -> Fr {
    let key: BigUint = (*key).into();
    // real plain-path values: per-slice normalization via the multi-table function pointers
    let slices = slice_key(&key, &mt.slice_sizes);
    let c2_raw: Vec<Fr> = slices
        .iter()
        .enumerate()
        .map(|(i, s)| (mt.get_table_values[i])([*s, 0])[0])
        .collect();
    let c2 = accumulate(&c2_raw, &mt.column_2_step_sizes);

    // carry-generic digit decomposition of the accumulated key (referee for §2 carry-freeness)
    let mut digits = Vec::new();
    let mut rem = key;
    while !rem.is_zero() {
        digits.push((&rem % spec.base).to_u64().expect("digit fits u64"));
        rem /= spec.base;
    }
    assert!(
        digits.len() <= 32,
        "normalization key has more than 32 base-{} digits: carry-freeness violated",
        spec.base
    );
    digits.resize(32, 0);

    let mut value_from_bits = 0u64;
    for (k, &d) in digits.iter().enumerate() {
        assert!(
            predicted_digits[k] < spec.base,
            "digit {k}: linear form {} exceeds table bound {}",
            predicted_digits[k],
            spec.base
        );
        assert_eq!(
            d, predicted_digits[k],
            "digit {k}: carry-generic accumulation disagrees with the linear-in-key-bits form"
        );
        for t in 0..spec.digit_bits {
            expected_bits.push((d >> t) & 1 == 1);
        }
        let table_value = fr_to_u64(&(spec.table_fn)([d, 0])[0]);
        assert!(table_value <= 2, "normalization table values are 2 bits");
        expected_bits.push(table_value & 1 == 1);
        expected_bits.push(table_value >> 1 == 1);
        value_from_bits += table_value << k;
    }
    // the Moebius bits must recombine to the exact lookup VALUE the plain path emits
    assert_eq!(
        Fr::from(value_from_bits),
        c2[0],
        "per-digit Moebius bits do not recombine to the plain normalized value"
    );
    c2[0]
}

/// Computes the full expected output-bit trace of the garbled circuit for one compression,
/// mirroring `sha256_block`'s read order and value flow (all-shared case) with the real
/// plain-path table machinery. Also cross-checks the final compression state against `sha2`.
fn reference_trace(h_init: [u32; 8], w_in: [u32; 16]) -> Vec<bool> {
    let plookup = Plookup::<Fr>::new::<Bn254>();
    let maj_in = plookup.get_multitable(MultiTableId::Sha256MajInput);
    let ch_in = plookup.get_multitable(MultiTableId::Sha256ChInput);
    let wit_in = plookup.get_multitable(MultiTableId::Sha256WitnessInput);
    let maj_out = plookup.get_multitable(MultiTableId::Sha256MajOutput);
    let ch_out = plookup.get_multitable(MultiTableId::Sha256ChOutput);
    let wit_out = plookup.get_multitable(MultiTableId::Sha256WitnessOutput);

    let choose_spec = NormalizationSpec {
        base: 28,
        digit_bits: 5,
        table_fn: BasicTableId::get_sparse_normalization_values_choose::<Fr, 28>,
    };
    let majority_spec = NormalizationSpec {
        base: 16,
        digit_bits: 4,
        table_fn: BasicTableId::get_sparse_normalization_values_maj::<Fr, 16>,
    };
    let witness_spec = NormalizationSpec {
        base: 16,
        digit_bits: 4,
        table_fn: BasicTableId::get_sparse_normalization_values_wtns::<Fr, 16>,
    };

    let mut bits = Vec::new();

    // --- init sparse-form reads (sha_compression.rs:132-139) ---
    let b_read = rotation_read(maj_in, h_init[1], &mut bits);
    let c_read = rotation_read(maj_in, h_init[2], &mut bits);
    let f_read = rotation_read(ch_in, h_init[5], &mut bits);
    let g_read = rotation_read(ch_in, h_init[6], &mut bits);
    // cross-check the accumulator machinery against the independent sparse-form map
    assert_eq!(
        b_read.c2[0],
        Fr::from(Utils::map_into_sparse_form::<16>(h_init[1] as u64))
    );
    assert_eq!(
        f_read.c2[0],
        Fr::from(Utils::map_into_sparse_form::<28>(h_init[5] as u64))
    );
    let mut b_sparse = b_read.c2[0];
    let mut c_sparse = c_read.c2[0];
    let mut f_sparse = f_read.c2[0];
    let mut g_sparse = g_read.c2[0];
    // a.sparse/e.sparse are written by the first majority()/choose() before any use
    let mut a_sparse;
    let mut e_sparse;

    let [mut a_n, mut b_n, mut c_n, mut d_n, mut e_n, mut f_n, mut g_n, mut h_n] = h_init;

    // --- extend_witness (sha_compression.rs:185-358) ---
    let mut w = [0u32; 64];
    w[..16].copy_from_slice(&w_in);
    // sparse_limbs/rotated_limbs (C2/C3 accumulators) of converted words, lazily filled
    let mut limbs: [Option<RotationRead>; 64] = std::array::from_fn(|_| None);
    for i in 16..64 {
        for j in [i - 15, i - 2] {
            if limbs[j].is_none() {
                limbs[j] = Some(rotation_read(wit_in, w[j], &mut bits));
            }
        }
        // linear recombination constants transcribed from sha_compression.rs:210-223
        let base = Fr::from(16u64);
        let pw = |e: u64| base.pow([e]);
        let left_multipliers = [
            pw(32 - 7) + pw(32 - 18),
            pw(32 - 18 + 3) + Fr::one(),
            pw(32 - 18 + 10) + pw(10 - 7) + pw(10 - 3),
            pw(18 - 7) + pw(18 - 3) + Fr::one(),
        ];
        let right_multipliers = [
            pw(32 - 17) + pw(32 - 19),
            pw(32 - 17 + 3) + pw(32 - 19 + 3),
            pw(32 - 19 + 10) + Fr::one(),
            pw(18 - 17) + pw(18 - 10),
        ];
        let left_limbs = limbs[i - 15].as_ref().unwrap();
        let right_limbs = limbs[i - 2].as_ref().unwrap();
        // sha_compression.rs:225-293: left/right sparse xor sums and the WitnessOutput key
        let mut left_sum = left_limbs.c3[1];
        for (limb, mult) in left_limbs.c2.iter().zip(left_multipliers.iter()) {
            left_sum += *limb * mult;
        }
        let left_xor_sparse = left_sum * Fr::from(4u64);
        let mut right_sum = right_limbs.c3[2] + right_limbs.c3[3];
        for (limb, mult) in right_limbs.c2.iter().zip(right_multipliers.iter()) {
            right_sum += *limb * mult;
        }
        let xor_key = right_sum + left_xor_sparse;

        // digit prediction: base-16 digit k = sigma1_popcount + 4 * sigma0_popcount (§2)
        let (wl, wr) = (w[i - 15], w[i - 2]);
        let predicted: [u64; 32] = std::array::from_fn(|k| {
            let left = bit(wl, k + 7)
                + bit(wl, k + 18)
                + if k + 3 < 32 { bit(wl, k + 3) } else { 0 };
            let right = bit(wr, k + 17)
                + bit(wr, k + 19)
                + if k + 10 < 32 { bit(wr, k + 10) } else { 0 };
            right + 4 * left
        });
        let xor_result = normalization_read(wit_out, &xor_key, &witness_spec, &predicted, &mut bits);

        // sha_compression.rs:304-333: w_out = (xor_result + w[i-16] + w[i-7]) & (2^32 - 1)
        let w_out_raw = fr_to_u64(&xor_result) + w[i - 16] as u64 + w[i - 7] as u64;
        w[i] = (w_out_raw & 0xFFFF_FFFF) as u32;
        // divisor <= 3 (sha_compression.rs:330-331)
        assert!(w_out_raw >> 32 <= 3);
    }

    // --- round loop (sha_compression.rs:144-158) ---
    let rc_ch: [Fr; 3] = get_choose_rotation_multipliers();
    let rc_maj: [Fr; 3] = get_majority_rotation_multipliers();
    let seven = Fr::from(7u64);
    let four = Fr::from(4u64);
    for i in 0..64 {
        // choose (sha_compression.rs:360-422)
        let e_read = rotation_read(ch_in, e_n, &mut bits);
        e_sparse = e_read.c2[0];
        assert_eq!(
            e_sparse,
            Fr::from(Utils::map_into_sparse_form::<28>(e_n as u64))
        );
        let xor_result = e_read.c3[0] * seven
            + e_sparse * (rc_ch[0] * seven + Fr::one())
            + e_read.c2[2] * (rc_ch[2] * seven);
        let ch_key = xor_result + f_sparse + f_sparse + g_sparse + g_sparse + g_sparse;
        let predicted: [u64; 32] = std::array::from_fn(|k| {
            bit(e_n, k)
                + 2 * bit(f_n, k)
                + 3 * bit(g_n, k)
                + 7 * (bit(e_n, k + 6) + bit(e_n, k + 11) + bit(e_n, k + 25))
        });
        let ch_value = normalization_read(ch_out, &ch_key, &choose_spec, &predicted, &mut bits);

        // majority (sha_compression.rs:424-478)
        let a_read = rotation_read(maj_in, a_n, &mut bits);
        a_sparse = a_read.c2[0];
        assert_eq!(
            a_sparse,
            Fr::from(Utils::map_into_sparse_form::<16>(a_n as u64))
        );
        let xor_result = a_read.c3[0] * four
            + a_sparse * (rc_maj[0] * four + Fr::one())
            + a_read.c2[1] * (rc_maj[1] * four);
        let maj_key = xor_result + b_sparse + c_sparse;
        let predicted: [u64; 32] = std::array::from_fn(|k| {
            bit(a_n, k)
                + bit(b_n, k)
                + bit(c_n, k)
                + 4 * (bit(a_n, k + 2) + bit(a_n, k + 13) + bit(a_n, k + 22))
        });
        let maj_value = normalization_read(maj_out, &maj_key, &majority_spec, &predicted, &mut bits);

        // temp1 and the register shift (sha_compression.rs:147-157); add_normalize_unsafe
        // reduces mod 2^32 (field_ct.rs:1944-1993)
        let temp1 =
            fr_to_u64(&ch_value) + h_n as u64 + w[i] as u64 + ROUND_CONSTANTS[i] as u64;
        let e_new = ((d_n as u64 + temp1) & 0xFFFF_FFFF) as u32;
        let a_new = ((temp1 + fr_to_u64(&maj_value)) & 0xFFFF_FFFF) as u32;
        h_n = g_n;
        g_n = f_n;
        g_sparse = f_sparse;
        f_n = e_n;
        f_sparse = e_sparse;
        e_n = e_new;
        d_n = c_n;
        c_n = b_n;
        c_sparse = b_sparse;
        b_n = a_n;
        b_sparse = a_sparse;
        a_n = a_new;
    }

    // final-state cross-check against an independent sha256 implementation
    let mut state = h_init;
    let mut block = [0u8; 64];
    for (i, word) in w_in.iter().enumerate() {
        block[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    sha2::compress256(&mut state, &[block.into()]);
    let ours = [a_n, b_n, c_n, d_n, e_n, f_n, g_n, h_n];
    for i in 0..8 {
        assert_eq!(
            ((h_init[i] as u64 + ours[i] as u64) & 0xFFFF_FFFF) as u32,
            state[i],
            "reference flow diverged from sha2 at output word {i}"
        );
    }

    assert_eq!(
        bits.len(),
        GarbledCircuits::SHA256_BLOCK_SPARSE_TRACE_OUTPUT_BITS
    );
    bits
}

/// Runs the garbled circuit (cleartext evaluation) against the reference trace for one input and
/// returns the measured AND-gate count of the composed circuit.
fn run_case(h_init: [u32; 8], w_in: [u32; 16], rng: &mut ChaCha12Rng) -> usize {
    use ark_ff::UniformRand;
    let expected = reference_trace(h_init, w_in);

    // random share split of each input: x1 + x2 = value mod p (exercises the mod-p input adders)
    let mut values = [0u32; 24];
    values[..8].copy_from_slice(&h_init);
    values[8..].copy_from_slice(&w_in);
    let x1: Vec<Fr> = (0..24).map(|_| Fr::rand(rng)).collect();
    let x2: Vec<Fr> = values
        .iter()
        .zip(x1.iter())
        .map(|(v, x1)| Fr::from(*v) - x1)
        .collect();

    let (bits, num_and_gates) =
        GarbledCircuits::sha256_block_sparse_trace_cleartext::<Fr>(&x1, &x2)
            .expect("cleartext evaluation works");

    assert_eq!(bits.len(), expected.len());
    if let Some(first_mismatch) = bits.iter().zip(expected.iter()).position(|(a, b)| a != b) {
        // locate the read this bit belongs to, for diagnostics
        let mut layout: Vec<(String, usize)> = Vec::new();
        for label in ["init MajInput(h1)", "init MajInput(h2)", "init ChInput(h5)", "init ChInput(h6)"] {
            layout.push((label.to_string(), 32));
        }
        let mut converted = [false; 64];
        for i in 16..64 {
            for j in [i - 15, i - 2] {
                if !converted[j] {
                    layout.push((format!("WitnessInput(w[{j}]) at i={i}"), 32));
                    converted[j] = true;
                }
            }
            layout.push((format!("WitnessOutput at i={i}"), 192));
        }
        for i in 0..64 {
            layout.push((format!("ChInput(e) round {i}"), 32));
            layout.push((format!("ChOutput round {i}"), 224));
            layout.push((format!("MajInput(a) round {i}"), 32));
            layout.push((format!("MajOutput round {i}"), 192));
        }
        let mut offset = 0;
        let mut located = String::new();
        for (label, len) in layout {
            if first_mismatch < offset + len {
                let got: Vec<u8> = bits[offset..offset + len].iter().map(|b| *b as u8).collect();
                let want: Vec<u8> =
                    expected[offset..offset + len].iter().map(|b| *b as u8).collect();
                located = format!(
                    "read '{label}' (offset {offset}, len {len})\n got  {got:?}\n want {want:?}"
                );
                break;
            }
            offset += len;
        }
        panic!(
            "sparse-trace output bit {first_mismatch} (of {}) differs from the plain reference \
             for h_init={h_init:08x?}, w_in={w_in:08x?}\n{located}",
            bits.len()
        );
    }
    num_and_gates
}

/// U1 main referee: every output bit of the one-shot sparse-trace circuit equals the plain-path
/// reference for >= 20 random inputs plus the all-zero and all-ones edge inputs; carry-freeness
/// and value recombination are asserted inside. Also pins the measured AND-gate count.
#[test]
fn sha256_block_sparse_trace_matches_plain_reference() {
    let mut rng = ChaCha12Rng::seed_from_u64(0x5AC0_FFEE_u64);

    let mut and_counts = Vec::new();
    // edge inputs
    and_counts.push(run_case([0u32; 8], [0u32; 16], &mut rng));
    and_counts.push(run_case([u32::MAX; 8], [u32::MAX; 16], &mut rng));
    // random inputs
    for _ in 0..20 {
        let h_init: [u32; 8] = std::array::from_fn(|_| rng.r#gen());
        let w_in: [u32; 16] = std::array::from_fn(|_| rng.r#gen());
        and_counts.push(run_case(h_init, w_in, &mut rng));
    }

    // The circuit is data-independent: the AND count must not vary with the input.
    assert!(and_counts.windows(2).all(|w| w[0] == w[1]));
    // Measured cost of the composed circuit (design L0e §3.1 predicted 130k-200k AND). Pinned as
    // a fence: update consciously when the circuit changes.
    println!(
        "sha256_block_sparse_trace: {} AND gates (42,016 output bits)",
        and_counts[0]
    );
    assert_eq!(and_counts[0], 92_941, "AND-gate count fence moved");
}

/// §7.2 referee: re-verifies coefficient-by-coefficient that the gadget's C3-based xor_result
/// recombinations are linear in the 32 key bits with exactly the rotation coefficients the
/// sparse-trace circuit assumes.
///
/// choose (sha_compression.rs:379-403 with `get_choose_rotation_multipliers`, :511-555):
///   xor_result(e) == sum_k e_k * (28^k + 7 * (28^((k-6) mod 32) + 28^((k-11) mod 32)
///                    + 28^((k-25) mod 32)))
/// majority (sha_compression.rs:443-466 with `get_majority_rotation_multipliers`, :557-593):
///   xor_result(a) == sum_k a_k * (16^k + 4 * (16^((k-2) mod 32) + 16^((k-13) mod 32)
///                    + 16^((k-22) mod 32)))
#[test]
fn choose_and_majority_rotation_recombination_linear_in_key_bits() {
    let plookup = Plookup::<Fr>::new::<Bn254>();
    let ch_in = plookup.get_multitable(MultiTableId::Sha256ChInput);
    let maj_in = plookup.get_multitable(MultiTableId::Sha256MajInput);
    let rc_ch: [Fr; 3] = get_choose_rotation_multipliers();
    let rc_maj: [Fr; 3] = get_majority_rotation_multipliers();
    let seven = Fr::from(7u64);
    let four = Fr::from(4u64);

    let choose_xor_of = |key: u32| -> Fr {
        let mut sink = Vec::new();
        let read = rotation_read(ch_in, key, &mut sink);
        read.c3[0] * seven
            + read.c2[0] * (rc_ch[0] * seven + Fr::one())
            + read.c2[2] * (rc_ch[2] * seven)
    };
    let majority_xor_of = |key: u32| -> Fr {
        let mut sink = Vec::new();
        let read = rotation_read(maj_in, key, &mut sink);
        read.c3[0] * four
            + read.c2[0] * (rc_maj[0] * four + Fr::one())
            + read.c2[1] * (rc_maj[1] * four)
    };

    assert_eq!(choose_xor_of(0), Fr::zero());
    assert_eq!(majority_xor_of(0), Fr::zero());

    let pow = |base: u64, e: usize| Fr::from(base).pow([e as u64]);
    let mut choose_basis = [Fr::zero(); 32];
    let mut majority_basis = [Fr::zero(); 32];
    for k in 0..32 {
        // coefficient-by-coefficient: evaluate on the basis vector e = 1 << k
        choose_basis[k] = choose_xor_of(1u32 << k);
        let expected = pow(28, k)
            + seven
                * (pow(28, (k + 32 - 6) % 32) + pow(28, (k + 32 - 11) % 32)
                    + pow(28, (k + 32 - 25) % 32));
        assert_eq!(
            choose_basis[k], expected,
            "ChInput C3 recombination: coefficient of key bit {k} is not the claimed linear form"
        );

        majority_basis[k] = majority_xor_of(1u32 << k);
        let expected = pow(16, k)
            + four
                * (pow(16, (k + 32 - 2) % 32) + pow(16, (k + 32 - 13) % 32)
                    + pow(16, (k + 32 - 22) % 32));
        assert_eq!(
            majority_basis[k], expected,
            "MajInput C3 recombination: coefficient of key bit {k} is not the claimed linear form"
        );
    }

    // linearity on random keys: f(x) == sum over set bits of the basis coefficients
    let mut rng = ChaCha12Rng::seed_from_u64(0xC3_11EA_u64);
    for _ in 0..100 {
        let key: u32 = rng.r#gen();
        let mut expected_ch = Fr::zero();
        let mut expected_maj = Fr::zero();
        for k in 0..32 {
            if (key >> k) & 1 == 1 {
                expected_ch += choose_basis[k];
                expected_maj += majority_basis[k];
            }
        }
        assert_eq!(choose_xor_of(key), expected_ch);
        assert_eq!(majority_xor_of(key), expected_maj);
    }
}

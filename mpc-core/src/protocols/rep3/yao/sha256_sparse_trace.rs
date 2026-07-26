//! SHA256 sparse-trace kernel (3-party REP3 network layer around
//! [`GarbledCircuits::sha256_block_sparse_trace`]).
//!
//! One invocation of [`sha256_block_sparse_trace_kernel`] per sha256 compression call replaces
//! the 369 per-read garbled-circuit invocations the builder's sha gadget
//! (co-builder `sha_compression.rs::sha256_block`) issues today: the circuit computes the bits
//! underlying ALL of the gadget's plookup reads in one shot, the output leaves the garbled
//! domain as wire-label bits (binary sharing, [`y2b_many`]), and a single
//! [`bit_inject_from_bits_to_field_many`] round converts every bit to an arithmetic share.
//! Every witness value the gadget needs is then a LOCAL public-weight linear combination of
//! those bit shares; [`sha256_block_sparse_trace_recombine_reads`] performs exactly those
//! recombinations and yields, for each of the 369 reads in the gadget's read order, the same
//! `(values, key_a_slices, key_b_slices)` tuples the per-read driver kernels
//! ([`super::get_sparse_table_with_rotation_values_many`] /
//! [`super::get_sparse_normalization_values_many`] plus the co-acvm driver's public-base-power
//! post-processing) produce today.
//!
//! Share-level conventions (value-identical to today's path, share-randomness differs):
//! - `key_b` of every sha read is the constant 0; its slices are returned as trivial
//!   ZERO shares (both summands zero) rather than freshly masked zero shares.
//! - The 33rd base-16 digit of a Maj/WitnessOutput read (digit index 32 of key slice 10) is
//!   structurally zero and is folded in as the constant 0.
//!
//! [`y2b_many`]: crate::protocols::rep3::conversion::y2b_many
//! [`bit_inject_from_bits_to_field_many`]: crate::protocols::rep3_ring::conversion::bit_inject_from_bits_to_field_many

use ark_ff::PrimeField;
use itertools::izip;
use mpc_net::Network;

use super::circuits::GarbledCircuits;
use super::decompose_circuit_compose_blueprint_to_binary;
use crate::protocols::rep3::{Rep3BigUintShare, Rep3PrimeFieldShare, Rep3State, arithmetic};
use crate::protocols::rep3_ring::{Rep3RingShare, conversion as ring_conversion, ring::bit::Bit};

/// The six sha256 plookup multi-tables served by the sparse-trace kernel, with the public
/// parameters of both the plain path (slice sizes, sparse base, rotations; co-builder
/// plookup.rs:707-920) and the per-read driver kernels (plookup.rs:1476-1592).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sha256SparseTraceTable {
    /// Sha256MajInput: rotation table, base 16, slices `2^11, 2^11, 2^10`, rotations `[2, 2, 0]`
    MajInput,
    /// Sha256ChInput: rotation table, base 28, slices `2^11, 2^11, 2^10`, rotations `[6, 0, 3]`
    ChInput,
    /// Sha256WitnessInput: rotation table, base 16, slices `2^3, 2^7, 2^8, 2^18`,
    /// rotations `[0, 4, 7, 1]`
    WitnessInput,
    /// Sha256MajOutput: normalization table, digit base 16, 11 slices of `16^3`
    MajOutput,
    /// Sha256ChOutput: normalization table, digit base 28, 16 slices of `28^2`
    ChOutput,
    /// Sha256WitnessOutput: normalization table, digit base 16, 11 slices of `16^3`
    WitnessOutput,
}

impl Sha256SparseTraceTable {
    /// Whether this is a rotation-kind read (32 key bits in the trace) as opposed to a
    /// normalization-kind read (per-digit groups in the trace).
    pub fn is_rotation(self) -> bool {
        matches!(self, Self::MajInput | Self::ChInput | Self::WitnessInput)
    }

    /// The sparse base: base of the sparse form for rotation tables, base of the key digits for
    /// normalization tables.
    pub fn base(self) -> u64 {
        match self {
            Self::ChInput | Self::ChOutput => 28,
            _ => 16,
        }
    }

    /// Number of bits this read occupies in the sparse-trace output
    /// (see [`GarbledCircuits::sha256_block_sparse_trace`]'s layout doc).
    pub fn trace_bits(self) -> usize {
        match self {
            Self::MajInput | Self::ChInput | Self::WitnessInput => 32,
            // 32 digit groups of [digit bits, f1, f2]
            Self::ChOutput => 32 * (5 + 2),
            Self::MajOutput | Self::WitnessOutput => 32 * (4 + 2),
        }
    }

    /// Rotation tables: bit widths of the key slices (log2 of the plain slice sizes).
    ///
    /// # Panics
    /// Panics for normalization tables.
    pub fn slice_bit_sizes(self) -> &'static [usize] {
        match self {
            Self::MajInput | Self::ChInput => &[11, 11, 10],
            Self::WitnessInput => &[3, 7, 8, 18],
            _ => panic!("slice_bit_sizes is only defined for rotation tables"),
        }
    }

    /// Rotation tables: per-slice rotation amounts (over u32).
    ///
    /// # Panics
    /// Panics for normalization tables.
    pub fn rotations(self) -> &'static [u32] {
        match self {
            Self::MajInput => &[2, 2, 0],
            Self::ChInput => &[6, 0, 3],
            Self::WitnessInput => &[0, 4, 7, 1],
            _ => panic!("rotations is only defined for rotation tables"),
        }
    }

    /// Normalization tables: number of bits per digit in the trace (5 for base 28, 4 for
    /// base 16).
    ///
    /// # Panics
    /// Panics for rotation tables.
    pub fn digit_bits(self) -> usize {
        match self {
            Self::ChOutput => 5,
            Self::MajOutput | Self::WitnessOutput => 4,
            _ => panic!("digit_bits is only defined for normalization tables"),
        }
    }

    /// Normalization tables: number of key digits per slice (`28^2` -> 2, `16^3` -> 3).
    ///
    /// # Panics
    /// Panics for rotation tables.
    pub fn digits_per_slice(self) -> usize {
        match self {
            Self::ChOutput => 2,
            Self::MajOutput | Self::WitnessOutput => 3,
            _ => panic!("digits_per_slice is only defined for normalization tables"),
        }
    }

    /// Number of slices (= lookup rows) of the read.
    pub fn num_slices(self) -> usize {
        match self {
            Self::MajInput | Self::ChInput => 3,
            Self::WitnessInput => 4,
            Self::MajOutput | Self::WitnessOutput => 11,
            Self::ChOutput => 16,
        }
    }

    /// The `slice_sizes`/`base_bits` argument the driver passes to the per-read kernels
    /// (co-builder plookup.rs:1476-1592: the multi-table's `slice_sizes`).
    pub fn driver_slice_sizes(self) -> Vec<u64> {
        match self {
            Self::MajInput | Self::ChInput => vec![1 << 11, 1 << 11, 1 << 10],
            Self::WitnessInput => vec![1 << 3, 1 << 7, 1 << 8, 1 << 18],
            Self::MajOutput | Self::WitnessOutput => vec![16u64.pow(3); 11],
            Self::ChOutput => vec![28u64.pow(2); 16],
        }
    }

    /// The `total_bitsize` argument the driver passes to the per-read kernels
    /// (co-builder plookup.rs:1476-1592: `max(ilog2(next_pow2(slice)) * slices, 64)` for
    /// rotation reads, `ilog2(next_pow2(slice)) * slices` for normalization reads).
    pub fn driver_total_bitsize(self) -> usize {
        match self {
            Self::MajInput | Self::ChInput | Self::WitnessInput => 64,
            Self::MajOutput | Self::WitnessOutput => 12 * 11,
            Self::ChOutput => 10 * 16,
        }
    }
}

/// One derived sha256 plookup read: arithmetic shares of exactly the values the per-read driver
/// kernels return today (after the driver's public-base-power post-processing), in the same
/// order.
#[derive(Debug, Clone)]
pub enum Sha256SparseTraceRead<F: PrimeField> {
    /// A rotation-kind read (MajInput/ChInput/WitnessInput). Fields correspond 1:1 to the
    /// 4-tuple of the driver's `slice_and_get_sparse_table_with_rotation_values`.
    Rotation {
        /// Which multi-table this read belongs to
        table: Sha256SparseTraceTable,
        /// Per slice: the sparse form `sum_j slice_bit_j * BASE^j` of the key slice (driver
        /// tuple element 0)
        sparse: Vec<Rep3PrimeFieldShare<F>>,
        /// Per slice: the sparse form of the slice value rotated right (as u32) by the table's
        /// rotation amount (driver tuple element 1)
        rotated_sparse: Vec<Rep3PrimeFieldShare<F>>,
        /// Per slice: the key slice value itself (driver tuple element 2)
        key_a_slices: Vec<Rep3PrimeFieldShare<F>>,
        /// Per slice: slice of key_b = 0, as trivial zero shares (driver tuple element 3)
        key_b_slices: Vec<Rep3PrimeFieldShare<F>>,
    },
    /// A normalization-kind read (MajOutput/ChOutput/WitnessOutput). Fields correspond 1:1 to
    /// the 3-tuple of the driver's `slice_and_get_sparse_normalization_values`.
    Normalization {
        /// Which multi-table this read belongs to
        table: Sha256SparseTraceTable,
        /// Per slice: the normalized value `sum_j table[digit_j] * 2^j` over the slice's digits
        /// (driver tuple element 0)
        values: Vec<Rep3PrimeFieldShare<F>>,
        /// Per slice: the key slice value `sum_j digit_j * BASE^j` (driver tuple element 1)
        key_a_slices: Vec<Rep3PrimeFieldShare<F>>,
        /// Per slice: slice of key_b = 0, as trivial zero shares (driver tuple element 2)
        key_b_slices: Vec<Rep3PrimeFieldShare<F>>,
    },
}

/// The gadget's read schedule: the 369 plookup reads of one all-shared sha256 compression call
/// in the exact order `sha256_block` performs them, each with its bit offset into the
/// sparse-trace output (see [`GarbledCircuits::sha256_block_sparse_trace`]'s layout doc):
///
/// 1. 4 init reads: MajInput(h1), MajInput(h2), ChInput(h5), ChInput(h6);
/// 2. per schedule iteration i = 16..64: the lazy WitnessInput conversion reads (w\[i-15\]
///    before w\[i-2\], each only on first use; 61 total), then the WitnessOutput read;
/// 3. per round 0..64: ChInput(e), ChOutput, MajInput(a), MajOutput.
pub fn sha256_block_sparse_trace_read_schedule() -> Vec<(Sha256SparseTraceTable, usize)> {
    use Sha256SparseTraceTable::*;
    let mut schedule = Vec::with_capacity(369);
    let mut offset = 0;
    let mut push = |schedule: &mut Vec<(Sha256SparseTraceTable, usize)>,
                    table: Sha256SparseTraceTable| {
        schedule.push((table, offset));
        offset += table.trace_bits();
    };

    // 1. init sparse-form reads (sha_compression.rs:132-139)
    for table in [MajInput, MajInput, ChInput, ChInput] {
        push(&mut schedule, table);
    }
    // 2. message schedule (extend_witness) with lazy conversion reads
    let mut converted = [false; 64];
    for i in 16..64 {
        for j in [i - 15, i - 2] {
            if !converted[j] {
                push(&mut schedule, WitnessInput);
                converted[j] = true;
            }
        }
        push(&mut schedule, WitnessOutput);
    }
    // 3. round loop
    for _ in 0..64 {
        push(&mut schedule, ChInput);
        push(&mut schedule, ChOutput);
        push(&mut schedule, MajInput);
        push(&mut schedule, MajOutput);
    }

    debug_assert_eq!(schedule.len(), 369);
    debug_assert_eq!(
        schedule.last().map(|(t, o)| o + t.trace_bits()),
        Some(GarbledCircuits::SHA256_BLOCK_SPARSE_TRACE_OUTPUT_BITS)
    );
    schedule
}

/// Runs the one-shot sparse-trace garbled circuit for one sha256 compression call and returns
/// arithmetic shares of all [`GarbledCircuits::SHA256_BLOCK_SPARSE_TRACE_OUTPUT_BITS`] = 42,016
/// output bits, in the circuit's documented output order (each share opens to 0 or 1).
///
/// Inputs are the 24 gadget inputs `h_init[0..8] || w_in[0..16]` as arithmetic shares; each is
/// taken mod 2^32 inside the circuit.
///
/// Protocol (design L0e §3.2), ~4 logical rounds total:
/// 1. ONE merged input round: [`super::joint_input_arithmetic_added_many`] (24 field inputs);
/// 2. the garbled circuit (92,941 AND gates measured in U1): tables ID1 -> ID0, SHA3-256 digest
///    ID2 -> ID0;
/// 3. outputs leave as wire-label bits via `y2b_many` (one ID0 -> ID2 message);
/// 4. ONE `bit_inject_from_bits_to_field_many` ring round converts all bits to arithmetic
///    shares.
///
/// There are NO x23 output-resharing values and no per-output 254-bit masked recomposition —
/// that is the entire point of the binary-output blueprint.
///
/// RNG-stream draw order (all draws are local to this kernel; it is not called by any
/// production path yet, so no existing stream sequence changes):
/// 1. `rngs.generate_random_garbler_delta` (ID1/ID2),
/// 2. `state.rng` wire-label encodes in the joint input round (ID1/ID2),
/// 3. `rngs.generate_garbler_randomness` (garbler seed, ID1/ID2),
/// 4. `rngs.rand.random_biguint_rng1`/`random_biguint_rng2` in `y2b_many` (ID0/ID1),
/// 5. `rngs.rand.masking_field_element` per output bit in
///    `bit_inject_from_bits_to_field_many` (all parties).
pub fn sha256_block_sparse_trace_kernel<F: PrimeField, N: Network>(
    h_init: &[Rep3PrimeFieldShare<F>; 8],
    w_in: &[Rep3PrimeFieldShare<F>; 16],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    let mut combined_inputs = Vec::with_capacity(h_init.len() + w_in.len());
    combined_inputs.extend_from_slice(h_init);
    combined_inputs.extend_from_slice(w_in);

    let binary: Rep3BigUintShare<F> = decompose_circuit_compose_blueprint_to_binary!(
        &combined_inputs,
        net,
        state,
        GarbledCircuits::sha256_block_sparse_trace::<_, F>,
        ()
    )?;

    let num_bits = GarbledCircuits::SHA256_BLOCK_SPARSE_TRACE_OUTPUT_BITS;
    let mut bit_shares = Vec::with_capacity(num_bits);
    for i in 0..num_bits as u64 {
        bit_shares.push(Rep3RingShare::new(
            Bit::new(binary.a.bit(i)),
            Bit::new(binary.b.bit(i)),
        ));
    }
    ring_conversion::bit_inject_from_bits_to_field_many::<F, _>(&bit_shares, net, state)
}

/// Recombines the arithmetic bit shares returned by [`sha256_block_sparse_trace_kernel`] into
/// the 369 per-read `(values, key_a_slices, key_b_slices)` tuples of the compression call, in
/// the gadget's read order (see [`sha256_block_sparse_trace_read_schedule`]).
///
/// Purely LOCAL: every returned share is a public-weight linear combination of the input bit
/// shares (plus trivial zero shares for the key_b slices) — no communication.
pub fn sha256_block_sparse_trace_recombine_reads<F: PrimeField>(
    bit_shares: &[Rep3PrimeFieldShare<F>],
) -> Vec<Sha256SparseTraceRead<F>> {
    assert_eq!(
        bit_shares.len(),
        GarbledCircuits::SHA256_BLOCK_SPARSE_TRACE_OUTPUT_BITS,
        "expected the full sparse-trace bit vector"
    );
    sha256_block_sparse_trace_read_schedule()
        .into_iter()
        .map(|(table, offset)| {
            let bits = &bit_shares[offset..offset + table.trace_bits()];
            if table.is_rotation() {
                recombine_rotation_read(table, bits)
            } else {
                recombine_normalization_read(table, bits)
            }
        })
        .collect()
}

/// Rotation read from its 32 key-bit shares (LSB first). Mirrors, value-for-value, the plain
/// `get_sparse_table_with_rotation_values` semantics (co-builder plookup.rs:269-285) and the
/// driver's base-power recombination (co-acvm rep3.rs:1750-1793):
/// - key slice `s` = `sum_t 2^t * bit[off_s + t]`,
/// - sparse form  = `sum_t BASE^t * bit[off_s + t]`,
/// - rotated sparse form = `sum_j BASE^j * resized[(j + rot_s) % 32]` where `resized` is the
///   slice's bit vector zero-extended to 32 (rotate_right of the slice value as u32).
fn recombine_rotation_read<F: PrimeField>(
    table: Sha256SparseTraceTable,
    key_bits: &[Rep3PrimeFieldShare<F>],
) -> Sha256SparseTraceRead<F> {
    debug_assert_eq!(key_bits.len(), 32);
    let base = F::from(table.base());
    let two = F::from(2u64);
    let mut base_pows = Vec::with_capacity(32);
    let mut acc = F::one();
    for _ in 0..32 {
        base_pows.push(acc);
        acc *= base;
    }

    let slice_bit_sizes = table.slice_bit_sizes();
    let num_slices = slice_bit_sizes.len();
    let mut sparse = Vec::with_capacity(num_slices);
    let mut rotated_sparse = Vec::with_capacity(num_slices);
    let mut key_a_slices = Vec::with_capacity(num_slices);

    let mut offset = 0;
    for (&len, &rot) in izip!(slice_bit_sizes, table.rotations()) {
        // the slice's bits are key bits [offset..offset+len); bits beyond the 32-bit key are
        // structurally zero (WitnessInput's last slice is nominally 18 bits wide)
        let mut key_slice = Rep3PrimeFieldShare::zero_share();
        let mut sparse_acc = Rep3PrimeFieldShare::zero_share();
        let mut two_pow = F::one();
        for t in 0..len {
            if offset + t >= 32 {
                break;
            }
            let bit = key_bits[offset + t];
            key_slice = arithmetic::add(key_slice, arithmetic::mul_public(bit, two_pow));
            sparse_acc = arithmetic::add(sparse_acc, arithmetic::mul_public(bit, base_pows[t]));
            two_pow *= two;
        }
        // rotate_right(rot) of the zero-extended slice value as u32
        let mut rot_acc = Rep3PrimeFieldShare::zero_share();
        for (j, base_pow) in base_pows.iter().enumerate() {
            let t = (j + rot as usize) % 32;
            if t < len && offset + t < 32 {
                rot_acc = arithmetic::add(
                    rot_acc,
                    arithmetic::mul_public(key_bits[offset + t], *base_pow),
                );
            }
        }
        key_a_slices.push(key_slice);
        sparse.push(sparse_acc);
        rotated_sparse.push(rot_acc);
        offset += len;
    }

    Sha256SparseTraceRead::Rotation {
        table,
        sparse,
        rotated_sparse,
        key_a_slices,
        key_b_slices: vec![Rep3PrimeFieldShare::zero_share(); num_slices],
    }
}

/// Normalization read from its 32 digit groups `[d0..d_(digit_bits-1), f1, f2]` (LSB first).
/// Mirrors, value-for-value, the plain `get_sparse_normalization_values` semantics (co-builder
/// plookup.rs:287-324): key slice `s` covers the key's base-BASE digits
/// `s * digits_per_slice + j`, so
/// - key slice = `sum_j digit * BASE^j` with `digit = sum_t 2^t * d_t`,
/// - value     = `sum_j table[digit] * 2^j` with `table[digit] = f1 + 2 * f2`.
///
/// The 33rd digit of a Maj/WitnessOutput read (j = 2 of slice 10) is structurally zero and
/// contributes nothing.
fn recombine_normalization_read<F: PrimeField>(
    table: Sha256SparseTraceTable,
    group_bits: &[Rep3PrimeFieldShare<F>],
) -> Sha256SparseTraceRead<F> {
    let digit_bits = table.digit_bits();
    let digits_per_slice = table.digits_per_slice();
    let num_slices = table.num_slices();
    debug_assert_eq!(group_bits.len(), 32 * (digit_bits + 2));
    let base = F::from(table.base());
    let two = F::from(2u64);

    let mut values = Vec::with_capacity(num_slices);
    let mut key_a_slices = Vec::with_capacity(num_slices);

    for s in 0..num_slices {
        let mut key_slice = Rep3PrimeFieldShare::zero_share();
        let mut value = Rep3PrimeFieldShare::zero_share();
        let mut digit_weight = F::one(); // BASE^j
        let mut value_weight = F::one(); // 2^j
        for j in 0..digits_per_slice {
            let digit_index = s * digits_per_slice + j;
            if digit_index >= 32 {
                // structurally-zero 33rd digit of the base-16 output reads
                break;
            }
            let group = &group_bits[digit_index * (digit_bits + 2)..];
            let mut bit_weight = digit_weight;
            for &digit_bit in group.iter().take(digit_bits) {
                key_slice =
                    arithmetic::add(key_slice, arithmetic::mul_public(digit_bit, bit_weight));
                bit_weight *= two;
            }
            // table[digit] = f1 + 2 * f2
            value = arithmetic::add(
                value,
                arithmetic::mul_public(group[digit_bits], value_weight),
            );
            value = arithmetic::add(
                value,
                arithmetic::mul_public(group[digit_bits + 1], value_weight * two),
            );
            digit_weight *= base;
            value_weight *= two;
        }
        key_a_slices.push(key_slice);
        values.push(value);
    }

    Sha256SparseTraceRead::Normalization {
        table,
        values,
        key_a_slices,
        key_b_slices: vec![Rep3PrimeFieldShare::zero_share(); num_slices],
    }
}

/// Convenience wrapper: runs [`sha256_block_sparse_trace_kernel`] and recombines the bit shares
/// into the 369 per-read tuples (see [`sha256_block_sparse_trace_recombine_reads`]).
pub fn sha256_block_sparse_trace_reads<F: PrimeField, N: Network>(
    h_init: &[Rep3PrimeFieldShare<F>; 8],
    w_in: &[Rep3PrimeFieldShare<F>; 16],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Sha256SparseTraceRead<F>>> {
    let bit_shares = sha256_block_sparse_trace_kernel(h_init, w_in, net, state)?;
    Ok(sha256_block_sparse_trace_recombine_reads(&bit_shares))
}

//! The plookup reads of the circuit builder's SHA-256 compression gadget, computed from the bits
//! of [`yao::sha256_compression_sparse_trace`].
//!
//! [`yao::sha256_compression_sparse_trace`]: mpc_core::protocols::rep3::yao::sha256_compression_sparse_trace

use ark_ff::PrimeField;
use mpc_core::protocols::rep3::{
    Rep3PrimeFieldShare,
    yao::circuits::{GarbledCircuits, SHA256Table},
};
use std::collections::VecDeque;

/// The SHA-256 multi-tables of the compression gadget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Sha256Table {
    MajInput,
    ChInput,
    WitnessInput,
    MajOutput,
    ChOutput,
    WitnessOutput,
}

impl Sha256Table {
    /// The table of a sparse-form read with these parameters, as the builder passes them to
    /// `slice_and_get_sparse_table_with_rotation_values`. Other tables (e.g. the AES input table)
    /// give `None`.
    pub(super) fn of_rotation_read(
        basis_bits: &[u64],
        rotation: &[u32],
        base: u64,
    ) -> Option<Self> {
        match (base, rotation, basis_bits) {
            (16, [2, 2, 0], [2048, 2048, 1024]) => Some(Self::MajInput),
            (28, [6, 0, 3], [2048, 2048, 1024]) => Some(Self::ChInput),
            (16, [0, 4, 7, 1], [8, 128, 256, 262144]) => Some(Self::WitnessInput),
            _ => None,
        }
    }

    /// The table of a normalization read with this table type.
    pub(super) fn of_normalization_read(table_type: &SHA256Table) -> Self {
        match table_type {
            SHA256Table::Majority => Self::MajOutput,
            SHA256Table::Choose => Self::ChOutput,
            SHA256Table::WitnessExtension => Self::WitnessOutput,
        }
    }

    /// The base of the sparse form (sparse-form reads) or of the key digits (normalizations).
    fn base(self) -> u64 {
        match self {
            Self::ChInput | Self::ChOutput => 28,
            _ => 16,
        }
    }

    /// The bits of a sparse-form read's key slices.
    fn slice_bits(self) -> &'static [usize] {
        match self {
            Self::MajInput | Self::ChInput => &[11, 11, 10],
            _ => &[3, 7, 8, 18],
        }
    }

    /// The rotations of a sparse-form read's key slices.
    fn rotations(self) -> &'static [usize] {
        match self {
            Self::MajInput => &[2, 2, 0],
            Self::ChInput => &[6, 0, 3],
            _ => &[0, 4, 7, 1],
        }
    }

    /// The bits of a normalization digit and the number of digits per key slice.
    fn digit_bits_and_digits_per_slice(self) -> (usize, usize) {
        match self {
            Self::ChOutput => (5, 2),
            _ => (4, 3),
        }
    }

    /// The number of bits of a read in the trace.
    fn trace_bits(self) -> usize {
        match self {
            Self::MajInput | Self::ChInput | Self::WitnessInput => 32,
            _ => 32 * (self.digit_bits_and_digits_per_slice().0 + 2),
        }
    }
}

/// One precomputed read: the vectors the driver returns for it, i.e. (sparse forms, rotated
/// sparse forms, key slices, slices of the zero second key) for a sparse-form read and
/// (normalized values, key slices, slices of the zero second key) for a normalization.
pub(super) struct Sha256Read<F: PrimeField> {
    pub(super) table: Sha256Table,
    pub(super) outputs: Vec<Vec<Rep3PrimeFieldShare<F>>>,
}

/// The tables of the gadget's reads with shared keys, in the order in which `sha256_block` makes
/// them: the sparse forms of `h_init[1]`, `h_init[2]`, `h_init[5]` and `h_init[6]`; per message
/// schedule step i = 16..64 the conversions of w\[i - 15\] and w\[i - 2\] (each only the first
/// time), then the normalization; per round the choose and then the majority conversion and
/// normalization.
fn read_order() -> Vec<Sha256Table> {
    use Sha256Table::*;
    let mut order = vec![MajInput, MajInput, ChInput, ChInput];
    let mut has_sparse_limbs = [false; 64];
    for i in 16..64 {
        for j in [i - 15, i - 2] {
            if !has_sparse_limbs[j] {
                order.push(WitnessInput);
                has_sparse_limbs[j] = true;
            }
        }
        order.push(WitnessOutput);
    }
    for _ in 0..64 {
        order.extend([ChInput, ChOutput, MajInput, MajOutput]);
    }
    order
}

/// Computes all reads of one compression, in the gadget's order, from the arithmetic shares of
/// the bits of [`GarbledCircuits::sha256_compression_sparse_trace`]. Local: every value is a
/// public linear combination of the bits.
pub(super) fn reads_from_trace<F: PrimeField>(
    bits: &[Rep3PrimeFieldShare<F>],
) -> eyre::Result<VecDeque<Sha256Read<F>>> {
    eyre::ensure!(
        bits.len() == GarbledCircuits::SHA256_SPARSE_TRACE_BITS,
        "Unexpected length of the SHA-256 sparse trace"
    );
    let mut offset = 0;
    let mut reads = VecDeque::new();
    for table in read_order() {
        let bits = &bits[offset..offset + table.trace_bits()];
        offset += table.trace_bits();
        let outputs = match table {
            Sha256Table::MajInput | Sha256Table::ChInput | Sha256Table::WitnessInput => {
                sparse_form_read(table, bits)
            }
            _ => normalization_read(table, bits),
        };
        reads.push_back(Sha256Read { table, outputs });
    }
    debug_assert_eq!(offset, bits.len());
    Ok(reads)
}

fn powers<F: PrimeField>(base: u64, n: usize) -> Vec<F> {
    std::iter::successors(Some(F::one()), |x| Some(*x * F::from(base)))
        .take(n)
        .collect()
}

/// A sparse-form read from the 32 bits of its key. Per key slice of `len` bits starting at bit
/// `start`, with rotation `r`: the slice, its sparse form `sum_t bit_(start + t) * base^t`, and the
/// sparse form of the slice rotated right by r as a 32-bit value. Key bits beyond 32 are zero.
fn sparse_form_read<F: PrimeField>(
    table: Sha256Table,
    key_bits: &[Rep3PrimeFieldShare<F>],
) -> Vec<Vec<Rep3PrimeFieldShare<F>>> {
    let base_powers = powers::<F>(table.base(), 32);
    let two_powers = powers::<F>(2, 32);
    let zero = Rep3PrimeFieldShare::zero_share();
    let num_slices = table.slice_bits().len();
    let (mut sparse, mut rotated, mut slices) = (Vec::new(), Vec::new(), Vec::new());
    let mut start = 0;
    for (&len, &r) in table.slice_bits().iter().zip(table.rotations()) {
        let bit = |t: usize| (t < len && start + t < 32).then(|| key_bits[start + t]);
        let (mut slice, mut sparse_form, mut rotated_form) = (zero, zero, zero);
        for j in 0..32 {
            if let Some(bit) = bit(j) {
                slice += bit * two_powers[j];
                sparse_form += bit * base_powers[j];
            }
            if let Some(bit) = bit((j + r) % 32) {
                rotated_form += bit * base_powers[j];
            }
        }
        slices.push(slice);
        sparse.push(sparse_form);
        rotated.push(rotated_form);
        start += len;
    }
    vec![sparse, rotated, slices, vec![zero; num_slices]]
}

/// A normalization from the groups `[digit bits.., f1, f2]` of its 32 digits. Key slice s
/// consists of the digits `s * n..(s + 1) * n`, so it is `sum_j digit_(s * n + j) * base^j`, and
/// its normalized value is `sum_j (f1 + 2 * f2)_(s * n + j) * 2^j`. The digits beyond the 32nd
/// (in the last slice of the base-16 tables) are zero.
fn normalization_read<F: PrimeField>(
    table: Sha256Table,
    groups: &[Rep3PrimeFieldShare<F>],
) -> Vec<Vec<Rep3PrimeFieldShare<F>>> {
    let (digit_bits, digits_per_slice) = table.digit_bits_and_digits_per_slice();
    let base_powers = powers::<F>(table.base(), digits_per_slice);
    let two_powers = powers::<F>(2, digits_per_slice + digit_bits);
    let zero = Rep3PrimeFieldShare::zero_share();
    let (mut values, mut slices) = (Vec::new(), Vec::new());
    for first_digit in (0..32).step_by(digits_per_slice) {
        let (mut value, mut slice) = (zero, zero);
        for (j, digit) in (first_digit..32.min(first_digit + digits_per_slice)).enumerate() {
            let group = &groups[digit * (digit_bits + 2)..(digit + 1) * (digit_bits + 2)];
            for (t, bit) in group[..digit_bits].iter().enumerate() {
                slice += *bit * (base_powers[j] * two_powers[t]);
            }
            value += group[digit_bits] * two_powers[j];
            value += group[digit_bits + 1] * two_powers[j + 1];
        }
        values.push(value);
        slices.push(slice);
    }
    let num_slices = slices.len();
    vec![values, slices, vec![zero; num_slices]]
}

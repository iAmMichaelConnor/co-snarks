//! Deterministic (seedable) source for the ZK *masking/blinding* values of the UltraHonk
//! prover.
//!
//! # Testing only -- never use in production
//!
//! This type exists solely so tests can prove **cross-driver determinism**: with the same
//! witness and the same injected blinding randomness, the plain-driver ZK proof and the
//! REP3 ZK proof must be byte-identical. Seeding the ZK blinding obviously destroys the
//! zero-knowledge property (the masking values become predictable), so this must never be
//! reachable from the co-noir CLI or any production entry point. Activation is
//! explicit-API-only via `prove_with_seeded_zk_blinding` on the provers.
//!
//! # Draw discipline
//!
//! Each masking *draw site* (a place in the prover that draws values which end up affecting
//! committed polynomials / the transcript) gets its own independent ChaCha12 stream, derived
//! from the master seed and a per-site label (see [`site`]). Within a site, values are drawn
//! in a fixed documented order (coefficient/evaluation index order). This makes the injected
//! values independent of the *relative* order in which different sites happen to execute, so
//! provers that reorder rounds (or draw sites) still produce identical masking values --
//! only the per-site draw *counts* (all derived from public quantities: polynomial sizes,
//! `virtual_log_n`, fixed masking-term lengths) must agree.
//!
//! Only the ZK masking values may come from this source. General protocol randomness
//! (`T::rand` used for inversion blinding, `array_prod` r-values, zero-sharings, ...) is
//! intentionally *not* covered: its draw counts legitimately differ between drivers and it
//! never reaches the transcript.

use ark_ff::PrimeField;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;

/// Labels for every ZK masking draw site of the (co-)UltraHonk prover. One label per site;
/// the label ties a site's draws to its own deterministic stream (see module docs).
pub mod site {
    /// Oink: witness-wire masking rows {1,2,3} (one site per masked polynomial).
    pub const OINK_MASK_W_L: &str = "oink/mask/W_L";
    pub const OINK_MASK_W_R: &str = "oink/mask/W_R";
    pub const OINK_MASK_W_O: &str = "oink/mask/W_O";
    pub const OINK_MASK_LOOKUP_READ_COUNTS: &str = "oink/mask/LOOKUP_READ_COUNTS";
    pub const OINK_MASK_LOOKUP_READ_TAGS: &str = "oink/mask/LOOKUP_READ_TAGS";
    pub const OINK_MASK_W_4: &str = "oink/mask/W_4";
    pub const OINK_MASK_LOOKUP_INVERSES: &str = "oink/mask/LOOKUP_INVERSES";
    pub const OINK_MASK_Z_PERM: &str = "oink/mask/Z_PERM";
    /// Oink: Gemini mask values in `gemini_masking_support` order (`commit_to_masking_poly`).
    pub const OINK_GEMINI_MASKING_POLY: &str = "oink/gemini_masking_poly";
    /// Decider/sumcheck: Libra constant term (`ZKSumcheckData`).
    pub const LIBRA_CONSTANT_TERM: &str = "decider/libra/constant_term";
    /// Decider/sumcheck: the `virtual_log_n` Libra univariates, drawn polynomial-major,
    /// coefficient-index order within each polynomial.
    pub const LIBRA_UNIVARIATES: &str = "decider/libra/univariates";
    /// Decider/sumcheck: degree-1 masking term of the concatenated Libra polynomial.
    pub const LIBRA_CONCAT_MASKING: &str = "decider/libra/concat_masking";
    /// Decider/PCS: degree-2 masking term of the SmallSubgroupIPA grand-sum polynomial.
    pub const IPA_GRAND_SUM_MASKING: &str = "decider/ipa/grand_sum_masking";
}

/// Public support for the v6 Gemini mask. Every supported coefficient receives an
/// independent uniform field element. This is BB's tail-halving construction with
/// extent equal to the dyadic size: our polynomial storage backs the full domain.
/// For d >= 4 the 2d positions give the hiding rank required by Shplemini; smaller
/// domains use the dense fallback. Never choose this support from witness values.
pub fn gemini_masking_support(polynomial_size: usize) -> Vec<usize> {
    assert!(polynomial_size.is_power_of_two());
    let d = polynomial_size.ilog2() as usize;
    if d < 4 {
        return (0..polynomial_size).collect();
    }
    let mut support = Vec::with_capacity(2 * d);
    support.extend([polynomial_size - 1, polynomial_size - 2]);
    for level in 1..d {
        let base = polynomial_size >> level;
        support.extend([base, base - 1]);
    }
    support
}

/// A seedable source of ZK masking values. See the module docs: **testing only**, never
/// production -- a seeded prover is not zero-knowledge.
#[derive(Clone, Debug)]
pub struct SeededZkBlinding {
    seed: [u8; 32],
}

impl SeededZkBlinding {
    /// Builds the source from a full 32-byte master seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self { seed }
    }

    /// Convenience for tests: expands a `u64` into a 32-byte master seed (little-endian,
    /// repeated -- distinct `u64`s give distinct master seeds).
    pub fn from_u64(seed: u64) -> Self {
        let mut out = [0u8; 32];
        for (chunk, _) in out.chunks_mut(8).zip(0..4) {
            chunk.copy_from_slice(&seed.to_le_bytes());
        }
        Self { seed: out }
    }

    /// Deterministic per-site stream: master seed with an FNV-1a-64 hash of the site label
    /// mixed into the first 8 bytes (and its byte-swap into the next 8). Not cryptographic
    /// -- it only has to make the fixed, small label set of [`site`] map to distinct
    /// streams, which the unit test below pins.
    pub fn site_rng(&self, site_label: &str) -> ChaCha12Rng {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in site_label.as_bytes() {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        let mut child = self.seed;
        for (c, hb) in child[..8].iter_mut().zip(h.to_le_bytes()) {
            *c ^= hb;
        }
        for (c, hb) in child[8..16].iter_mut().zip(h.swap_bytes().to_le_bytes()) {
            *c ^= hb;
        }
        ChaCha12Rng::from_seed(child)
    }

    /// Draws `n` field elements for the given site, in stream order. This is THE draw
    /// primitive every seeded masking site must use, so the value derivation
    /// (`F::rand(ChaCha12)`) is identical everywhere.
    pub fn site_fields<F: PrimeField>(&self, site_label: &str, n: usize) -> Vec<F> {
        let mut rng = self.site_rng(site_label);
        (0..n).map(|_| F::rand(&mut rng)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_SITES: &[&str] = &[
        site::OINK_MASK_W_L,
        site::OINK_MASK_W_R,
        site::OINK_MASK_W_O,
        site::OINK_MASK_LOOKUP_READ_COUNTS,
        site::OINK_MASK_LOOKUP_READ_TAGS,
        site::OINK_MASK_W_4,
        site::OINK_MASK_LOOKUP_INVERSES,
        site::OINK_MASK_Z_PERM,
        site::OINK_GEMINI_MASKING_POLY,
        site::LIBRA_CONSTANT_TERM,
        site::LIBRA_UNIVARIATES,
        site::LIBRA_CONCAT_MASKING,
        site::IPA_GRAND_SUM_MASKING,
    ];

    /// Every site label must map to a distinct stream (pairwise), and the same
    /// (seed, site) pair must be reproducible.
    #[test]
    fn site_streams_distinct_and_reproducible() {
        use rand::RngCore as _;
        let src = SeededZkBlinding::from_u64(42);
        let firsts: Vec<u64> = ALL_SITES
            .iter()
            .map(|s| src.site_rng(s).next_u64())
            .collect();
        for i in 0..firsts.len() {
            for j in i + 1..firsts.len() {
                assert_ne!(
                    firsts[i], firsts[j],
                    "site labels {:?} and {:?} collided",
                    ALL_SITES[i], ALL_SITES[j]
                );
            }
        }
        let again: Vec<u64> = ALL_SITES
            .iter()
            .map(|s| src.site_rng(s).next_u64())
            .collect();
        assert_eq!(firsts, again, "same (seed, site) must reproduce");
        // And a different master seed must give different streams.
        let other = SeededZkBlinding::from_u64(43);
        assert_ne!(firsts[0], other.site_rng(ALL_SITES[0]).next_u64());
    }
}

#[cfg(test)]
mod sparse_rank_tests {
    use super::gemini_masking_support;
    use crate::honk_proof::TranscriptFieldType as Fr;
    use ark_ff::{Field, One, Zero};

    #[test]
    fn sparse_support_spans_gemini_leakage_at_regular_challenges() {
        // The relevant map sends X^s to L_(s mod 2^t)(u_<t) times
        // (tau^(s >> t), (-r^(2^t))^(s >> t)), for each fold t. This
        // tests the hiding rank, not merely the number of mask coefficients.
        // These regular challenge samples are regression evidence; the general
        // rank argument remains the pinned BB SHPLEMINI_ZK_MASKING.md theorem.
        for d in 4..=10 {
            let support = gemini_masking_support(1 << d);
            assert_eq!(support.len(), 2 * d);
            for seed in [101u64, 211u64] {
                let tau = Fr::from(seed);
                let r = Fr::from(seed + 2);
                let u: Vec<_> = (0..d).map(|i| Fr::from(seed + 6 + 2 * i as u64)).collect();
                let mut matrix = Vec::new();
                for t in 0..d {
                    for point in [tau, -r.pow([1u64 << t])] {
                        matrix.push(
                            support
                                .iter()
                                .map(|s| {
                                    let mut lagrange = Fr::one();
                                    for (k, challenge) in u.iter().enumerate().take(t) {
                                        lagrange *= if (s >> k) & 1 == 1 {
                                            *challenge
                                        } else {
                                            Fr::one() - challenge
                                        };
                                    }
                                    lagrange * point.pow([(s >> t) as u64])
                                })
                                .collect::<Vec<_>>(),
                        );
                    }
                }
                for col in 0..2 * d {
                    let pivot = (col..2 * d)
                        .find(|row| !matrix[*row][col].is_zero())
                        .expect("sparse Gemini masking map lost rank");
                    matrix.swap(col, pivot);
                    let inverse = matrix[col][col].inverse().unwrap();
                    for value in &mut matrix[col] {
                        *value *= inverse;
                    }
                    let pivot_row = matrix[col].clone();
                    for row in matrix.iter_mut().skip(col + 1) {
                        let factor = row[col];
                        for (value, pivot) in row.iter_mut().zip(&pivot_row) {
                            *value -= factor * pivot;
                        }
                    }
                }
            }
        }
        for n in [1, 2, 4, 8] {
            assert_eq!(gemini_masking_support(n), (0..n).collect::<Vec<_>>());
        }
    }
}

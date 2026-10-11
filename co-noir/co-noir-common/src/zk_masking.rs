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
    /// Oink: Gemini mask values in coefficient order (`commit_to_masking_poly`).
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

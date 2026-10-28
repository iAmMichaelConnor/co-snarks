//! Rep3 RNGs
//!
//! This module contains implementations of rep3 rngs

use super::{id::PartyID, yao::GCUtils};
use crate::RngType;
use crate::uint::UintBackend;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use fancy_garbling::WireMod2;
use rand::{Rng, SeedableRng, distributions::Standard, prelude::Distribution, seq::SliceRandom};
use rayon::prelude::*;
use sha3::{Digest, Sha3_256};

#[derive(Debug)]
/// A correlated rng for rep3
pub struct Rep3CorrelatedRng {
    /// Rep3 rng with this party's rng and the prev party's rng
    pub rand: Rep3Rand,
    pub(crate) bitcomp1: Rep3RandBitComp,
    pub(crate) bitcomp2: Rep3RandBitComp,
    // Public randomness must not share a cursor with private conversion masks.
    common_rng: RngType,
}

impl Rep3CorrelatedRng {
    /// Construct a new [`Rep3CorrelatedRng`]
    pub fn new(
        rand: Rep3Rand,
        bitcomp1: Rep3RandBitComp,
        bitcomp2: Rep3RandBitComp,
        id: PartyID,
    ) -> Self {
        // setup_bitcomp gives all three parties this same initial seed. The
        // matching streams are NOT consumed equally by later conversions:
        // party 0 does not draw bitcomp1 masks during direct b2a. Derive a
        // separate public stream without advancing any private mask cursor.
        let common_seed = match id {
            PartyID::ID0 | PartyID::ID1 => bitcomp1.rng2.get_seed(),
            PartyID::ID2 => bitcomp1.rng1.get_seed(),
        };
        let mut hash = Sha3_256::new();
        hash.update(b"co-snarks/rep3/common-public-rng/v1\0");
        hash.update(common_seed);
        let common_rng = RngType::from_seed(hash.finalize().into());
        Self {
            rand,
            bitcomp1,
            bitcomp2,
            common_rng,
        }
    }

    /// Create a fork of the current rng
    pub fn fork(&mut self) -> Self {
        let rand = self.rand.fork();
        let bitcomp1 = self.bitcomp1.fork();
        let bitcomp2 = self.bitcomp2.fork();
        let common_rng = RngType::from_seed(self.common_rng.r#gen());
        Self {
            rand,
            bitcomp1,
            bitcomp2,
            common_rng,
        }
    }

    /// Generate a value that is equal on all three parties
    pub fn generate_shared<T>(&mut self, _id: PartyID) -> T
    where
        Standard: Distribution<T>,
    {
        self.common_rng.r#gen()
    }

    /// Generate a value that is equal on all two garbler parties
    pub fn generate_garbler_randomness<T>(&mut self, id: PartyID) -> T
    where
        Standard: Distribution<T>,
    {
        match id {
            PartyID::ID0 => panic!("Garbler should not be PartyID::ID0"),
            PartyID::ID1 => self.rand.rng1.r#gen(),
            PartyID::ID2 => self.rand.rng2.r#gen(),
        }
    }

    /// Generate a random delta that is equal for the two garblers
    pub fn generate_random_garbler_delta(&mut self, id: PartyID) -> Option<WireMod2> {
        match id {
            PartyID::ID0 => None,
            PartyID::ID1 => Some(GCUtils::random_delta(&mut self.rand.rng1)),
            PartyID::ID2 => Some(GCUtils::random_delta(&mut self.rand.rng2)),
        }
    }
}

#[derive(Debug)]
/// Rep3 rng with this party's rng and the prev party's rng
pub struct Rep3Rand {
    rng1: RngType,
    rng2: RngType,
}

impl Rep3Rand {
    /// Construct a new [`Rep3Rand`]
    pub fn new(seed1: [u8; crate::SEED_SIZE], seed2: [u8; crate::SEED_SIZE]) -> Self {
        let rng1 = RngType::from_seed(seed1);
        let rng2 = RngType::from_seed(seed2);
        Self { rng1, rng2 }
    }

    /// Create a fork of this rng
    pub fn fork(&mut self) -> Self {
        let (seed1, seed2) = self.random_seeds();
        Self::new(seed1, seed2)
    }

    /// Generate a masking field element
    pub fn masking_field_element<F: PrimeField>(&mut self) -> F {
        let (a, b) = self.random_fes::<F>();
        a - b
    }

    /// Generate two random field elements
    pub fn random_fes<F: PrimeField>(&mut self) -> (F, F) {
        let a = F::rand(&mut self.rng1);
        let b = F::rand(&mut self.rng2);
        (a, b)
    }

    /// Generate a masking element
    pub fn masking_element<T>(&mut self) -> T
    where
        Standard: Distribution<T>,
        T: std::ops::Sub<Output = T>,
    {
        let (a, b) = self.random_elements::<T>();
        a - b
    }

    /// Generate two random elements
    pub fn random_elements<T>(&mut self) -> (T, T)
    where
        Standard: Distribution<T>,
    {
        let a = self.rng1.r#gen();
        let b = self.rng2.r#gen();
        (a, b)
    }

    // TODO do not collect the values
    /// Generate a vector of masking field elements
    pub fn masking_field_elements_vec<F: PrimeField>(&mut self, len: usize) -> Vec<F> {
        // Each party knows one of the two adjacent pairwise masks. The other
        // must therefore be uniform by itself; subtracting two biased samples
        // is not sufficient. Reducing only ceil(log2(p)/8) random bytes modulo
        // p gives a non-negligible bias (about 0.039 for BN254 Fr).
        // F::rand uses uniform field sampling and matches the scalar path's
        // consumption of each pairwise RNG. Draw the two independent streams
        // in parallel, then subtract locally without further randomness.
        let (a, b) = rayon::join(
            || {
                (0..len)
                    .map(|_| F::rand(&mut self.rng1))
                    .collect::<Vec<_>>()
            },
            || {
                (0..len)
                    .map(|_| F::rand(&mut self.rng2))
                    .collect::<Vec<_>>()
            },
        );
        a.into_par_iter()
            .zip_eq(b.into_par_iter())
            .with_min_len(512)
            .map(|(a, b)| a - b)
            .collect()
    }

    // TODO do not collect the values
    /// Generate a vector of masking elements
    pub fn masking_elements_vec<T>(&mut self, len: usize) -> Vec<T>
    where
        Standard: Distribution<T>,
        T: Send + Sync + std::ops::Sub<Output = T>,
    {
        let (a, b) = rayon::join(
            || (0..len).map(|_| self.rng1.r#gen()).collect::<Vec<_>>(),
            || (0..len).map(|_| self.rng2.r#gen()).collect::<Vec<_>>(),
        );
        a.into_par_iter()
            .zip_eq(b.into_par_iter())
            .with_min_len(512)
            .map(|(a, b)| a - b)
            .collect()
    }

    /// Create a masking elliptic curve element
    pub fn masking_ec_element<C: CurveGroup>(&mut self) -> C {
        let (a, b) = self.random_ecs::<C>();
        a - b
    }

    /// Generate two random elliptic curve elements
    pub fn random_ecs<C: CurveGroup>(&mut self) -> (C, C) {
        let a = C::rand(&mut self.rng1);
        let b = C::rand(&mut self.rng2);
        (a, b)
    }

    /// Generate two random fixed-width uints with given `bitlen`
    pub fn random_uint<U: UintBackend>(&mut self, bitlen: usize) -> (U, U) {
        let a = U::random_bits(&mut self.rng1, bitlen);
        let b = U::random_bits(&mut self.rng2, bitlen);
        (a, b)
    }

    /// Generate a random fixed-width uint with given `bitlen` from rng1
    pub fn random_uint_rng1<U: UintBackend>(&mut self, bitlen: usize) -> U {
        U::random_bits(&mut self.rng1, bitlen)
    }

    /// Generate a random fixed-width uint with given `bitlen` from rng2
    pub fn random_uint_rng2<U: UintBackend>(&mut self, bitlen: usize) -> U {
        U::random_bits(&mut self.rng2, bitlen)
    }

    /// Generate a random field_element from rng1
    pub fn random_field_element_rng1<F: PrimeField>(&mut self) -> F {
        F::rand(&mut self.rng1)
    }

    /// Generate a random field_element from rng2
    pub fn random_field_element_rng2<F: PrimeField>(&mut self) -> F {
        F::rand(&mut self.rng2)
    }

    /// Generate a random `T` from rng1
    pub fn random_element_rng1<T>(&mut self) -> T
    where
        Standard: Distribution<T>,
    {
        self.rng1.r#gen()
    }

    /// Generate a random `T` from rng1
    pub fn random_element_rng2<T>(&mut self) -> T
    where
        Standard: Distribution<T>,
    {
        self.rng2.r#gen()
    }

    /// Generate a seed from each rng
    pub fn random_seeds(&mut self) -> ([u8; crate::SEED_SIZE], [u8; crate::SEED_SIZE]) {
        let seed1 = self.rng1.r#gen();
        let seed2 = self.rng2.r#gen();
        (seed1, seed2)
    }

    /// Generate a random shared permutation
    pub fn random_perm<T: Clone>(&mut self, input: Vec<T>) -> (Vec<T>, Vec<T>) {
        let mut a = input.to_owned();
        let mut b = input;
        a.shuffle(&mut self.rng1);
        b.shuffle(&mut self.rng2);
        (a, b)
    }
}

/// This struct is responsible for creating random shares for the Binary to Arithmetic conversion. The approach is the following: for a final sharing x = x1 + x2 + x3, we want to have random values x2, x3 and subtract these from the original value x using a binary circuit to get the share x1. Hence, we need to sample random x2 and x3 and share them amongst the parties. One RandBitComp struct is responsible for either sampling x2 or x3. For sampling x2, parties 1 and 2 will get x2 in plain (since this is the final share of x), so they need to have a PRF key from all parties. party 3, however, will not get x2 in plain and must thus only be able to sample its shares of x2, requiring two PRF keys.
#[derive(Debug)]
pub struct Rep3RandBitComp {
    rng1: RngType,
    rng2: RngType,
    rng3: Option<RngType>,
}

impl Rep3RandBitComp {
    /// Construct a new [`Rep3RandBitComp`] w rngs
    pub fn new_2keys(rng1: [u8; crate::SEED_SIZE], rng2: [u8; crate::SEED_SIZE]) -> Self {
        Self {
            rng1: RngType::from_seed(rng1),
            rng2: RngType::from_seed(rng2),
            rng3: None,
        }
    }

    /// Construct a new [`Rep3RandBitComp`] with 3 rngs
    pub fn new_3keys(
        rng1: [u8; crate::SEED_SIZE],
        rng2: [u8; crate::SEED_SIZE],
        rng3: [u8; crate::SEED_SIZE],
    ) -> Self {
        Self {
            rng1: RngType::from_seed(rng1),
            rng2: RngType::from_seed(rng2),
            rng3: Some(RngType::from_seed(rng3)),
        }
    }

    /// Generate three random field elements
    pub fn random_fes_3keys<F: PrimeField>(&mut self) -> (F, F, F) {
        let a = F::rand(&mut self.rng1);
        let b = F::rand(&mut self.rng2);
        let c = if let Some(rng3) = &mut self.rng3 {
            F::rand(rng3)
        } else {
            unreachable!()
        };
        (a, b, c)
    }

    /// Generate three random curve elements
    pub fn random_curves_3keys<C: CurveGroup>(&mut self) -> (C, C, C) {
        let a = C::rand(&mut self.rng1);
        let b = C::rand(&mut self.rng2);
        let c = if let Some(rng3) = &mut self.rng3 {
            C::rand(rng3)
        } else {
            unreachable!()
        };
        (a, b, c)
    }

    /// Generate three random field elements
    pub fn random_elements_3keys<T>(&mut self) -> (T, T, T)
    where
        Standard: Distribution<T>,
    {
        let a = self.rng1.r#gen();
        let b = self.rng2.r#gen();
        let c = if let Some(rng3) = &mut self.rng3 {
            rng3.r#gen()
        } else {
            unreachable!()
        };
        (a, b, c)
    }

    /// Create a fork of this rng
    pub fn fork(&mut self) -> Self {
        let rng1 = RngType::from_seed(self.rng1.r#gen());
        let rng2 = RngType::from_seed(self.rng2.r#gen());
        let rng3 = self
            .rng3
            .as_mut()
            .map(|rng| RngType::from_seed(rng.r#gen()));
        Self { rng1, rng2, rng3 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uint::U256;

    fn seeds() -> ([u8; crate::SEED_SIZE], [u8; crate::SEED_SIZE]) {
        ([1u8; crate::SEED_SIZE], [2u8; crate::SEED_SIZE])
    }

    #[test]
    fn random_uint_masks_and_derives_from_both_rngs() {
        let (seed1, seed2) = seeds();
        let mut rand = Rep3Rand::new(seed1, seed2);
        for _ in 0..100 {
            let (a, b): (U256, U256) = rand.random_uint(100);
            assert!(a.bit_len() <= 100);
            assert!(b.bit_len() <= 100);
        }

        // rng1/rng2 single draws equal the pair components drawn from
        // equal-seeded clones.
        let mut rand_pair = Rep3Rand::new(seed1, seed2);
        let mut rand_single = Rep3Rand::new(seed1, seed2);
        let (pair_a, pair_b): (U256, U256) = rand_pair.random_uint(64);
        let single_a: U256 = rand_single.random_uint_rng1(64);
        let single_b: U256 = rand_single.random_uint_rng2(64);
        assert_eq!(pair_a, single_a);
        assert_eq!(pair_b, single_b);
    }
}

#[cfg(test)]
mod uniform_mask_tests {
    use super::Rep3Rand;
    use ark_bn254::Fr;
    use ark_ff::Zero;

    #[test]
    fn vector_masks_match_uniform_scalar_sampling_across_batches() {
        // The scalar path uses rejection sampling through F::rand. Matching
        // both its outputs and subsequent stream position prevents replacing
        // it with biased fixed-width modular reduction in the batch path.
        let mut scalar = Rep3Rand::new([17; 32], [29; 32]);
        let mut batched = Rep3Rand::new([17; 32], [29; 32]);
        for len in [0, 1, 31, 1024, 3] {
            let expected: Vec<Fr> = (0..len).map(|_| scalar.masking_field_element()).collect();
            assert_eq!(batched.masking_field_elements_vec::<Fr>(len), expected);
            assert_eq!(
                batched.random_fes::<Fr>(),
                scalar.random_fes::<Fr>(),
                "batching changed subsequent pairwise RNG consumption"
            );
        }
    }

    #[test]
    fn vector_masks_cancel_across_rep3_edges() {
        // Every edge is sampled independently by its two endpoints. A fresh
        // zero sharing must sum to zero after any mixture of batch lengths.
        let seeds = [[17; 32], [29; 32], [43; 32]];
        let mut parties = [
            Rep3Rand::new(seeds[0], seeds[2]),
            Rep3Rand::new(seeds[1], seeds[0]),
            Rep3Rand::new(seeds[2], seeds[1]),
        ];
        for len in [1, 7, 1024, 0, 13] {
            let masks = parties
                .each_mut()
                .map(|rng| rng.masking_field_elements_vec::<Fr>(len));
            for i in 0..len {
                assert!((masks[0][i] + masks[1][i] + masks[2][i]).is_zero());
            }
        }
    }
}

#[cfg(test)]
mod common_rng_tests {
    use super::*;
    use ark_bn254::{Fq, Fr};

    fn parties() -> [Rep3CorrelatedRng; 3] {
        // Same seed topology as setup_bitcomp: the three-key sums are equal
        // despite their per-party key order. Only party 0 lacks bitcomp1's
        // third key and only party 1 lacks bitcomp2's third key.
        let [a, b, c, d, e, f] = [11, 13, 17, 19, 23, 29].map(|x| [x; 32]);
        [
            Rep3CorrelatedRng::new(
                Rep3Rand::new(a, c),
                Rep3RandBitComp::new_2keys(a, c),
                Rep3RandBitComp::new_3keys(d, e, f),
                PartyID::ID0,
            ),
            Rep3CorrelatedRng::new(
                Rep3Rand::new(b, a),
                Rep3RandBitComp::new_3keys(b, c, a),
                Rep3RandBitComp::new_2keys(e, d),
                PartyID::ID1,
            ),
            Rep3CorrelatedRng::new(
                Rep3Rand::new(c, b),
                Rep3RandBitComp::new_3keys(c, a, b),
                Rep3RandBitComp::new_3keys(f, d, e),
                PartyID::ID2,
            ),
        ]
    }

    fn check_common(parties: &mut [Rep3CorrelatedRng; 3]) -> [u8; 32] {
        let [p0, p1, p2] = parties.each_mut();
        let seeds = [
            p0.generate_shared::<[u8; 32]>(PartyID::ID0),
            p1.generate_shared::<[u8; 32]>(PartyID::ID1),
            p2.generate_shared::<[u8; 32]>(PartyID::ID2),
        ];
        assert!(seeds[0] == seeds[1] && seeds[1] == seeds[2]);
        seeds[0]
    }

    fn consume_field_masks<F: PrimeField>(parties: &mut [Rep3CorrelatedRng; 3]) {
        let [p0, p1, p2] = parties.each_mut();
        let sum = |(a, b, c): (F, F, F)| a + b + c;
        let k3 = sum(p0.bitcomp2.random_fes_3keys::<F>());
        let k2 = sum(p1.bitcomp1.random_fes_3keys::<F>());
        assert_eq!(k2, sum(p2.bitcomp1.random_fes_3keys::<F>()));
        assert_eq!(k3, sum(p2.bitcomp2.random_fes_3keys::<F>()));
    }

    fn consume_ring_masks(parties: &mut [Rep3CorrelatedRng; 3]) {
        let [p0, p1, p2] = parties.each_mut();
        let sum = |(a, b, c): (u32, u32, u32)| a.wrapping_add(b).wrapping_add(c);
        let k3 = sum(p0.bitcomp2.random_elements_3keys::<u32>());
        let k2 = sum(p1.bitcomp1.random_elements_3keys::<u32>());
        assert_eq!(k2, sum(p2.bitcomp1.random_elements_3keys::<u32>()));
        assert_eq!(k3, sum(p2.bitcomp2.random_elements_3keys::<u32>()));
    }

    fn private_positions(rng: &Rep3CorrelatedRng) -> [Option<u128>; 8] {
        [
            Some(rng.rand.rng1.get_word_pos()),
            Some(rng.rand.rng2.get_word_pos()),
            Some(rng.bitcomp1.rng1.get_word_pos()),
            Some(rng.bitcomp1.rng2.get_word_pos()),
            rng.bitcomp1.rng3.as_ref().map(RngType::get_word_pos),
            Some(rng.bitcomp2.rng1.get_word_pos()),
            Some(rng.bitcomp2.rng2.get_word_pos()),
            rng.bitcomp2.rng3.as_ref().map(RngType::get_word_pos),
        ]
    }

    #[test]
    fn common_rng_stays_equal_after_private_masks_and_forks() {
        let mut parties = parties();
        check_common(&mut parties);
        for _ in 0..9 {
            consume_field_masks::<Fr>(&mut parties);
            consume_ring_masks(&mut parties);
            consume_field_masks::<Fq>(&mut parties);
            check_common(&mut parties);
        }
        let mut children = parties.each_mut().map(Rep3CorrelatedRng::fork);
        let parent_seed = check_common(&mut parties);
        let child_seed = check_common(&mut children);
        assert!(parent_seed != child_seed);
        for group in [&mut parties, &mut children] {
            consume_field_masks::<Fr>(group);
            consume_ring_masks(group);
            consume_field_masks::<Fq>(group);
            check_common(group);
        }
        let mut grandchildren = children.each_mut().map(Rep3CorrelatedRng::fork);
        check_common(&mut grandchildren);
        consume_field_masks::<Fr>(&mut grandchildren);
        check_common(&mut grandchildren);
    }

    #[test]
    fn common_rng_does_not_consume_private_streams() {
        let mut parties = parties();
        consume_field_masks::<Fr>(&mut parties);
        consume_ring_masks(&mut parties);
        let before = parties.each_ref().map(private_positions);
        for _ in 0..17 {
            check_common(&mut parties);
        }
        assert_eq!(before, parties.each_ref().map(private_positions));
        consume_field_masks::<Fq>(&mut parties);
        consume_ring_masks(&mut parties);
    }
}

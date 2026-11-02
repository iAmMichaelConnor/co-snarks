//! Rep3 RNGs
//!
//! This module contains implementations of rep3 rngs

use super::yao::fancy::WireMod2;
use super::{id::PartyID, yao::GCUtils};
use crate::RngType;
use crate::uint::UintBackend;
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField};
use rand::{Rng, SeedableRng, distributions::Standard, prelude::Distribution, seq::SliceRandom};
use rayon::prelude::*;

#[derive(Debug)]
/// A correlated rng for rep3
pub struct Rep3CorrelatedRng {
    /// Rep3 rng with this party's rng and the prev party's rng
    pub rand: Rep3Rand,
    pub(crate) bitcomp1: Rep3RandBitComp,
    pub(crate) bitcomp2: Rep3RandBitComp,
    /// Stream for values that are equal on all three parties, see [`Self::with_common_seed`]
    common: Option<RngType>,
}

impl Rep3CorrelatedRng {
    /// Construct a new [`Rep3CorrelatedRng`] without a separate stream for common randomness.
    ///
    /// [`Self::generate_shared`] then draws from the bit-composition streams, which the
    /// parties do not consume equally during conversions, so its values are only equal on
    /// all parties until the first conversion. Prefer [`Self::with_common_seed`].
    pub fn new(rand: Rep3Rand, bitcomp1: Rep3RandBitComp, bitcomp2: Rep3RandBitComp) -> Self {
        Self {
            rand,
            bitcomp1,
            bitcomp2,
            common: None,
        }
    }

    /// Construct a new [`Rep3CorrelatedRng`] whose [`Self::generate_shared`] values come from
    /// a separate stream seeded with `common_seed`, which must be equal on all three parties
    /// and independent of the other streams.
    pub fn with_common_seed(
        rand: Rep3Rand,
        bitcomp1: Rep3RandBitComp,
        bitcomp2: Rep3RandBitComp,
        common_seed: [u8; crate::SEED_SIZE],
    ) -> Self {
        Self {
            rand,
            bitcomp1,
            bitcomp2,
            common: Some(RngType::from_seed(common_seed)),
        }
    }

    /// Create a fork of the current rng
    pub fn fork(&mut self) -> Self {
        let rand = self.rand.fork();
        let bitcomp1 = self.bitcomp1.fork();
        let bitcomp2 = self.bitcomp2.fork();
        let common = self
            .common
            .as_mut()
            .map(|rng| RngType::from_seed(rng.r#gen()));
        Self {
            rand,
            bitcomp1,
            bitcomp2,
            common,
        }
    }

    /// Generate a value that is equal on all three parties
    pub fn generate_shared<T>(&mut self, id: PartyID) -> T
    where
        Standard: Distribution<T>,
    {
        if let Some(common) = &mut self.common {
            return common.r#gen();
        }
        match id {
            PartyID::ID0 => self.bitcomp1.rng2.r#gen(),
            PartyID::ID1 => self.bitcomp1.rng2.r#gen(),
            PartyID::ID2 => self.bitcomp1.rng1.r#gen(),
        }
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
        // Chunk c samples from clones of both streams seeked to word position
        // `base + c * budget` (ChaCha streams are seekable), so the result is a deterministic
        // function of the rng state and the party sharing a stream obtains the same values.
        // arkworks samples field elements by rejection after masking to the modulus bit
        // length, consuming 2 * NUM_LIMBS words per attempt with success probability >= 1/2;
        // with a budget of 8 attempts per element, exhausting a chunk's region has
        // probability < 2^-1000 and is asserted (identically on both parties), since
        // continuing would overlap the next chunk's region and reuse masks.
        const CHUNK: usize = 1024;
        let budget = 2 * <F::BigInt as BigInteger>::NUM_LIMBS as u128 * CHUNK as u128 * 8;
        let (base1, base2) = (self.rng1.get_word_pos(), self.rng2.get_word_pos());
        let n_chunks = len.div_ceil(CHUNK);
        let (rng1, rng2) = (&self.rng1, &self.rng2);
        let res = (0..n_chunks)
            .into_par_iter()
            .map(|c| {
                let (mut r1, mut r2) = (rng1.clone(), rng2.clone());
                r1.set_word_pos(base1 + c as u128 * budget);
                r2.set_word_pos(base2 + c as u128 * budget);
                let take = CHUNK.min(len - c * CHUNK);
                let v = (0..take)
                    .map(|_| F::rand(&mut r1) - F::rand(&mut r2))
                    .collect::<Vec<_>>();
                assert!(
                    r1.get_word_pos() <= base1 + (c as u128 + 1) * budget
                        && r2.get_word_pos() <= base2 + (c as u128 + 1) * budget,
                    "rng chunk budget exhausted"
                );
                v
            })
            .flatten()
            .collect();
        self.rng1.set_word_pos(base1 + n_chunks as u128 * budget);
        self.rng2.set_word_pos(base2 + n_chunks as u128 * budget);
        res
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
    use ark_bn254::Fr;
    use ark_ff::Zero;
    use itertools::izip;

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

    #[test]
    fn masking_field_elements_vec_cancel_across_parties() {
        // Each pairwise stream is shared by two parties, so for every length the three
        // parties' masks at each index are a sharing of zero.
        let seeds = [
            [17; crate::SEED_SIZE],
            [29; crate::SEED_SIZE],
            [43; crate::SEED_SIZE],
        ];
        let mut parties = [
            Rep3Rand::new(seeds[0], seeds[2]),
            Rep3Rand::new(seeds[1], seeds[0]),
            Rep3Rand::new(seeds[2], seeds[1]),
        ];
        for len in [1, 7, 1024, 0, 13] {
            let masks = parties
                .each_mut()
                .map(|rng| rng.masking_field_elements_vec::<Fr>(len));
            let [m0, m1, m2] = masks;
            assert!(m0.len() == len && m1.len() == len && m2.len() == len);
            for (a, b, c) in izip!(m0, m1, m2) {
                assert!((a + b + c).is_zero());
            }
            let [a, b, c] = parties
                .each_mut()
                .map(|rng| rng.masking_field_element::<Fr>());
            assert!((a + b + c).is_zero());
        }
    }

    /// The rngs of the three parties with the key layout of `Rep3State::setup_bitcomp`.
    fn three_parties() -> [Rep3CorrelatedRng; 3] {
        let [a, b, c, d, e, f] = [11, 13, 17, 19, 23, 29].map(|x| [x; crate::SEED_SIZE]);
        let ctor = |rand, bitcomp1, bitcomp2| {
            Rep3CorrelatedRng::with_common_seed(rand, bitcomp1, bitcomp2, [31; crate::SEED_SIZE])
        };
        [
            ctor(
                Rep3Rand::new(a, c),
                Rep3RandBitComp::new_2keys(a, c),
                Rep3RandBitComp::new_3keys(d, e, f),
            ),
            ctor(
                Rep3Rand::new(b, a),
                Rep3RandBitComp::new_3keys(b, c, a),
                Rep3RandBitComp::new_2keys(e, d),
            ),
            ctor(
                Rep3Rand::new(c, b),
                Rep3RandBitComp::new_3keys(c, a, b),
                Rep3RandBitComp::new_3keys(f, d, e),
            ),
        ]
    }

    fn generate_shared(parties: &mut [Rep3CorrelatedRng; 3]) -> [[u8; 32]; 3] {
        let [p0, p1, p2] = parties.each_mut();
        [
            p0.generate_shared(PartyID::ID0),
            p1.generate_shared(PartyID::ID1),
            p2.generate_shared(PartyID::ID2),
        ]
    }

    /// Draws one mask from each bit-composition rng the way the conversions do: party 0
    /// does not draw from `bitcomp1`, party 1 does not draw from `bitcomp2`.
    fn draw_bitcomp_masks(parties: &mut [Rep3CorrelatedRng; 3]) {
        let [p0, p1, p2] = parties.each_mut();
        let sum = |(a, b, c): (Fr, Fr, Fr)| a + b + c;
        let k2 = sum(p1.bitcomp1.random_fes_3keys());
        assert_eq!(k2, sum(p2.bitcomp1.random_fes_3keys()));
        let k3 = sum(p0.bitcomp2.random_fes_3keys());
        assert_eq!(k3, sum(p2.bitcomp2.random_fes_3keys()));
    }

    #[test]
    fn common_randomness_is_independent_of_bitcomp_masks() {
        let mut parties = three_parties();
        for _ in 0..4 {
            let [c0, c1, c2] = generate_shared(&mut parties);
            assert!(c0 == c1 && c1 == c2);
            draw_bitcomp_masks(&mut parties);
        }
        let mut children = parties.each_mut().map(Rep3CorrelatedRng::fork);
        for group in [&mut parties, &mut children] {
            draw_bitcomp_masks(group);
            let [c0, c1, c2] = generate_shared(group);
            assert!(c0 == c1 && c1 == c2);
        }
        assert_ne!(
            generate_shared(&mut parties),
            generate_shared(&mut children)
        );
        // Drawing common randomness does not move the bit-composition streams.
        let mut a = three_parties();
        let mut b = three_parties();
        generate_shared(&mut a);
        let [a0, a1, a2] = a.each_mut();
        let [b0, b1, b2] = b.each_mut();
        assert_eq!(
            a1.bitcomp1.random_fes_3keys::<Fr>(),
            b1.bitcomp1.random_fes_3keys::<Fr>()
        );
        assert_eq!(
            a2.bitcomp1.random_fes_3keys::<Fr>(),
            b2.bitcomp1.random_fes_3keys::<Fr>()
        );
        assert_eq!(
            a0.bitcomp2.random_fes_3keys::<Fr>(),
            b0.bitcomp2.random_fes_3keys::<Fr>()
        );
    }
}

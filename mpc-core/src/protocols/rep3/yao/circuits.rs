//! Circuits
//!
//! This module contains some garbled circuit implementations.

use super::bristol_fashion::BristolFashionEvaluator;
use crate::protocols::rep3::yao::{GCUtils, bristol_fashion::BristolFashionCircuit};
use ark_ff::PrimeField;
use core::panic;
use fancy_garbling::{BinaryBundle, Fancy, FancyBinary, FancyError, HasModulus};
use itertools::izip;
use num_bigint::BigUint;
use std::ops::Not;

/// This trait allows to lazily initialize the constants 0 and 1 for the garbled circuit, such that these constants are only send at most once each.
pub trait FancyBinaryConstant: FancyBinary {
    /// Takes an already initialized constant 0 or adds it to the garbled circuit if not yet present
    fn const_zero(&mut self) -> Result<Self::Item, Self::Error>;

    /// Takes an already initialized constant 1 or adds it to the garbled circuit if not yet present
    fn const_one(&mut self) -> Result<Self::Item, Self::Error>;
}

/// An enum used for using the right table in the garbled circuit implementation of SHA256.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SHA256Table {
    /// Picks the CHOOSE_NORMALIZATION_TABLE (see plookup.rs)
    Choose,
    /// Picks the MAJORITY_NORMALIZATION_TABLE (see plookup.rs)
    Majority,
    /// Picks the WITNESS_EXTENSION_NORMALIZATION_TABLE (see plookup.rs)
    WitnessExtension,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum ReturnType {
    BinaryAsArithmetic,
    Arithmetic,
}

/// This struct contains some predefined garbled circuits.
pub struct GarbledCircuits {}

impl GarbledCircuits {
    fn constant_bundle_from_u32<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        c: u32,
        size: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        Self::constant_bundle_from_usize(g, c as usize, size)
    }

    fn constant_bundle_from_usize<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        c: usize,
        size: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        let mut result = Vec::with_capacity(size);

        for i in 0..size {
            let bit = (c >> i) & 1 != 0;
            if bit {
                result.push(g.const_one()?);
            } else {
                result.push(g.const_zero()?);
            }
        }

        Ok(result)
    }
    fn full_adder_const<G: FancyBinary>(
        g: &mut G,
        a: &G::Item,
        b: bool,
        c: &G::Item,
    ) -> Result<(G::Item, G::Item), G::Error> {
        let (s, c) = if b {
            let z1 = g.negate(a)?;
            let s = g.xor(&z1, c)?;
            let z3 = g.xor(a, c)?;
            let z4 = g.and(&z1, &z3)?;
            let c = g.xor(&z4, a)?;
            (s, c)
        } else {
            let z1 = a;
            let s = g.xor(z1, c)?;
            let z3 = &s;
            let z4 = g.and(z1, z3)?;
            let c = g.xor(&z4, a)?;
            (s, c)
        };

        Ok((s, c))
    }

    fn half_adder<G: FancyBinary>(
        g: &mut G,
        a: &G::Item,
        b: &G::Item,
    ) -> Result<(G::Item, G::Item), G::Error> {
        let s = g.xor(a, b)?;
        let c = g.and(a, b)?;
        Ok((s, c))
    }

    fn half_adder_const<G: FancyBinary>(
        g: &mut G,
        a: &G::Item,
        b: bool,
    ) -> Result<(G::Item, G::Item), G::Error> {
        let s = if b { g.negate(a)? } else { a.to_owned() };
        let c = a.to_owned();
        Ok((s, c))
    }

    /// Full adder, just outputs carry
    fn full_adder_carry<G: FancyBinary>(
        g: &mut G,
        a: &G::Item,
        b: &G::Item,
        c: &G::Item,
    ) -> Result<G::Item, G::Error> {
        let z1 = g.xor(a, b)?;
        let z3 = g.xor(a, c)?;
        let z4 = g.and(&z1, &z3)?;
        let c = g.xor(&z4, a)?;
        Ok(c)
    }

    fn full_adder<G: FancyBinary>(
        g: &mut G,
        a: &G::Item,
        b: &G::Item,
        c: &G::Item,
    ) -> Result<(G::Item, G::Item), G::Error> {
        let z1 = g.xor(a, b)?;
        let s = g.xor(&z1, c)?;
        let z3 = g.xor(a, c)?;
        let z4 = g.and(&z1, &z3)?;
        let c = g.xor(&z4, a)?;
        Ok((s, c))
    }

    /// Full adder with carry in set
    fn full_adder_cin_set<G: FancyBinary>(
        g: &mut G,
        a: &G::Item,
        b: &G::Item,
    ) -> Result<(G::Item, G::Item), G::Error> {
        let z1 = g.xor(a, b)?;
        let s = g.negate(&z1)?;
        let z3 = g.negate(a)?;
        let z4 = g.and(&z1, &z3)?;
        let c = g.xor(&z4, a)?;
        Ok((s, c))
    }

    /// Full adder with carry in set
    fn full_adder_const_cin_set<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        a: &G::Item,
        b: bool,
    ) -> Result<(G::Item, G::Item), G::Error> {
        let (s, c) = if b {
            (a.clone(), g.const_one()?)
        } else {
            (g.negate(a)?, a.clone())
        };
        Ok((s, c))
    }

    /// Full adder with carry in set, just outputs carry
    fn full_adder_carry_cin_set<G: FancyBinary>(
        g: &mut G,
        a: &G::Item,
        b: &G::Item,
    ) -> Result<G::Item, G::Error> {
        let z1 = g.xor(a, b)?;
        let z3 = g.negate(a)?;
        let z4 = g.and(&z1, &z3)?;
        let c = g.xor(&z4, a)?;
        Ok(c)
    }

    /// Binary addition. Returns the result and the carry.
    #[expect(clippy::type_complexity)]
    fn bin_addition<G: FancyBinary>(
        g: &mut G,
        xs: &[G::Item],
        ys: &[G::Item],
    ) -> Result<(Vec<G::Item>, G::Item), G::Error> {
        debug_assert_eq!(xs.len(), ys.len());
        let mut result = Vec::with_capacity(xs.len());

        let (mut s, mut c) = Self::half_adder(g, &xs[0], &ys[0])?;
        result.push(s);

        for (x, y) in xs.iter().zip(ys.iter()).skip(1) {
            let res = Self::full_adder(g, x, y, &c)?;
            s = res.0;
            c = res.1;
            result.push(s);
        }

        Ok((result, c))
    }

    /// Binary addition. Returns just the result.
    fn bin_addition_no_carry<G: FancyBinary>(
        g: &mut G,
        xs: &[G::Item],
        ys: &[G::Item],
    ) -> Result<Vec<G::Item>, G::Error> {
        debug_assert_eq!(xs.len(), ys.len());
        if xs.len() == 1 {
            return Ok(vec![g.xor(&xs[0], &ys[0])?]);
        }

        let mut result = Vec::with_capacity(xs.len());

        let (mut s, mut c) = Self::half_adder(g, &xs[0], &ys[0])?;
        result.push(s);

        for (x, y) in xs.iter().zip(ys.iter()).take(xs.len() - 1).skip(1) {
            let res = Self::full_adder(g, x, y, &c)?;
            s = res.0;
            c = res.1;
            result.push(s);
        }

        // Finally, just the xor of the full_adder
        let z1 = g.xor(xs.last().unwrap(), ys.last().unwrap())?;
        let s = g.xor(&z1, &c)?;
        result.push(s);

        Ok(result)
    }

    /// Binary addition. Returns just the result.
    fn bin_addition_constant_no_carry<G: FancyBinary>(
        g: &mut G,
        xs: &[G::Item],
        ys: &[bool],
    ) -> Result<Vec<G::Item>, G::Error> {
        debug_assert_eq!(xs.len(), ys.len());
        if xs.len() == 1 {
            if ys[0] {
                return Ok(vec![g.negate(&xs[0])?]);
            } else {
                return Ok(vec![xs[0].clone()]);
            }
        }

        let mut result = Vec::with_capacity(xs.len());

        let (mut s, mut c) = Self::half_adder_const(g, &xs[0], ys[0])?;
        result.push(s);

        for (x, y) in xs.iter().zip(ys.iter()).take(xs.len() - 1).skip(1) {
            let res = Self::full_adder_const(g, x, *y, &c)?;
            s = res.0;
            c = res.1;
            result.push(s);
        }

        // Finally, just the xor of the full_adder
        let z1 = if *ys.last().unwrap() {
            g.negate(xs.last().unwrap())?
        } else {
            xs.last().unwrap().clone()
        };
        let s = g.xor(&z1, &c)?;
        result.push(s);

        Ok(result)
    }

    /// Binary subtraction. Returns the result and whether it underflowed.
    /// I.e., calculates 2^k + x1 - x2
    #[expect(clippy::type_complexity)]
    pub fn bin_subtraction<G: FancyBinary>(
        g: &mut G,
        xs: &[G::Item],
        ys: &[G::Item],
    ) -> Result<(Vec<G::Item>, G::Item), G::Error> {
        debug_assert_eq!(xs.len(), ys.len());
        let mut result = Vec::with_capacity(xs.len());
        // Twos complement is negation + 1, we implement by having cin in adder = 1, so only negation is required

        let y0 = g.negate(&ys[0])?;
        let (mut s, mut c) = Self::full_adder_cin_set(g, &xs[0], &y0)?;
        result.push(s);

        for (x, y) in xs.iter().zip(ys.iter()).skip(1) {
            let y = g.negate(y)?;
            let res = Self::full_adder(g, x, &y, &c)?;
            s = res.0;
            c = res.1;
            result.push(s);
        }

        Ok((result, c))
    }

    /// Needed for subtraction in binary division (for shared/shared) where xs is (conceptually) a constant 0 bundle with only some values set
    #[expect(clippy::type_complexity)]
    fn bin_subtraction_partial<G: FancyBinary>(
        g: &mut G,
        xs: &[G::Item],
        ys: &[G::Item],
    ) -> Result<(Vec<G::Item>, G::Item), G::Error> {
        let mut result = Vec::with_capacity(xs.len());
        // Twos complement is negation + 1, we implement by having cin in adder = 1, so only negation is required
        let length = xs.len();
        let y0 = g.negate(&ys[0])?;
        let (mut s, mut c) = Self::full_adder_cin_set(g, &xs[0], &y0)?;
        result.push(s);
        if xs.len() > 1 {
            for (x, y) in xs.iter().zip(ys.iter().take(xs.len())).skip(1) {
                let y = g.negate(y)?;
                let res = Self::full_adder(g, x, &y, &c)?;
                s = res.0;
                c = res.1;
                result.push(s);
            }
        }
        for y in ys[length..].iter() {
            let y = g.negate(y)?;
            // FULL ADDER with a=0 (x=0)
            s = g.xor(&y, &c)?;
            c = g.and(&y, &c)?;
            result.push(s);
        }
        Ok((result, c))
    }

    /// Needed for subtraction in binary division (for shared/public) where xs is (conceptually) a constant 0 bundle with only some values set and the subtrahend is a constant/public
    #[expect(clippy::type_complexity)]
    fn bin_subtraction_partial_by_constant<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        xs: &[G::Item],
        ys: &[bool],
    ) -> Result<(Vec<G::Item>, G::Item), G::Error> {
        let mut result = Vec::with_capacity(xs.len());
        // Twos complement is negation + 1, we implement by having cin in adder = 1, so only negation is required
        let length = xs.len();
        let y0 = &ys[0].not();
        let (mut s, mut c) = Self::full_adder_const_cin_set(g, &xs[0], *y0)?;
        result.push(s);
        if xs.len() > 1 {
            for (x, y) in xs.iter().zip(ys.iter().take(xs.len())).skip(1) {
                let y = y.not();
                let res = Self::full_adder_const(g, x, y, &c)?;
                s = res.0;
                c = res.1;
                result.push(s);
            }
        }
        for y in ys[length..].iter() {
            // FULL ADDER with a=0 (x=0)
            (s, c) = if *y {
                (c, g.const_zero()?)
            } else {
                (g.negate(&c)?, c)
            };
            result.push(s);
        }
        Ok((result, c))
    }

    /// Needed for subtraction in binary division (public/shared) where xs is (conceptually) a constant 0 bundle with only some constant/public values set
    #[expect(clippy::type_complexity)]
    fn bin_subtraction_partial_from_constant<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        xs: &[bool],
        ys: &[G::Item],
    ) -> Result<(Vec<G::Item>, G::Item), G::Error> {
        let mut result = Vec::with_capacity(xs.len());
        // Twos complement is negation + 1, we implement by having cin in adder = 1, so only negation is required
        let length = xs.len();
        let y0 = g.negate(&ys[0])?;
        let (mut s, mut c) = Self::full_adder_const_cin_set(g, &y0, xs[0])?;
        result.push(s);
        if xs.len() > 1 {
            for (x, y) in xs.iter().zip(ys.iter().take(xs.len())).skip(1) {
                let y = g.negate(y)?;
                let res = Self::full_adder_const(g, &y, *x, &c)?;
                s = res.0;
                c = res.1;
                result.push(s);
            }
        }
        if length < ys.len() {
            for y in ys[length..].iter() {
                let y = g.negate(y)?;
                // FULL ADDER with a=0 (x=0)
                s = g.xor(&y, &c)?;
                c = g.and(&y, &c)?;
                result.push(s);
            }
        }
        Ok((result, c))
    }

    /// Binary subtraction. Returns whether it underflowed.
    /// I.e., calculates the msb of 2^k + x1 - x2
    fn bin_subtraction_get_carry_only<G: FancyBinary>(
        g: &mut G,
        xs: &[G::Item],
        ys: &[G::Item],
    ) -> Result<G::Item, G::Error> {
        debug_assert_eq!(xs.len(), ys.len());
        // Twos complement is negation + 1, we implement by having cin in adder = 1, so only negation is required

        let y0 = g.negate(&ys[0])?;
        let mut c = Self::full_adder_carry_cin_set(g, &xs[0], &y0)?;

        for (x, y) in xs.iter().zip(ys.iter()).skip(1) {
            let y = g.negate(y)?;
            c = Self::full_adder_carry(g, x, &y, &c)?;
        }

        Ok(c)
    }

    // From swanky:
    /// Full multiplier with public value
    fn bin_mul_with_public<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        lhs: &[G::Item],
        rhs: &[bool],
    ) -> Result<Vec<G::Item>, G::Error> {
        let zero = g.const_zero()?;
        let mut sum = if rhs[0] {
            lhs.to_vec()
        } else {
            vec![zero.clone(); lhs.len()]
        };
        sum.push(zero.clone());
        for (i, item) in rhs.iter().enumerate().skip(1) {
            let mut mul = if *item {
                lhs.to_vec()
            } else {
                vec![zero.clone(); lhs.len()]
            };

            for _ in 0..i {
                mul.insert(0, zero.clone());
            }
            let res = Self::bin_addition(g, &sum, &mul)?;
            sum = res.0;
            sum.push(res.1);
        }

        Ok(sum)
    }

    // From swanky:
    /// Binary division
    fn bin_div<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        dividend: &[G::Item],
        divisor: &[G::Item],
    ) -> Result<Vec<G::Item>, G::Error> {
        let mut acc: Vec<G::Item> = Vec::with_capacity(dividend.len());
        let mut qs: Vec<G::Item> = vec![];
        for x in dividend.iter().rev() {
            if acc.len() == dividend.len() {
                acc.pop();
            }
            acc.insert(0, x.clone());

            let (res, cout) = Self::bin_subtraction_partial(g, &acc, divisor)?;

            acc = Self::bin_multiplex(g, &cout, &acc, &res)?;
            qs.push(cout);
        }
        qs.reverse(); // Switch back to little-endian
        Ok(qs)
    }

    // From swanky:
    /// Binary division by a public value
    fn bin_div_by_public<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        dividend: &[G::Item],
        divisor: &[bool],
    ) -> Result<Vec<G::Item>, G::Error> {
        let mut acc: Vec<G::Item> = Vec::with_capacity(dividend.len());
        let mut qs: Vec<G::Item> = vec![];
        for x in dividend.iter().rev() {
            if acc.len() == dividend.len() {
                acc.pop();
            }
            acc.insert(0, x.clone());

            let (res, cout) = Self::bin_subtraction_partial_by_constant(g, &acc, divisor)?;

            acc = Self::bin_multiplex(g, &cout, &acc, &res)?;
            qs.push(cout);
        }
        qs.reverse(); // Switch back to little-endian
        Ok(qs)
    }

    // From swanky:
    /// Binary division of a public by a shared value
    fn bin_div_by_shared<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        dividend: &[bool],
        divisor: &[G::Item],
    ) -> Result<Vec<G::Item>, G::Error> {
        let mut acc: Vec<bool> = vec![false; divisor.len() - 1];
        let mut acc_g;
        let mut qs: Vec<G::Item> = vec![];
        acc.insert(0, *dividend.last().unwrap());

        let (res, cout) = Self::bin_subtraction_partial_from_constant(g, &acc, divisor)?;

        acc_g = Self::bin_multiplex_const(g, &cout, &acc, &res)?;
        qs.push(cout);
        for x in dividend.iter().rev().skip(1) {
            if acc_g.len() == divisor.len() {
                acc_g.pop();
            }
            acc_g.insert(0, if *x { g.const_one()? } else { g.const_zero()? });
            let (res, cout) = Self::bin_subtraction(g, &acc_g, divisor)?;
            let mut acc_g_tmp = Vec::with_capacity(res.len());
            // this is the first part of the multiplex as the "first" entry is a public bool
            acc_g_tmp.insert(0, {
                if *x {
                    let cout_not = g.negate(&cout)?;
                    g.or(&cout_not, &res[0])?
                } else {
                    g.and(&cout, &res[0])?
                }
            });
            acc_g_tmp.extend(Self::bin_multiplex(g, &cout, &acc_g[1..], &res[1..])?);
            acc_g = acc_g_tmp;
            qs.push(cout);
        }
        qs.reverse(); // Switch back to little-endian
        Ok(qs)
    }

    /// Multiplex gadget for binary bundles
    fn bin_multiplex<G: FancyBinary>(
        g: &mut G,
        b: &G::Item,
        x: &[G::Item],
        y: &[G::Item],
    ) -> Result<Vec<G::Item>, G::Error> {
        x.iter()
            .zip(y.iter())
            .map(|(xwire, ywire)| g.mux(b, xwire, ywire))
            .collect::<Result<Vec<G::Item>, G::Error>>()
    }

    /// Multiplex gadget for public/shared
    fn bin_multiplex_const<G: FancyBinary>(
        g: &mut G,
        b: &G::Item,
        x: &[bool],
        y: &[G::Item],
    ) -> Result<Vec<G::Item>, G::Error> {
        x.iter()
            .zip(y.iter())
            .map(|(xwire, ywire)| {
                if *xwire {
                    let b_not = g.negate(b)?;
                    g.or(&b_not, ywire)
                } else {
                    g.and(b, ywire)
                }
            })
            .collect::<Result<Vec<G::Item>, G::Error>>()
    }

    /// Subtracts p from wires (with carry) and returns the result and the overflow bit.
    #[expect(clippy::type_complexity)]
    fn sub_p<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        wires: &[G::Item],
        carry: G::Item,
    ) -> Result<(Vec<G::Item>, G::Item), G::Error> {
        let bitlen = wires.len();
        debug_assert_eq!(bitlen, F::MODULUS_BIT_SIZE as usize);

        // Prepare p for subtraction
        let new_bitlen = bitlen + 1;
        let p_ = (BigUint::from(1u64) << new_bitlen) - F::MODULUS.into();
        let p_bits = GCUtils::biguint_to_bits(&p_, new_bitlen);

        // manual_rca:
        let mut subtracted = Vec::with_capacity(bitlen);
        // half_adder:
        debug_assert!(p_bits[0]);
        let s = g.negate(&wires[0])?;
        subtracted.push(s);
        let mut c = wires[0].to_owned();
        // full_adders:
        for (a, b) in wires.iter().zip(p_bits.iter()).skip(1) {
            let (s, c_) = Self::full_adder_const(g, a, *b, &c)?;
            c = c_;
            subtracted.push(s);
        }
        // final_full_adder to get ov bit
        let z = if p_bits[bitlen] {
            g.negate(&carry)?
        } else {
            carry
        };
        let ov = g.xor(&z, &c)?;

        Ok((subtracted, ov))
    }

    fn sub_p_and_mux_with_output_size<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        wires: &[G::Item],
        carry: G::Item,
        outlen: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        let (subtracted, ov) = Self::sub_p::<_, F>(g, wires, carry)?;

        // multiplex for result
        let mut result = Vec::with_capacity(outlen);
        for (s, a) in subtracted.iter().zip(wires.iter()).take(outlen) {
            // CMUX
            let r = g.mux(&ov, s, a)?;
            result.push(r);
        }

        Ok(result)
    }

    /// Adds two shared field elements mod p. The field elements are encoded as Yao shared wires. The output is only of size outlen.
    fn adder_mod_p_with_output_size<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        wires_a: &[G::Item],
        wires_b: &[G::Item],
        outlen: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        let bitlen = wires_a.len();
        debug_assert_eq!(bitlen, wires_b.len());
        debug_assert_eq!(bitlen, F::MODULUS_BIT_SIZE as usize);

        // First addition
        let (added, carry_add) = Self::bin_addition(g, wires_a, wires_b)?;

        let result = Self::sub_p_and_mux_with_output_size::<_, F>(g, &added, carry_add, outlen)?;
        Ok(result)
    }

    /// Adds two shared field elements mod p. The field elements are encoded as Yao shared wires.
    pub fn adder_mod_p<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        wires_a: &BinaryBundle<G::Item>,
        wires_b: &BinaryBundle<G::Item>,
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        let bitlen = wires_a.size();
        debug_assert_eq!(bitlen, wires_b.size());
        let res = Self::adder_mod_p_with_output_size::<_, F>(
            g,
            wires_a.wires(),
            wires_b.wires(),
            bitlen,
        )?;
        Ok(BinaryBundle::new(res))
    }

    /// Adds two vectors of shared field elements mod p. The field elements are encoded as Yao shared wires.
    pub fn adder_mod_p_many<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        wires_a: &BinaryBundle<G::Item>,
        wires_b: &BinaryBundle<G::Item>,
    ) -> Result<Vec<BinaryBundle<G::Item>>, G::Error> {
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        let mut results = Vec::with_capacity(wires_a.size() / input_bitlen);
        for (chunk_a, chunk_b) in izip!(
            wires_a.wires().chunks(input_bitlen),
            wires_b.wires().chunks(input_bitlen),
        ) {
            results.push(BinaryBundle::new(
                Self::adder_mod_p_with_output_size::<_, F>(g, chunk_a, chunk_b, input_bitlen)?,
            ));
        }
        Ok(results)
    }

    /// Adds two shared ring elements mod 2^k. The ring elements are encoded as Yao shared wires.
    pub fn adder_mod_2k<G: FancyBinary>(
        g: &mut G,
        wires_a: &BinaryBundle<G::Item>,
        wires_b: &BinaryBundle<G::Item>,
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        debug_assert_eq!(wires_a.size(), wires_b.size());
        let res = Self::bin_addition_no_carry(g, wires_a.wires(), wires_b.wires())?;
        Ok(BinaryBundle::new(res))
    }

    /// XORs two bundles of wires. Does not require any network interaction.
    pub(crate) fn xor_many<G: FancyBinary>(
        g: &mut G,
        wires_a: &BinaryBundle<G::Item>,
        wires_b: &BinaryBundle<G::Item>,
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        let bitlen = wires_a.size();
        debug_assert_eq!(bitlen, wires_b.size());

        let mut result = Vec::with_capacity(wires_a.size());
        for (a, b) in wires_a.wires().iter().zip(wires_b.wires().iter()) {
            let r = g.xor(a, b)?;
            result.push(r);
        }
        Ok(BinaryBundle::new(result))
    }

    /// XORs two bundles of wires. Does not require any network interaction.
    pub(crate) fn xor_many_as_wires<G: FancyBinary>(
        g: &mut G,
        wires_a: &[G::Item],
        wires_b: &[G::Item],
    ) -> Result<Vec<G::Item>, G::Error> {
        let bitlen = wires_a.len();
        debug_assert_eq!(bitlen, wires_b.len());

        let mut result = Vec::with_capacity(wires_a.len());
        for (a, b) in wires_a.iter().zip(wires_b.iter()) {
            let r = g.xor(a, b)?;
            result.push(r);
        }
        Ok(result)
    }

    fn compose_field_element<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        field_wires: &[G::Item],
        rand_wires: &[G::Item],
    ) -> Result<Vec<G::Item>, G::Error> {
        let input_bitlen = field_wires.len();
        debug_assert!(input_bitlen <= F::MODULUS_BIT_SIZE as usize);
        debug_assert_eq!(rand_wires.len(), F::MODULUS_BIT_SIZE as usize);
        // compose chunk_bits again
        // For the bin addition, our input is not of size F::ModulusBitSize, thus we can optimize a little bit

        if field_wires.is_empty() {
            return Ok(rand_wires.to_owned());
        }

        let mut added = Vec::with_capacity(input_bitlen);

        let xs = field_wires;
        let ys = rand_wires;

        let (mut s, mut c) = Self::half_adder(g, &xs[0], &ys[0])?;
        added.push(s);

        for (x, y) in xs.iter().zip(ys.iter()).skip(1) {
            let res = Self::full_adder(g, x, y, &c)?;
            s = res.0;
            c = res.1;
            added.push(s);
        }
        for y in ys.iter().skip(xs.len()) {
            let res = Self::full_adder_const(g, y, false, &c)?;
            s = res.0;
            c = res.1;
            added.push(s);
        }

        Self::sub_p_and_mux_with_output_size::<_, F>(g, &added, c, F::MODULUS_BIT_SIZE as usize)
    }

    /// Decomposes a field element (represented as two bitdecompositions wires_a, wires_b which need to be added first) into a vector of num_decomposition ring elements of size decompose_bitlen. For the bitcomposition, wires_c are used.
    fn decompose_field_element_to_rings<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        wires_a: &[G::Item],
        wires_b: &[G::Item],
        wires_c: &[G::Item],
        num_decomps_per_field: usize,
        decompose_bitlen: usize,
        output_bitlen: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        let total_output_bitlen = decompose_bitlen * num_decomps_per_field;
        debug_assert_eq!(wires_a.len(), wires_b.len());
        let input_bitlen = wires_a.len();
        debug_assert_eq!(input_bitlen, F::MODULUS_BIT_SIZE as usize);
        debug_assert!(decompose_bitlen <= total_output_bitlen);
        debug_assert_eq!(wires_c.len(), output_bitlen * num_decomps_per_field);
        debug_assert!(output_bitlen >= decompose_bitlen);

        let input_bits =
            Self::adder_mod_p_with_output_size::<_, F>(g, wires_a, wires_b, total_output_bitlen)?;

        let mut results = Vec::with_capacity(wires_c.len());

        for (xs, ys) in izip!(
            input_bits.chunks(decompose_bitlen),
            wires_c.chunks(output_bitlen),
        ) {
            // compose chunk_bits again
            // For the bin addition, our input is not guaranteed to be of size output_bitlen, thus we can optimize a little bit in some cases

            let mut added = Vec::with_capacity(output_bitlen);

            let (mut s, mut c) = Self::half_adder(g, &xs[0], &ys[0])?;
            added.push(s);

            if ys.len() == 1 {
                results.extend(added);
                continue;
            }

            for (x, y) in xs.iter().zip(ys.iter()).take(ys.len() - 1).skip(1) {
                let res = Self::full_adder(g, x, y, &c)?;
                s = res.0;
                c = res.1;
                added.push(s);
            }
            for y in ys.iter().take(ys.len() - 1).skip(xs.len()) {
                let res = Self::full_adder_const(g, y, false, &c)?;
                s = res.0;
                c = res.1;
                added.push(s);
            }

            // Finally, just the xor of the full_adder
            if xs.len() == ys.len() {
                let z1 = g.xor(xs.last().unwrap(), ys.last().unwrap())?;
                let s = g.xor(&z1, &c)?;
                added.push(s);
            } else {
                added.push(g.xor(ys.last().unwrap(), &c)?);
            }
            results.extend(added);
        }

        Ok(results)
    }

    /// Decomposes a vector of field elements (represented as two bitdecompositions wires_a, wires_b which need to be added first) into a vector of num_decomposition ring elements of size decompose_bitlen. For the bitcomposition, wires_c are used.
    pub(crate) fn decompose_field_element_to_rings_many<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        wires_a: &BinaryBundle<G::Item>,
        wires_b: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        num_decomps_per_field: usize,
        decompose_bitlen: usize,
        output_bitlen: usize,
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        debug_assert_eq!(wires_a.size(), wires_b.size());
        let input_size = wires_a.size();
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        let num_inputs = input_size / input_bitlen;

        let total_output_bitlen_per_field = decompose_bitlen * num_decomps_per_field;
        let total_output_elements = num_decomps_per_field * num_inputs;

        debug_assert_eq!(input_size % input_bitlen, 0);
        debug_assert!(decompose_bitlen <= total_output_bitlen_per_field);
        debug_assert!(output_bitlen >= decompose_bitlen);
        debug_assert_eq!(wires_c.size(), output_bitlen * total_output_elements);

        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_a, chunk_b, chunk_c) in izip!(
            wires_a.wires().chunks(input_bitlen),
            wires_b.wires().chunks(input_bitlen),
            wires_c
                .wires()
                .chunks(output_bitlen * num_decomps_per_field)
        ) {
            let decomposed = Self::decompose_field_element_to_rings::<_, F>(
                g,
                chunk_a,
                chunk_b,
                chunk_c,
                num_decomps_per_field,
                decompose_bitlen,
                output_bitlen,
            )?;
            results.extend(decomposed);
        }

        Ok(BinaryBundle::new(results))
    }

    /// Decomposes a field element (represented as two bitdecompositions wires_a, wires_b which need to be added first) into a vector of num_decomposition field elements of size decompose_bitlen. For the bitcomposition, wires_c are used.
    fn decompose_field_element<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        wires_a: &[G::Item],
        wires_b: &[G::Item],
        wires_c: &[G::Item],
        decompose_bitlen: usize,
        total_output_bitlen: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        let num_decomps_per_field = total_output_bitlen.div_ceil(decompose_bitlen);
        debug_assert_eq!(wires_a.len(), wires_b.len());
        let input_bitlen = wires_a.len();
        debug_assert_eq!(input_bitlen, F::MODULUS_BIT_SIZE as usize);
        debug_assert!(input_bitlen >= total_output_bitlen);
        debug_assert!(decompose_bitlen <= total_output_bitlen);
        debug_assert_eq!(wires_c.len(), input_bitlen * num_decomps_per_field);

        let input_bits =
            Self::adder_mod_p_with_output_size::<_, F>(g, wires_a, wires_b, total_output_bitlen)?;

        let mut results = Vec::with_capacity(wires_c.len());

        for (xs, ys) in izip!(
            input_bits.chunks(decompose_bitlen),
            wires_c.chunks(input_bitlen),
        ) {
            let result = Self::compose_field_element::<_, F>(g, xs, ys)?;
            results.extend(result);
        }

        Ok(results)
    }

    /// Decomposes a vector of field elements (represented as two bitdecompositions wires_a, wires_b which need to be added first) into a vector of num_decomposition field elements of size decompose_bitlen. For the bitcomposition, wires_c are used.
    pub(crate) fn decompose_field_element_many<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        wires_a: &BinaryBundle<G::Item>,
        wires_b: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        decompose_bitlen: usize,
        total_output_bitlen_per_field: usize,
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        debug_assert_eq!(wires_a.size(), wires_b.size());
        let input_size = wires_a.size();
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        let num_inputs = input_size / input_bitlen;

        let num_decomps_per_field = total_output_bitlen_per_field.div_ceil(decompose_bitlen);
        let total_output_elements = num_decomps_per_field * num_inputs;

        debug_assert_eq!(input_size % input_bitlen, 0);
        debug_assert!(input_bitlen >= total_output_bitlen_per_field);
        debug_assert!(decompose_bitlen <= total_output_bitlen_per_field);
        debug_assert_eq!(wires_c.size(), input_bitlen * total_output_elements);

        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_a, chunk_b, chunk_c) in izip!(
            wires_a.wires().chunks(input_bitlen),
            wires_b.wires().chunks(input_bitlen),
            wires_c.wires().chunks(input_bitlen * num_decomps_per_field)
        ) {
            let decomposed = Self::decompose_field_element::<_, F>(
                g,
                chunk_a,
                chunk_b,
                chunk_c,
                decompose_bitlen,
                total_output_bitlen_per_field,
            )?;
            results.extend(decomposed);
        }

        Ok(BinaryBundle::new(results))
    }

    /// Decomposes a field element (represented as two bitdecompositions wires_a, wires_b which need to be added first) into a vector of num_decomposition field elements of size decompose_bitlen. For the bitcomposition, wires_c are used.
    fn decompose_field_element_to_other_field<G: FancyBinary, F: PrimeField, K: PrimeField>(
        g: &mut G,
        wires_a: &[G::Item],
        wires_b: &[G::Item],
        wires_c: &[G::Item],
        decompose_bitlen: usize,
        total_output_bitlen: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        let num_decomps_per_field = total_output_bitlen.div_ceil(decompose_bitlen);
        debug_assert_eq!(wires_a.len(), wires_b.len());
        let input_bitlen = wires_a.len();
        let output_bitlen = K::MODULUS_BIT_SIZE as usize;
        debug_assert_eq!(input_bitlen, F::MODULUS_BIT_SIZE as usize);
        debug_assert!(input_bitlen >= total_output_bitlen);
        debug_assert!(decompose_bitlen <= total_output_bitlen);
        debug_assert_eq!(wires_c.len(), input_bitlen * num_decomps_per_field);

        let input_bits =
            Self::adder_mod_p_with_output_size::<_, F>(g, wires_a, wires_b, total_output_bitlen)?;

        let mut results = Vec::with_capacity(wires_c.len());

        for (xs, ys) in izip!(
            input_bits.chunks(decompose_bitlen),
            wires_c.chunks(output_bitlen),
        ) {
            let result = Self::compose_field_element::<_, K>(g, xs, ys)?;
            results.extend(result);
        }

        Ok(results)
    }

    /// Decomposes a vector of field elements (represented as two bitdecompositions wires_a, wires_b which need to be added first) into a vector of num_decomposition field elements of size decompose_bitlen. For the bitcomposition, wires_c are used.
    pub(crate) fn decompose_field_element_to_other_field_many<
        G: FancyBinary,
        F: PrimeField,
        K: PrimeField,
    >(
        g: &mut G,
        wires_a: &BinaryBundle<G::Item>,
        wires_b: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        decompose_bitlen: usize,
        total_output_bitlen_per_field: usize,
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        debug_assert_eq!(wires_a.size(), wires_b.size());
        let input_size = wires_a.size();
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        let output_bitlen = K::MODULUS_BIT_SIZE as usize;
        let num_inputs = input_size / input_bitlen;

        let num_decomps_per_field = total_output_bitlen_per_field.div_ceil(decompose_bitlen);
        let total_output_elements = num_decomps_per_field * num_inputs;

        debug_assert_eq!(input_size % input_bitlen, 0);
        debug_assert!(input_bitlen >= total_output_bitlen_per_field);
        debug_assert!(decompose_bitlen <= total_output_bitlen_per_field);
        debug_assert_eq!(wires_c.size(), input_bitlen * total_output_elements);

        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_a, chunk_b, chunk_c) in izip!(
            wires_a.wires().chunks(input_bitlen),
            wires_b.wires().chunks(input_bitlen),
            wires_c
                .wires()
                .chunks(output_bitlen * num_decomps_per_field)
        ) {
            let decomposed = Self::decompose_field_element_to_other_field::<_, F, K>(
                g,
                chunk_a,
                chunk_b,
                chunk_c,
                decompose_bitlen,
                total_output_bitlen_per_field,
            )?;
            results.extend(decomposed);
        }

        Ok(BinaryBundle::new(results))
    }

    /// Slices a field element (represented as two bitdecompositions wires_a, wires_b which need to be added first) at given indices (lo, mid), into lo and hi, where lo has all bits from lsb to (excluding) msb and hi all bits from msb up to bitsize.. For the bitcomposition, wires_c are used.
    fn slice_field_element<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        wires_a: &[G::Item],
        wires_b: &[G::Item],
        wires_c: &[G::Item],
        lo: usize,
        mid: usize,
        bitsize: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        debug_assert_eq!(wires_a.len(), wires_b.len());
        let input_bitlen = wires_a.len();
        debug_assert_eq!(input_bitlen, F::MODULUS_BIT_SIZE as usize);
        debug_assert!(input_bitlen >= bitsize);
        debug_assert!(mid >= lo);
        debug_assert!(mid < bitsize);
        debug_assert_eq!(wires_c.len(), input_bitlen * 2);

        let input_bits = Self::adder_mod_p_with_output_size::<_, F>(g, wires_a, wires_b, bitsize)?;
        let mut rands = wires_c.chunks(input_bitlen);

        let lo =
            Self::compose_field_element::<_, F>(g, &input_bits[lo..mid], rands.next().unwrap())?;

        let hi = Self::compose_field_element::<_, F>(g, &input_bits[mid..], rands.next().unwrap())?;

        let mut results = lo;
        results.extend(hi);

        Ok(results)
    }

    /// Slices a vector of field elements (represented as two bitdecompositions wires_a, wires_b which need to be added first) at given indices (lo, mid), into lo and hi, where lo has all bits from lsb to (excluding) msb and hi all bits from msb up to bitsize.. For the bitcomposition, wires_c are used.
    pub(crate) fn slice_field_element_many<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        wires_a: &BinaryBundle<G::Item>,
        wires_b: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        lo: usize,
        mid: usize,
        bitsize: usize,
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        debug_assert_eq!(wires_a.size(), wires_b.size());
        let input_size = wires_a.size();
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        let num_inputs = input_size / input_bitlen;

        let total_output_elements = 2 * num_inputs;

        debug_assert_eq!(input_size % input_bitlen, 0);
        debug_assert!(input_bitlen >= bitsize);
        debug_assert!(lo <= mid);
        debug_assert!(lo < bitsize);
        debug_assert_eq!(wires_c.size(), input_bitlen * total_output_elements);

        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_a, chunk_b, chunk_c) in izip!(
            wires_a.wires().chunks(input_bitlen),
            wires_b.wires().chunks(input_bitlen),
            wires_c.wires().chunks(input_bitlen * 2)
        ) {
            let sliced =
                Self::slice_field_element::<_, F>(g, chunk_a, chunk_b, chunk_c, lo, mid, bitsize)?;
            results.extend(sliced);
        }

        Ok(BinaryBundle::new(results))
    }

    fn unsigned_ge<G: FancyBinary>(
        g: &mut G,
        a: &[G::Item],
        b: &[G::Item],
    ) -> Result<G::Item, G::Error> {
        debug_assert_eq!(a.len(), b.len());
        Self::bin_subtraction_get_carry_only(g, a, b)
    }

    fn unsigned_lt<G: FancyBinary>(
        g: &mut G,
        a: &[G::Item],
        b: &[G::Item],
    ) -> Result<G::Item, G::Error> {
        let ge = Self::unsigned_ge(g, a, b)?;
        g.negate(&ge)
    }

    #[expect(dead_code)]
    fn unsigned_le<G: FancyBinary>(
        g: &mut G,
        a: &[G::Item],
        b: &[G::Item],
    ) -> Result<G::Item, G::Error> {
        Self::unsigned_ge(g, b, a)
    }

    fn unsigned_gt<G: FancyBinary>(
        g: &mut G,
        a: &[G::Item],
        b: &[G::Item],
    ) -> Result<G::Item, G::Error> {
        Self::unsigned_lt(g, b, a)
    }

    fn batcher_odd_even_merge_sort_inner<G: FancyBinary>(
        g: &mut G,
        inputs: &mut [Vec<G::Item>],
    ) -> Result<(), G::Error>
    where
        G::Item: Default,
    {
        debug_assert!(!inputs.is_empty());
        let len = inputs.len();
        let inner_len = inputs[0].len();
        let mut lhs_result = vec![G::Item::default(); inner_len];
        let mut rhs_result = vec![G::Item::default(); inner_len];

        let mut p = 1;
        while p < len {
            let mut k = p;
            while k >= 1 {
                for j in (k % p..len - k).step_by(2 * k) {
                    for i in 0..std::cmp::min(k, len - j - k) {
                        if (i + j) / (2 * p) == (i + j + k) / (2 * p) {
                            {
                                let lhs = &inputs[i + j];
                                let rhs = &inputs[i + j + k];
                                debug_assert_eq!(lhs.len(), rhs.len());
                                debug_assert_eq!(lhs.len(), inner_len);

                                let cmp = Self::unsigned_gt(g, lhs, rhs)?;

                                for (l, r, l_res, r_res) in izip!(
                                    lhs.iter(),
                                    rhs.iter(),
                                    lhs_result.iter_mut(),
                                    rhs_result.iter_mut()
                                ) {
                                    // This is a cmux, setting lres to l if cmp is 0, else r
                                    let xor = g.xor(l, r)?;
                                    let and = g.and(&cmp, &xor)?;
                                    *l_res = g.xor(&and, l)?;
                                    // sets r_res to the opposite of l_res
                                    *r_res = g.xor(&xor, l_res)?;
                                }
                            }
                            inputs[i + j].clone_from_slice(&lhs_result);
                            inputs[i + j + k].clone_from_slice(&rhs_result);
                        }
                    }
                }
                k >>= 1;
            }
            p <<= 1;
        }

        Ok(())
    }

    /// Sorts a vector of field elements (represented as two bitdecompositions wires_a, wires_b which need to be added first). Thereby, only bitsize bits are used in sorting. Finally, the sorted vector is composed to shared field elements using wires_c.
    pub(crate) fn batcher_odd_even_merge_sort<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        wires_a: &BinaryBundle<G::Item>,
        wires_b: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        bitlen: usize,
    ) -> Result<BinaryBundle<G::Item>, G::Error>
    where
        G::Item: Default,
    {
        debug_assert_eq!(wires_a.size(), wires_b.size());
        debug_assert_eq!(wires_a.size(), wires_c.size());
        let input_size = wires_a.size();
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        let num_inputs = input_size / input_bitlen;

        debug_assert_eq!(input_size % input_bitlen, 0);
        debug_assert!(input_bitlen >= bitlen);

        // Add wires_a and wires_b to get the input bits as Yao wires
        let mut inputs = Vec::with_capacity(num_inputs);
        for (chunk_a, chunk_b) in izip!(
            wires_a.wires().chunks(input_bitlen),
            wires_b.wires().chunks(input_bitlen),
        ) {
            let input_bits =
                Self::adder_mod_p_with_output_size::<_, F>(g, chunk_a, chunk_b, bitlen)?;
            inputs.push(input_bits);
        }

        // Perform the actual sorting
        Self::batcher_odd_even_merge_sort_inner(g, &mut inputs)?;

        // Add each field element to wires_c for the composition
        let mut results = Vec::with_capacity(input_size);
        for (xs, ys) in izip!(inputs, wires_c.wires().chunks(input_bitlen),) {
            let result = Self::compose_field_element::<_, F>(g, &xs, ys)?;
            results.extend(result);
        }

        Ok(BinaryBundle::new(results))
    }

    /// Transforms a field_sharing (represented as two bitdecompositions wires_a, wires_b which need to be added first) to a sharing of a ring. The ring share is composed using wires_c.
    fn field_to_ring<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        wires_a: &[G::Item],
        wires_b: &[G::Item],
        wires_c: &[G::Item],
    ) -> Result<Vec<G::Item>, G::Error> {
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        let output_bitlen = wires_c.len();
        debug_assert_eq!(input_bitlen, wires_a.len());
        debug_assert_eq!(input_bitlen, wires_b.len());
        debug_assert!(output_bitlen <= input_bitlen);

        // Add wires_a and wires_b to get the input bits as Yao wires
        let input_bits =
            Self::adder_mod_p_with_output_size::<_, F>(g, wires_a, wires_b, output_bitlen)?;
        Self::bin_addition_no_carry(g, &input_bits, wires_c)
    }

    /// Transforms a vector of field_sharings (represented as two bitdecompositions wires_a, wires_b which need to be added first) to a sharing vector of rings. The ring shares are composed using wires_c.
    pub(crate) fn field_to_ring_many<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        wires_a: &BinaryBundle<G::Item>,
        wires_b: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        output_bitlen: usize,
    ) -> Result<BinaryBundle<G::Item>, G::Error>
    where
        G::Item: Default,
    {
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        debug_assert_eq!(wires_a.size(), wires_b.size());
        let input_size = wires_a.size();
        let num_inputs = input_size / input_bitlen;

        debug_assert_eq!(input_size % input_bitlen, 0);
        debug_assert_eq!(wires_c.size(), num_inputs * output_bitlen);

        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_a, chunk_b, chunk_c) in izip!(
            wires_a.wires().chunks(input_bitlen),
            wires_b.wires().chunks(input_bitlen),
            wires_c.wires().chunks(output_bitlen),
        ) {
            results.extend(Self::field_to_ring::<_, F>(g, chunk_a, chunk_b, chunk_c)?);
        }

        Ok(BinaryBundle::new(results))
    }

    /// Transforms a ring_sharing (represented as two bitdecompositions wires_a, wires_b which need to be added first) to a sharing of a field. The field share is composed using wires_c.
    fn ring_to_field<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        wires_a: &[G::Item],
        wires_b: &[G::Item],
        wires_c: &[G::Item],
    ) -> Result<Vec<G::Item>, G::Error> {
        let input_bitlen = wires_a.len();
        let output_bitlen = F::MODULUS_BIT_SIZE as usize;
        debug_assert_eq!(input_bitlen, wires_b.len());
        debug_assert_eq!(wires_c.len(), output_bitlen);

        // Add wires_a and wires_b to get the input bits as Yao wires
        let input_bits = Self::bin_addition_no_carry(g, wires_a, wires_b)?;
        Self::compose_field_element::<_, F>(g, &input_bits, wires_c)
    }

    /// Transforms a vector of ring_sharings (represented as two bitdecompositions wires_a, wires_b which need to be added first) to a sharing vector of fields. The field shares are composed using wires_c.
    pub(crate) fn ring_to_field_many<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        wires_a: &BinaryBundle<G::Item>,
        wires_b: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        input_bitlen: usize,
    ) -> Result<BinaryBundle<G::Item>, G::Error>
    where
        G::Item: Default,
    {
        debug_assert_eq!(wires_a.size(), wires_b.size());
        let input_size = wires_a.size();
        let num_inputs = input_size / input_bitlen;

        debug_assert_eq!(input_size % input_bitlen, 0);
        let output_bitlen = F::MODULUS_BIT_SIZE as usize;
        debug_assert_eq!(wires_c.size(), num_inputs * output_bitlen);

        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_a, chunk_b, chunk_c) in izip!(
            wires_a.wires().chunks(input_bitlen),
            wires_b.wires().chunks(input_bitlen),
            wires_c.wires().chunks(output_bitlen),
        ) {
            results.extend(Self::ring_to_field::<_, F>(g, chunk_a, chunk_b, chunk_c)?);
        }

        Ok(BinaryBundle::new(results))
    }

    /// Transforms a ring_sharing (represented as two bitdecompositions wires_a, wires_b which need to be added first) to a sharing of another ring. The output ring share is composed using wires_c.
    fn ring_to_ring_upcast<G: FancyBinary>(
        g: &mut G,
        wires_a: &[G::Item],
        wires_b: &[G::Item],
        wires_c: &[G::Item],
    ) -> Result<Vec<G::Item>, G::Error> {
        let input_bitlen = wires_a.len();
        let output_bitlen = wires_c.len();
        debug_assert_eq!(input_bitlen, wires_b.len());
        debug_assert!(output_bitlen > input_bitlen);

        // Add wires_a and wires_b to get the input bits as Yao wires
        let input_bits = Self::bin_addition_no_carry(g, wires_a, wires_b)?;

        // compose chunk_bits again
        // For the bin addition, our input is not of size output_bitlen, thus we can optimize a little bit

        let mut added = Vec::with_capacity(input_bitlen);

        let xs = input_bits;
        let ys = wires_c;
        let (mut s, mut c) = Self::half_adder(g, &xs[0], &ys[0])?;
        added.push(s);

        for (x, y) in xs.iter().zip(ys.iter()).skip(1) {
            let res = Self::full_adder(g, x, y, &c)?;
            s = res.0;
            c = res.1;
            added.push(s);
        }
        for y in ys.iter().take(ys.len() - 1).skip(xs.len()) {
            let res = Self::full_adder_const(g, y, false, &c)?;
            s = res.0;
            c = res.1;
            added.push(s);
        }

        // Finally, just the xor of the full_adder, where x is 0...
        let s = g.xor(ys.last().unwrap(), &c)?;
        added.push(s);
        Ok(added)
    }

    /// Transforms a vector of ring_sharings (represented as two bitdecompositions wires_a, wires_b which need to be added first) to a sharing vector of another ring. The output ring shares are composed using wires_c.
    pub(crate) fn ring_to_ring_upcast_many<G: FancyBinary>(
        g: &mut G,
        wires_a: &BinaryBundle<G::Item>,
        wires_b: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        input_bitlen: usize,
        output_bitlen: usize,
    ) -> Result<BinaryBundle<G::Item>, G::Error>
    where
        G::Item: Default,
    {
        debug_assert_eq!(wires_a.size(), wires_b.size());
        let input_size = wires_a.size();
        let num_inputs = input_size / input_bitlen;

        debug_assert_eq!(input_size % input_bitlen, 0);
        debug_assert_eq!(wires_c.size(), num_inputs * output_bitlen);

        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_a, chunk_b, chunk_c) in izip!(
            wires_a.wires().chunks(input_bitlen),
            wires_b.wires().chunks(input_bitlen),
            wires_c.wires().chunks(output_bitlen),
        ) {
            results.extend(Self::ring_to_ring_upcast(g, chunk_a, chunk_b, chunk_c)?);
        }

        Ok(BinaryBundle::new(results))
    }

    /// Divides a ring element by a power of 2. The ring element is represented as two bitdecompositions wires_a, wires_b which need to be added first. The output is composed using wires_c, whereas wires_c are the same size as wires_a and wires_b.
    fn ring_div_power_2<G: FancyBinary>(
        g: &mut G,
        wires_a: &[G::Item],
        wires_b: &[G::Item],
        wires_c: &[G::Item],
        divisor_bit: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        let input_bitlen = wires_a.len();
        debug_assert_eq!(input_bitlen, wires_b.len());
        debug_assert_eq!(input_bitlen, wires_c.len());
        debug_assert!(divisor_bit < input_bitlen);
        debug_assert!(divisor_bit > 0);

        // Add wires_a and wires_b to get the input bits as Yao wires
        // TODO we do some XORs too much since we do not need the s-values for the first divisor_bit bits. However, this does not effect communication
        let input_bits = Self::bin_addition_no_carry(g, wires_a, wires_b)?;

        // compose chunk_bits again
        // For the bin addition, our input is not of size input_bitlen, thus we can optimize a little bit

        let mut added = Vec::with_capacity(input_bitlen);

        let xs = &input_bits[divisor_bit..];
        let ys = wires_c;
        let (mut s, mut c) = Self::half_adder(g, &xs[0], &ys[0])?;
        added.push(s);

        for (x, y) in xs.iter().zip(ys.iter()).skip(1) {
            let res = Self::full_adder(g, x, y, &c)?;
            s = res.0;
            c = res.1;
            added.push(s);
        }
        for y in ys.iter().take(ys.len() - 1).skip(xs.len()) {
            let res = Self::full_adder_const(g, y, false, &c)?;
            s = res.0;
            c = res.1;
            added.push(s);
        }

        // Finally, just the xor of the full_adder, where x is 0...
        let s = g.xor(ys.last().unwrap(), &c)?;
        added.push(s);
        Ok(added)
    }

    /// Divides a field element by a power of 2. The field element is represented as two bitdecompositions wires_a, wires_b which need to be added first. The output is composed using wires_c, whereas wires_c are the same size as wires_a and wires_b.
    fn field_int_div_power_2<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        wires_a: &[G::Item],
        wires_b: &[G::Item],
        wires_c: &[G::Item],
        divisor_bit: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        let input_bitlen = wires_a.len();
        let n_bits = F::MODULUS_BIT_SIZE as usize;
        assert_eq!(input_bitlen, n_bits);
        debug_assert_eq!(input_bitlen, wires_b.len());
        debug_assert_eq!(input_bitlen, wires_c.len());
        debug_assert!(divisor_bit < input_bitlen);
        debug_assert!(divisor_bit > 0);

        // Add wires_a and wires_b to get the input bits as Yao wires
        let (added, carry_add) = Self::bin_addition(g, wires_a, wires_b)?;
        let (subtracted, ov) = Self::sub_p::<_, F>(g, &added, carry_add)?;

        // multiplex for result
        let mut input_bits = Vec::with_capacity(input_bitlen - divisor_bit);
        for (s, a) in subtracted.iter().zip(added.iter()).skip(divisor_bit) {
            // CMUX
            let r = g.mux(&ov, s, a)?;
            input_bits.push(r);
        }

        // compose chunk_bits again
        let result = Self::compose_field_element::<G, F>(g, &input_bits, wires_c)?;

        Ok(result)
    }

    /// Divides a ring element by another. The ring elements are represented as bitdecompositions x1s, x2s, y1s and y2s which need to be added first. The output is composed using wires_c, whereas wires_c are the same size as the input wires.
    fn ring_div<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        x1s: &[G::Item],
        x2s: &[G::Item],
        y1s: &[G::Item],
        y2s: &[G::Item],
        wires_c: &[G::Item],
        input_bitlen: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        let dividend = Self::bin_addition_no_carry(g, x1s, x2s)?;
        let divisor = Self::bin_addition_no_carry(g, y1s, y2s)?;

        debug_assert_eq!(dividend.len(), input_bitlen);
        debug_assert_eq!(dividend.len(), divisor.len());
        let quotient = Self::bin_div(g, &dividend, &divisor)?;

        let mut added = Vec::with_capacity(input_bitlen);
        let ys = wires_c;
        let (mut s, mut c) = Self::half_adder(g, &quotient[0], &ys[0])?;
        added.push(s);

        for (x, y) in quotient.iter().zip(ys.iter()).skip(1) {
            let res = Self::full_adder(g, x, y, &c)?;
            s = res.0;
            c = res.1;
            added.push(s);
        }
        for y in ys.iter().take(ys.len() - 1).skip(quotient.len()) {
            let res = Self::full_adder_const(g, y, false, &c)?;
            s = res.0;
            c = res.1;
            added.push(s);
        }
        Ok(added)
    }

    /// Divides a ring element by another public ring element. The ring element is represented as bitdecompositions x1s and x2s which need to be added first. The output is composed using wires_c, whereas wires_c are the same size as the input wires.
    fn ring_div_by_public<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        x1s: &[G::Item],
        x2s: &[G::Item],
        divisor: &[bool],
        wires_c: &[G::Item],
        input_bitlen: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        let dividend = Self::bin_addition_no_carry(g, x1s, x2s)?;

        debug_assert_eq!(dividend.len(), input_bitlen);
        debug_assert_eq!(dividend.len(), divisor.len());
        let quotient = Self::bin_div_by_public(g, &dividend, divisor)?;

        let mut added = Vec::with_capacity(input_bitlen);
        let ys = wires_c;
        let (mut s, mut c) = Self::half_adder(g, &quotient[0], &ys[0])?;
        added.push(s);

        for (x, y) in quotient.iter().zip(ys.iter()).skip(1) {
            let res = Self::full_adder(g, x, y, &c)?;
            s = res.0;
            c = res.1;
            added.push(s);
        }
        for y in ys.iter().take(ys.len() - 1).skip(quotient.len()) {
            let res = Self::full_adder_const(g, y, false, &c)?;
            s = res.0;
            c = res.1;
            added.push(s);
        }
        Ok(added)
    }

    /// Divides a public ring element by another shared ring element. The ring element is represented as bitdecompositions x1s and x2s which need to be added first. The output is composed using wires_c, whereas wires_c are the same size as the input wires.
    fn ring_div_by_shared<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        x1s: &[G::Item],
        x2s: &[G::Item],
        dividend: &[bool],
        wires_c: &[G::Item],
        input_bitlen: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        let divisor = Self::bin_addition_no_carry(g, x1s, x2s)?;

        debug_assert_eq!(dividend.len(), input_bitlen);
        debug_assert_eq!(divisor.len(), dividend.len());
        let quotient = Self::bin_div_by_shared(g, dividend, &divisor)?;

        let mut added = Vec::with_capacity(input_bitlen);
        let ys = wires_c;
        let (mut s, mut c) = Self::half_adder(g, &quotient[0], &ys[0])?;
        added.push(s);

        for (x, y) in quotient.iter().zip(ys.iter()).skip(1) {
            let res = Self::full_adder(g, x, y, &c)?;
            s = res.0;
            c = res.1;
            added.push(s);
        }
        for y in ys.iter().take(ys.len() - 1).skip(quotient.len()) {
            let res = Self::full_adder_const(g, y, false, &c)?;
            s = res.0;
            c = res.1;
            added.push(s);
        }
        Ok(added)
    }

    /// Divides a field element by another. The field elements are represented as bitdecompositions x1s, x2s, y1s and y2s which need to be added first. The output is composed using wires_c, whereas wires_c are the same size as the input wires.
    fn field_int_div<G: FancyBinary + FancyBinaryConstant, F: PrimeField>(
        g: &mut G,
        x1s: &[G::Item],
        x2s: &[G::Item],
        y1s: &[G::Item],
        y2s: &[G::Item],
        wires_c: &[G::Item],
        input_bitlen: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        let n_bits = F::MODULUS_BIT_SIZE as usize;
        assert_eq!(input_bitlen, n_bits);
        debug_assert_eq!(input_bitlen, x1s.len());
        debug_assert_eq!(input_bitlen, wires_c.len());

        // Add x1s and x2s to get the first input bits as Yao wires
        let added1 = Self::adder_mod_p_with_output_size::<_, F>(g, x1s, x2s, x1s.len())?;

        // Add y1s and y2s to get the second input bits as Yao wires
        let added2 = Self::adder_mod_p_with_output_size::<_, F>(g, y1s, y2s, x1s.len())?;

        // compute the division
        let quotient = Self::bin_div(g, &added1, &added2)?;

        // compose chunk_bits again
        let result = Self::compose_field_element::<G, F>(g, &quotient, wires_c)?;

        Ok(result)
    }

    /// Divides a field element by another public field element. The field elements is represented as bitdecompositions x1s and x2s which need to be added first. The output is composed using wires_c, whereas wires_c are the same size as the input wires.
    fn field_int_div_by_public<G: FancyBinary + FancyBinaryConstant, F: PrimeField>(
        g: &mut G,
        x1s: &[G::Item],
        x2s: &[G::Item],
        divisor: &[bool],
        wires_c: &[G::Item],
        input_bitlen: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        let n_bits = F::MODULUS_BIT_SIZE as usize;
        assert_eq!(input_bitlen, n_bits);
        debug_assert_eq!(input_bitlen, x1s.len());
        debug_assert_eq!(input_bitlen, wires_c.len());

        // Add x1s and x2s to get the first input bits as Yao wires
        let added1 = Self::adder_mod_p_with_output_size::<_, F>(g, x1s, x2s, x1s.len())?;

        // compute the division
        let quotient = Self::bin_div_by_public(g, &added1, divisor)?;

        // compose chunk_bits again
        let result = Self::compose_field_element::<G, F>(g, &quotient, wires_c)?;

        Ok(result)
    }

    /// Divides a public field element by another shared field element. The field elements is represented as bitdecompositions x1s and x2s which need to be added first. The output is composed using wires_c, whereas wires_c are the same size as the input wires.
    fn field_int_div_by_shared<G: FancyBinary + FancyBinaryConstant, F: PrimeField>(
        g: &mut G,
        x1s: &[G::Item],
        x2s: &[G::Item],
        dividend: &[bool],
        wires_c: &[G::Item],
        input_bitlen: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        let n_bits = F::MODULUS_BIT_SIZE as usize;
        assert_eq!(input_bitlen, n_bits);
        debug_assert_eq!(input_bitlen, x1s.len());
        debug_assert_eq!(input_bitlen, wires_c.len());

        // Add x1s and x2s to get the first input bits as Yao wires
        let added1 = Self::adder_mod_p_with_output_size::<_, F>(g, x1s, x2s, x1s.len())?;

        // compute the division
        let quotient = Self::bin_div_by_shared(g, dividend, &added1)?;

        // compose chunk_bits again
        let result = Self::compose_field_element::<G, F>(g, &quotient, wires_c)?;

        Ok(result)
    }

    /// Divides a ring element by a power of 2. The ring element is represented as two bitdecompositions wires_a, wires_b which need to be added first. The output is composed using wires_c, whereas wires_c are the same size as wires_a and wires_b.
    pub(crate) fn ring_div_power_2_many<G: FancyBinary>(
        g: &mut G,
        wires_a: &BinaryBundle<G::Item>,
        wires_b: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        input_bitlen: usize,
        divisor_bit: usize,
    ) -> Result<BinaryBundle<G::Item>, G::Error>
    where
        G::Item: Default,
    {
        debug_assert_eq!(wires_a.size(), wires_b.size());
        let input_size = wires_a.size();

        debug_assert_eq!(input_size % input_bitlen, 0);
        debug_assert!(divisor_bit < input_bitlen);
        debug_assert!(divisor_bit > 0);
        debug_assert_eq!(wires_c.size(), input_size);

        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_a, chunk_b, chunk_c) in izip!(
            wires_a.wires().chunks(input_bitlen),
            wires_b.wires().chunks(input_bitlen),
            wires_c.wires().chunks(input_bitlen),
        ) {
            results.extend(Self::ring_div_power_2(
                g,
                chunk_a,
                chunk_b,
                chunk_c,
                divisor_bit,
            )?);
        }
        Ok(BinaryBundle::new(results))
    }

    /// Divides a field element by a power of 2. The field element is represented as two bitdecompositions wires_a, wires_b which need to be added first. The output is composed using wires_c, whereas wires_c are the same size as wires_a and wires_b.
    pub(crate) fn field_int_div_power_2_many<G: FancyBinary, F: PrimeField>(
        g: &mut G,
        wires_a: &BinaryBundle<G::Item>,
        wires_b: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        divisor_bit: usize,
    ) -> Result<BinaryBundle<G::Item>, G::Error>
    where
        G::Item: Default,
    {
        debug_assert_eq!(wires_a.size(), wires_b.size());
        let input_size = wires_a.size();
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;

        debug_assert_eq!(input_size % input_bitlen, 0);
        debug_assert!(divisor_bit < input_bitlen);
        debug_assert!(divisor_bit > 0);
        debug_assert_eq!(wires_c.size(), input_size);

        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_a, chunk_b, chunk_c) in izip!(
            wires_a.wires().chunks(input_bitlen),
            wires_b.wires().chunks(input_bitlen),
            wires_c.wires().chunks(input_bitlen),
        ) {
            results.extend(Self::field_int_div_power_2::<G, F>(
                g,
                chunk_a,
                chunk_b,
                chunk_c,
                divisor_bit,
            )?);
        }

        Ok(BinaryBundle::new(results))
    }

    /// Binary division for two vecs of inputs
    pub fn ring_div_many<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        wires_x1: &BinaryBundle<G::Item>,
        wires_x2: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        input_bitlen: usize,
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        debug_assert_eq!(wires_x1.size(), wires_x2.size());
        let length = wires_x1.size();
        debug_assert_eq!(length % 2, 0);

        debug_assert_eq!(length / 2 % input_bitlen, 0);
        debug_assert_eq!(wires_c.size(), length / 2);
        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_x1, chunk_x2, chunk_y1, chunk_y2, chunk_c) in izip!(
            wires_x1.wires()[0..length / 2].chunks(input_bitlen),
            wires_x2.wires()[0..length / 2].chunks(input_bitlen),
            wires_x1.wires()[length / 2..].chunks(input_bitlen),
            wires_x2.wires()[length / 2..].chunks(input_bitlen),
            wires_c.wires().chunks(input_bitlen),
        ) {
            results.extend(Self::ring_div(
                g,
                chunk_x1,
                chunk_x2,
                chunk_y1,
                chunk_y2,
                chunk_c,
                input_bitlen,
            )?);
        }
        Ok(BinaryBundle::new(results))
    }

    /// Divides the quotient by a public divisor and then returns the quotient as field elements in limbs_per_field many limbs in one field F and the remainder in another field K. The field elements are composed using wires_c.
    #[expect(clippy::too_many_arguments)]
    pub fn ring_div_by_public_to_fr_limbs_and_fq_many<
        G: FancyBinary + FancyBinaryConstant,
        F: PrimeField,
        K: PrimeField,
    >(
        g: &mut G,
        wires_x1: &BinaryBundle<G::Item>,
        wires_x2: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        input_bitlen: usize,
        limb_size: usize,
        num_limbs_per_field: usize,
        divisor: &[bool],
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        let length = wires_x1.size();

        debug_assert_eq!(wires_x1.size(), wires_x2.size());
        debug_assert_eq!(length % input_bitlen, 0);
        debug_assert_eq!(
            wires_c.size(),
            num_limbs_per_field * F::MODULUS_BIT_SIZE as usize * (length / input_bitlen)
                + K::MODULUS_BIT_SIZE as usize * (length / input_bitlen)
        );

        let mut results = Vec::with_capacity(wires_c.size());

        let num_outputs_per_chunk =
            num_limbs_per_field * F::MODULUS_BIT_SIZE as usize + K::MODULUS_BIT_SIZE as usize;

        for (chunk_x1, chunk_x2, chunk_c) in izip!(
            wires_x1.wires().chunks(input_bitlen),
            wires_x2.wires().chunks(input_bitlen),
            wires_c.wires().chunks(num_outputs_per_chunk),
        ) {
            let res = Self::ring_div_by_public_to_fr_limbs_and_fq::<G, F, K>(
                g,
                chunk_x1,
                chunk_x2,
                chunk_c,
                divisor,
                input_bitlen,
                limb_size,
                num_limbs_per_field,
            )?;
            results.extend(res);
        }
        Ok(BinaryBundle::new(results))
    }

    /// Divides the quotient by a public divisor and then returns the quotient as field elements in limbs_per_field many limbs in one field F and the remainder in another field K. The field elements are composed using wires_c.
    #[expect(clippy::too_many_arguments)]
    fn ring_div_by_public_to_fr_limbs_and_fq<
        G: FancyBinary + FancyBinaryConstant,
        F: PrimeField,
        K: PrimeField,
    >(
        g: &mut G,
        x1s: &[G::Item],
        x2s: &[G::Item],
        wires_c: &[G::Item],
        divisor: &[bool],
        input_bitlen: usize,
        output_bitlen: usize,
        limbs_per_field: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        let dividend = Self::bin_addition_no_carry(g, x1s, x2s)?;

        debug_assert_eq!(dividend.len(), input_bitlen);
        debug_assert_eq!(dividend.len(), divisor.len());
        debug_assert_eq!(
            wires_c.len(),
            F::MODULUS_BIT_SIZE as usize * limbs_per_field + K::MODULUS_BIT_SIZE as usize
        );
        let quotient = Self::bin_div_by_public(g, &dividend, divisor)?;
        let km = Self::bin_mul_with_public(g, &quotient, divisor)?;
        let remainder = &Self::bin_subtraction(g, &dividend, &km[..dividend.len()])?.0;

        let mut results = Vec::with_capacity(
            F::MODULUS_BIT_SIZE as usize * limbs_per_field + K::MODULUS_BIT_SIZE as usize,
        );

        let (wires_c_f, wires_c_k) =
            wires_c.split_at(F::MODULUS_BIT_SIZE as usize * limbs_per_field);

        for (xs, ys) in izip!(
            quotient.chunks(output_bitlen),
            wires_c_f.chunks(F::MODULUS_BIT_SIZE as usize),
        ) {
            let result = Self::compose_field_element::<_, F>(g, xs, ys)?;
            results.extend(result);
        }
        results.extend(Self::compose_field_element::<_, K>(
            g,
            remainder[..K::MODULUS_BIT_SIZE as usize].as_ref(),
            wires_c_k,
        )?);
        Ok(results)
    }

    /// Divides the quotient by a public divisor and then returns the quotient and remainder as field elements in limbs_per_field many limbs of size limb_size. The field elements are composed using wires_c.
    #[expect(clippy::too_many_arguments)]
    pub fn ring_div_by_public_to_limbs_many<G: FancyBinary + FancyBinaryConstant, F: PrimeField>(
        g: &mut G,
        wires_x1: &BinaryBundle<G::Item>,
        wires_x2: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        input_bitlen: usize,
        divisor: &[bool],
        limb_size: usize,
        num_limbs_per_field: usize,
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        let length = wires_x1.size();

        debug_assert_eq!(wires_x1.size(), wires_x2.size());
        debug_assert_eq!(length % input_bitlen, 0);
        debug_assert_eq!(
            wires_c.size(),
            2 * F::MODULUS_BIT_SIZE as usize * num_limbs_per_field * (length / input_bitlen)
        );

        let mut results = Vec::with_capacity(wires_c.size());

        let num_outputs_per_chunk = 2 * F::MODULUS_BIT_SIZE as usize * num_limbs_per_field;

        for (chunk_x1, chunk_x2, chunk_c) in izip!(
            wires_x1.wires().chunks(input_bitlen),
            wires_x2.wires().chunks(input_bitlen),
            wires_c.wires().chunks(num_outputs_per_chunk),
        ) {
            let res = Self::ring_div_by_public_to_limbs::<G, F>(
                g,
                chunk_x1,
                chunk_x2,
                chunk_c,
                divisor,
                input_bitlen,
                limb_size,
                num_limbs_per_field,
            )?;
            results.extend(res);
        }
        Ok(BinaryBundle::new(results))
    }

    /// Divides the quotient by a public divisor and then returns the quotient and remainder as field elements in limbs_per_field many limbs of size limb_size. The field elements are composed using wires_c.
    #[expect(clippy::too_many_arguments)]
    fn ring_div_by_public_to_limbs<G: FancyBinary + FancyBinaryConstant, F: PrimeField>(
        g: &mut G,
        x1s: &[G::Item],
        x2s: &[G::Item],
        wires_c: &[G::Item],
        divisor: &[bool],
        input_bitlen: usize,
        limb_size: usize,
        num_limbs_per_field: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        let dividend = Self::bin_addition_no_carry(g, x1s, x2s)?;

        debug_assert_eq!(dividend.len(), input_bitlen);
        debug_assert_eq!(dividend.len(), divisor.len());
        debug_assert_eq!(
            wires_c.len(),
            F::MODULUS_BIT_SIZE as usize * 2 * num_limbs_per_field
        );
        let quotient = Self::bin_div_by_public(g, &dividend, divisor)?;
        let km = Self::bin_mul_with_public(g, &quotient, divisor)?;
        let remainder = &Self::bin_subtraction(g, &dividend, &km[..dividend.len()])?.0;

        let mut results = Vec::with_capacity(F::MODULUS_BIT_SIZE as usize * 2);
        let mut rands = wires_c.chunks(F::MODULUS_BIT_SIZE as usize);

        for xs in quotient.chunks(limb_size).take(num_limbs_per_field) {
            results.extend(Self::compose_field_element::<_, F>(
                g,
                xs,
                rands.next().unwrap(),
            )?);
        }
        for xs in remainder.chunks(limb_size).take(num_limbs_per_field) {
            results.extend(Self::compose_field_element::<_, F>(
                g,
                xs,
                rands.next().unwrap(),
            )?);
        }
        Ok(results)
    }

    /// Binary division for two vecs of inputs. The ring elements are represented as two bitdecompositions wires_a, wires_b which need to be split first to get the two inputs. The output is composed using wires_c, whereas wires_c is half the size as wires_a and wires_b.
    pub fn ring_div_by_public_many<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        wires_x1: &BinaryBundle<G::Item>,
        wires_x2: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        input_bitlen: usize,
        divisor: Vec<bool>,
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        debug_assert_eq!(wires_x1.size(), wires_x2.size());
        let length = wires_x1.size();
        debug_assert_eq!(length % 2, 0);

        debug_assert_eq!(length % input_bitlen, 0);
        debug_assert_eq!(wires_c.size(), length);
        debug_assert_eq!(divisor.len(), length);
        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_x1, chunk_x2, div, chunk_c) in izip!(
            wires_x1.wires().chunks(input_bitlen),
            wires_x2.wires().chunks(input_bitlen),
            divisor.chunks(input_bitlen),
            wires_c.wires().chunks(input_bitlen),
        ) {
            results.extend(Self::ring_div_by_public(
                g,
                chunk_x1,
                chunk_x2,
                div,
                chunk_c,
                input_bitlen,
            )?);
        }
        Ok(BinaryBundle::new(results))
    }

    /// Binary division for two vecs of inputs. The ring elements are represented as two bitdecompositions wires_a, wires_b which need to be split first to get the two inputs. The output is composed using wires_c, whereas wires_c is half the size as wires_a and wires_b.
    pub fn ring_div_by_shared_many<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        wires_x1: &BinaryBundle<G::Item>,
        wires_x2: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        input_bitlen: usize,
        dividend: Vec<bool>,
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        debug_assert_eq!(wires_x1.size(), wires_x2.size());
        let length = wires_x1.size();
        debug_assert_eq!(length % 2, 0);

        debug_assert_eq!(length % input_bitlen, 0);
        debug_assert_eq!(wires_c.size(), length);
        debug_assert_eq!(dividend.len(), length);
        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_x1, chunk_x2, div, chunk_c) in izip!(
            wires_x1.wires().chunks(input_bitlen),
            wires_x2.wires().chunks(input_bitlen),
            dividend.chunks(input_bitlen),
            wires_c.wires().chunks(input_bitlen),
        ) {
            results.extend(Self::ring_div_by_shared(
                g,
                chunk_x1,
                chunk_x2,
                div,
                chunk_c,
                input_bitlen,
            )?);
        }
        Ok(BinaryBundle::new(results))
    }

    /// Divides a field element by another. The field elements are represented as two bitdecompositions wires_a, wires_b which need to be split first to get the two inputs. The output is composed using wires_c, whereas wires_c is half the size as wires_a and wires_b.
    pub(crate) fn field_int_div_many<G: FancyBinary + FancyBinaryConstant, F: PrimeField>(
        g: &mut G,
        wires_x1: &BinaryBundle<G::Item>,
        wires_x2: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
    ) -> Result<BinaryBundle<G::Item>, G::Error>
    where
        G::Item: Default,
    {
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        debug_assert_eq!(wires_x1.size(), wires_x2.size());
        let length = wires_x1.size();
        debug_assert_eq!(length % 2, 0);

        debug_assert_eq!(length / 2 % input_bitlen, 0);
        debug_assert_eq!(wires_c.size(), length / 2);
        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_x1, chunk_x2, chunk_y1, chunk_y2, chunk_c) in izip!(
            wires_x1.wires()[0..length / 2].chunks(input_bitlen),
            wires_x2.wires()[0..length / 2].chunks(input_bitlen),
            wires_x1.wires()[length / 2..].chunks(input_bitlen),
            wires_x2.wires()[length / 2..].chunks(input_bitlen),
            wires_c.wires().chunks(input_bitlen),
        ) {
            results.extend(Self::field_int_div::<G, F>(
                g,
                chunk_x1,
                chunk_x2,
                chunk_y1,
                chunk_y2,
                chunk_c,
                input_bitlen,
            )?);
        }
        Ok(BinaryBundle::new(results))
    }

    /// Divides a field element by another public. The field elements are represented as two bitdecompositions wires_a, wires_b which need to be split first to get the two inputs. The output is composed using wires_c, whereas wires_c is half the size as wires_a and wires_b.
    pub(crate) fn field_int_div_by_public_many<
        G: FancyBinary + FancyBinaryConstant,
        F: PrimeField,
    >(
        g: &mut G,
        wires_x1: &BinaryBundle<G::Item>,
        wires_x2: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        divisor: Vec<bool>,
    ) -> Result<BinaryBundle<G::Item>, G::Error>
    where
        G::Item: Default,
    {
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        debug_assert_eq!(wires_x1.size(), wires_x2.size());
        let length = wires_x1.size();
        debug_assert_eq!(length % 2, 0);

        debug_assert_eq!(length % input_bitlen, 0);
        debug_assert_eq!(wires_c.size(), length);
        debug_assert_eq!(divisor.len(), length);
        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_x1, chunk_x2, div, chunk_c) in izip!(
            wires_x1.wires().chunks(input_bitlen),
            wires_x2.wires().chunks(input_bitlen),
            divisor.chunks(input_bitlen),
            wires_c.wires().chunks(input_bitlen),
        ) {
            results.extend(Self::field_int_div_by_public::<G, F>(
                g,
                chunk_x1,
                chunk_x2,
                div,
                chunk_c,
                input_bitlen,
            )?);
        }
        Ok(BinaryBundle::new(results))
    }

    /// Divides public field elements by another shared. The field elements are represented as two bitdecompositions wires_a, wires_b which need to be split first to get the two inputs. The output is composed using wires_c, whereas wires_c is half the size as wires_a and wires_b.
    pub(crate) fn field_int_div_by_shared_many<
        G: FancyBinary + FancyBinaryConstant,
        F: PrimeField,
    >(
        g: &mut G,
        wires_x1: &BinaryBundle<G::Item>,
        wires_x2: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        dividend: Vec<bool>,
    ) -> Result<BinaryBundle<G::Item>, G::Error>
    where
        G::Item: Default,
    {
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        debug_assert_eq!(wires_x1.size(), wires_x2.size());
        let length = wires_x1.size();
        debug_assert_eq!(length % 2, 0);

        debug_assert_eq!(length % input_bitlen, 0);
        debug_assert_eq!(wires_c.size(), length);
        debug_assert_eq!(dividend.len(), length);
        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_x1, chunk_x2, div, chunk_c) in izip!(
            wires_x1.wires().chunks(input_bitlen),
            wires_x2.wires().chunks(input_bitlen),
            dividend.chunks(input_bitlen),
            wires_c.wires().chunks(input_bitlen),
        ) {
            results.extend(Self::field_int_div_by_shared::<G, F>(
                g,
                chunk_x1,
                chunk_x2,
                div,
                chunk_c,
                input_bitlen,
            )?);
        }
        Ok(BinaryBundle::new(results))
    }

    /// Slices field elements in chunks, then XORs the slices and rotates them (over u64), a specific circuit for the plookup accumulator in the builder. The field elements are represented as two bitdecompositions wires_x1, wires_x2 which need to be split first to get the two inputs. The output is composed using wires_c. Base_bit is the size of the slice, rotation the the length of the rotation and total_output_bitlen_per_field is the amount of bits the output field elements have.
    pub(crate) fn slice_and_get_xor_rotate_values_from_key_many<
        G: FancyBinary + FancyBinaryConstant,
        F: PrimeField,
    >(
        g: &mut G,
        wires_x1: &BinaryBundle<G::Item>,
        wires_x2: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        base_bit: usize,
        rotation: usize,
        total_output_bitlen_per_field: usize,
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        debug_assert_eq!(wires_x1.size(), wires_x2.size());
        let length = wires_x1.size();
        debug_assert_eq!(length % 2, 0);
        let num_decomps_per_field = total_output_bitlen_per_field.div_ceil(base_bit);
        let num_inputs = (length / 2) / input_bitlen;

        let total_output_elements = 3 * num_decomps_per_field * num_inputs;
        debug_assert_eq!(wires_c.size(), total_output_elements * input_bitlen);
        debug_assert_eq!((length / 2) % input_bitlen, 0);

        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_x1, chunk_x2, chunk_y1, chunk_y2, chunk_c) in izip!(
            wires_x1.wires()[0..length / 2].chunks(input_bitlen),
            wires_x2.wires()[0..length / 2].chunks(input_bitlen),
            wires_x1.wires()[length / 2..].chunks(input_bitlen),
            wires_x2.wires()[length / 2..].chunks(input_bitlen),
            wires_c
                .wires()
                .chunks(3 * input_bitlen * num_decomps_per_field),
        ) {
            let value = Self::slice_and_get_xor_rotate_values_from_key::<G, F>(
                g,
                chunk_x1,
                chunk_x2,
                chunk_y1,
                chunk_y2,
                chunk_c,
                base_bit,
                rotation,
                total_output_bitlen_per_field,
            )?;

            results.extend(value);
        }
        Ok(BinaryBundle::new(results))
    }

    /// Slices field elements in chunks, then XORs the slices and rotates them (over u64), a specific circuit for the plookup accumulator in the builder. The field elements are represented as two bitdecompositions wires_x1, wires_x2 which need to be split first to get the two inputs. The output is composed using wires_c. Base_bit is the size of the slice, rotation the the length of the rotation and total_output_bitlen_per_field is the amount of bits the output field elements have.
    pub(crate) fn slice_and_get_xor_rotate_values_from_key_with_filter_many<
        G: FancyBinary + FancyBinaryConstant,
        F: PrimeField,
    >(
        g: &mut G,
        wires_x1: &BinaryBundle<G::Item>,
        wires_x2: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        base_bits: &[u64],
        rotation: &[usize],
        filter: &[bool],
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        debug_assert_eq!(wires_x1.size(), wires_x2.size());
        let length = wires_x1.size();
        debug_assert_eq!(length % 2, 0);
        let num_decomps_per_field = base_bits.len();
        let num_inputs = (length / 2) / input_bitlen;

        let total_output_elements = 3 * num_decomps_per_field * num_inputs;
        debug_assert_eq!(wires_c.size(), total_output_elements * input_bitlen);
        debug_assert_eq!((length / 2) % input_bitlen, 0);

        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_x1, chunk_x2, chunk_y1, chunk_y2, chunk_c) in izip!(
            wires_x1.wires()[0..length / 2].chunks(input_bitlen),
            wires_x2.wires()[0..length / 2].chunks(input_bitlen),
            wires_x1.wires()[length / 2..].chunks(input_bitlen),
            wires_x2.wires()[length / 2..].chunks(input_bitlen),
            wires_c
                .wires()
                .chunks(3 * input_bitlen * num_decomps_per_field),
        ) {
            let value = Self::slice_and_get_xor_rotate_values_from_key_with_filter::<G, F>(
                g, chunk_x1, chunk_x2, chunk_y1, chunk_y2, chunk_c, base_bits, rotation, filter,
            )?;

            results.extend(value);
        }
        Ok(BinaryBundle::new(results))
    }

    /// Slices field elements in chunks, then ANDs the slices and rotates them (over u64), a specific circuit for the plookup accumulator in the builder. The field elements are represented as two bitdecompositions wires_x1, wires_x2 which need to be split first to get the two sets of inputs. The output is composed using wires_c. Base_bit is the size of the slice, rotation the the length of the rotation and total_output_bitlen_per_field is the amount of bits the output field elements have.
    pub(crate) fn slice_and_get_and_rotate_values_from_key_many<
        G: FancyBinary + FancyBinaryConstant,
        F: PrimeField,
    >(
        g: &mut G,
        wires_x1: &BinaryBundle<G::Item>,
        wires_x2: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        base_bit: usize,
        rotation: usize,
        total_output_bitlen_per_field: usize,
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        debug_assert_eq!(wires_x1.size(), wires_x2.size());
        let length = wires_x1.size();
        debug_assert_eq!(length % 2, 0);
        let num_decomps_per_field = total_output_bitlen_per_field.div_ceil(base_bit);
        let num_inputs = (length / 2) / input_bitlen;

        let total_output_elements = 3 * num_decomps_per_field * num_inputs;
        debug_assert_eq!(wires_c.size(), total_output_elements * input_bitlen);
        debug_assert_eq!((length / 2) % input_bitlen, 0);

        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_x1, chunk_x2, chunk_y1, chunk_y2, chunk_c) in izip!(
            wires_x1.wires()[0..length / 2].chunks(input_bitlen),
            wires_x2.wires()[0..length / 2].chunks(input_bitlen),
            wires_x1.wires()[length / 2..].chunks(input_bitlen),
            wires_x2.wires()[length / 2..].chunks(input_bitlen),
            wires_c
                .wires()
                .chunks(3 * input_bitlen * num_decomps_per_field),
        ) {
            let value = Self::slice_and_get_and_rotate_values_from_key::<G, F>(
                g,
                chunk_x1,
                chunk_x2,
                chunk_y1,
                chunk_y2,
                chunk_c,
                base_bit,
                rotation,
                total_output_bitlen_per_field,
            )?;
            results.extend(value);
        }

        Ok(BinaryBundle::new(results))
    }

    /// Slice two field elements in chunks, then XORs the slices and rotates them (over u64), a specific circuit for the plookup accumulator in the builder. The field elements are represented as bitdecompositions x1s, x2s, y1s and y2s which need to be added first get the two sets of inputs. The output is composed using wires_c. Base_bit is the size of the slice, rotation the the length of the rotation and total_output_bitlen_per_field is the amount of bits the output field elements have.
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn slice_and_get_xor_rotate_values_from_key<
        G: FancyBinary + FancyBinaryConstant,
        F: PrimeField,
    >(
        g: &mut G,
        x1s: &[G::Item],
        x2s: &[G::Item],
        y1s: &[G::Item],
        y2s: &[G::Item],
        wires_c: &[G::Item],
        base_bit: usize,
        rotation: usize,
        total_output_bitlen_per_field: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        let num_decomps_per_field = total_output_bitlen_per_field.div_ceil(base_bit);
        debug_assert_eq!(x1s.len(), input_bitlen);
        debug_assert_eq!(x2s.len(), input_bitlen);
        debug_assert_eq!(y1s.len(), input_bitlen);
        debug_assert_eq!(y2s.len(), input_bitlen);
        debug_assert_eq!(wires_c.len(), 3 * input_bitlen * num_decomps_per_field);

        // Combine the inputs
        let input_bits_1 =
            Self::adder_mod_p_with_output_size::<_, F>(g, x1s, x2s, total_output_bitlen_per_field)?;
        let input_bits_2 =
            Self::adder_mod_p_with_output_size::<_, F>(g, y1s, y2s, total_output_bitlen_per_field)?;

        let mut results = Vec::with_capacity(input_bitlen * num_decomps_per_field);
        let mut rands = wires_c.chunks(input_bitlen);

        // Perform the actual XOR
        let res = input_bits_1
            .iter()
            .zip(input_bits_2.iter())
            .map(|(x, y)| g.xor(x, y))
            .collect::<Result<Vec<_>, _>>()?;

        // Compose the inputs
        for inp in input_bits_1
            .chunks(base_bit)
            .chain(input_bits_2.chunks(base_bit))
        {
            results.extend(Self::compose_field_element::<_, F>(
                g,
                inp,
                rands.next().unwrap(),
            )?);
        }

        // Compose the results
        for xs in res.chunks(base_bit) {
            if rotation == 0 {
                results.extend(Self::compose_field_element::<_, F>(
                    g,
                    xs,
                    rands.next().unwrap(),
                )?);
            } else {
                let mut rotated = xs.to_owned();
                rotated.resize(64, g.const_zero()?);
                rotated.rotate_left(rotation);
                results.extend(Self::compose_field_element::<_, F>(
                    g,
                    &rotated,
                    rands.next().unwrap(),
                )?);
            }
        }
        Ok(results)
    }

    /// Slice two field elements in chunks, then XORs the slices and rotates them (over u64), a specific circuit for the plookup accumulator in the builder. The field elements are represented as bitdecompositions x1s, x2s, y1s and y2s which need to be added first get the two sets of inputs. The output is composed using wires_c. Base_bit is the size of the slice, rotation the the length of the rotation and total_output_bitlen_per_field is the amount of bits the output field elements have.
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn slice_and_get_xor_rotate_values_from_key_with_filter<
        G: FancyBinary + FancyBinaryConstant,
        F: PrimeField,
    >(
        g: &mut G,
        x1s: &[G::Item],
        x2s: &[G::Item],
        y1s: &[G::Item],
        y2s: &[G::Item],
        wires_c: &[G::Item],
        base_bits: &[u64],
        rotation: &[usize],
        filter: &[bool],
    ) -> Result<Vec<G::Item>, G::Error> {
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        let mut base_bits = base_bits.to_vec();
        let base_bits = base_bits.iter_mut().map(|x| x.ilog2()).collect::<Vec<_>>();
        let total_bits: u32 = base_bits.iter().sum();
        let num_decomps_per_field = base_bits.len();
        debug_assert_eq!(x1s.len(), input_bitlen);
        debug_assert_eq!(x2s.len(), input_bitlen);
        debug_assert_eq!(y1s.len(), input_bitlen);
        debug_assert_eq!(y2s.len(), input_bitlen);
        debug_assert_eq!(wires_c.len(), 3 * input_bitlen * num_decomps_per_field);

        // Combine the inputs
        let mut input_bits_1 =
            Self::adder_mod_p_with_output_size::<_, F>(g, x1s, x2s, total_bits as usize)?;
        let mut input_bits_2 =
            Self::adder_mod_p_with_output_size::<_, F>(g, y1s, y2s, total_bits as usize)?;

        // Compose the inputs
        let mut results = Vec::with_capacity(3 * input_bitlen * num_decomps_per_field);
        let mut rands = wires_c.chunks(input_bitlen);
        let mut offset = 0;
        for &bits in base_bits.iter() {
            let end = offset + bits as usize;

            let inp = &input_bits_1[offset..end];
            results.extend(Self::compose_field_element::<_, F>(
                g,
                inp,
                rands.next().unwrap(),
            )?);
            offset = end;
        }
        let mut offset = 0;
        for &bits in base_bits.iter() {
            let end = offset + bits as usize;
            let inp = &input_bits_2[offset..end];
            results.extend(Self::compose_field_element::<_, F>(
                g,
                inp,
                rands.next().unwrap(),
            )?);

            offset = end;
        }

        let mut sum = 0;
        for (i, filt) in filter.iter().enumerate() {
            let len = base_bits[i] as usize;
            if *filt {
                for (i1, i2) in input_bits_1
                    .iter_mut()
                    .zip(input_bits_2.iter_mut())
                    .skip(sum)
                    .take(len)
                    .skip(2)
                {
                    *i1 = g.const_zero()?;
                    *i2 = g.const_zero()?;
                }
            }
            sum += len;
        }

        // Perform the actual XOR
        let res = Self::xor_many_as_wires(g, &input_bits_1, &input_bits_2)?;

        // Compose the results
        let mut iter = base_bits.iter();
        for (xs, rot) in res
            .chunks(*iter.next().unwrap() as usize)
            .zip(rotation.iter())
        {
            if *rot == 0 {
                let xs = if xs.len() > 32 { &xs[0..32] } else { xs };
                results.extend(Self::compose_field_element::<_, F>(
                    g,
                    xs,
                    rands.next().unwrap(),
                )?);
            } else {
                let mut rotated = xs.to_owned();
                rotated.resize(32, g.const_zero()?); // For Blake we need 32 here
                rotated.rotate_left(*rot);
                results.extend(Self::compose_field_element::<_, F>(
                    g,
                    &rotated,
                    rands.next().unwrap(),
                )?);
            }
        }
        Ok(results)
    }

    /// Slice two field elements in chunks, then ANDs the slices and rotates them (over u64), a specific circuit for the plookup accumulator in the builder. The field elements are represented as bitdecompositions x1s, x2s, y1s and y2s which need to be added first get the two inputs. The output is composed using wires_c. Base_bit is the size of the slice, rotation the the length of the rotation and total_output_bitlen_per_field is the amount of bits the output field elements have.
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn slice_and_get_and_rotate_values_from_key<
        G: FancyBinary + FancyBinaryConstant,
        F: PrimeField,
    >(
        g: &mut G,
        x1s: &[G::Item],
        x2s: &[G::Item],
        y1s: &[G::Item],
        y2s: &[G::Item],
        wires_c: &[G::Item],
        base_bit: usize,
        rotation: usize,
        total_output_bitlen_per_field: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        let num_decomps_per_field = total_output_bitlen_per_field.div_ceil(base_bit);
        debug_assert_eq!(x1s.len(), input_bitlen);
        debug_assert_eq!(x2s.len(), input_bitlen);
        debug_assert_eq!(y1s.len(), input_bitlen);
        debug_assert_eq!(y2s.len(), input_bitlen);
        debug_assert_eq!(wires_c.len(), 3 * input_bitlen * num_decomps_per_field);

        // Combine the inputs
        let input_bits_1 =
            Self::adder_mod_p_with_output_size::<_, F>(g, x1s, x2s, total_output_bitlen_per_field)?;
        let input_bits_2 =
            Self::adder_mod_p_with_output_size::<_, F>(g, y1s, y2s, total_output_bitlen_per_field)?;

        let mut results = Vec::with_capacity(input_bitlen * num_decomps_per_field);
        let mut rands = wires_c.chunks(input_bitlen);

        // Perform the actual AND
        let res = input_bits_1
            .iter()
            .zip(input_bits_2.iter())
            .map(|(x, y)| g.and(x, y))
            .collect::<Result<Vec<_>, _>>()?;

        // Compose the inputs
        for inp in input_bits_1
            .chunks(base_bit)
            .chain(input_bits_2.chunks(base_bit))
        {
            results.extend(Self::compose_field_element::<_, F>(
                g,
                inp,
                rands.next().unwrap(),
            )?);
        }

        // Compose the results
        for xs in res.chunks(base_bit) {
            if rotation == 0 {
                results.extend(Self::compose_field_element::<_, F>(
                    g,
                    xs,
                    rands.next().unwrap(),
                )?);
            } else {
                let mut rotated = xs.to_owned();
                rotated.resize(64, g.const_zero()?);
                rotated.rotate_left(rotation);
                results.extend(Self::compose_field_element::<_, F>(
                    g,
                    &rotated,
                    rands.next().unwrap(),
                )?);
            }
        }
        Ok(results)
    }

    /// Slice two field elements in chunks, then ANDs the slices and rotates them (over u64), a specific circuit for the plookup accumulator in the builder. The field elements are represented as bitdecompositions x1s, x2s, y1s and y2s which need to be added first get the two inputs. The output is composed using wires_c. Base_bit is the size of the slice, rotation the the length of the rotation and total_output_bitlen_per_field is the amount of bits the output field elements have.
    pub(crate) fn slice_and_get_sparse_table_with_rotation_values_many<
        G: FancyBinary + FancyBinaryConstant,
        F: PrimeField,
    >(
        g: &mut G,
        wires_x1: &BinaryBundle<G::Item>,
        wires_x2: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        base_bits: &[u64],
        rotation: &[u32],
        total_output_bitlen_per_field: usize,
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        debug_assert_eq!(wires_x1.size(), wires_x2.size());
        let length = wires_x1.size();
        debug_assert_eq!(length % 2, 0);
        let num_decomps_per_field = base_bits.len();
        let num_inputs = length / input_bitlen;

        let total_output_elements =
            num_inputs * num_decomps_per_field + 32 * 2 * (num_inputs / 2) * num_decomps_per_field;

        debug_assert_eq!(wires_c.size(), total_output_elements * input_bitlen);
        debug_assert_eq!(length % input_bitlen, 0);

        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_x1, chunk_x2, chunk_y1, chunk_y2, chunk_c) in izip!(
            wires_x1.wires()[0..length / 2].chunks(input_bitlen),
            wires_x2.wires()[0..length / 2].chunks(input_bitlen),
            wires_x1.wires()[length / 2..].chunks(input_bitlen),
            wires_x2.wires()[length / 2..].chunks(input_bitlen),
            wires_c.wires().chunks(
                (2 * num_decomps_per_field + 32 * 2 * num_decomps_per_field) * input_bitlen
            ),
        ) {
            let value = Self::slice_and_get_sparse_table_with_rotation_values::<G, F>(
                g,
                chunk_x1,
                chunk_x2,
                chunk_y1,
                chunk_y2,
                chunk_c,
                base_bits,
                rotation,
                total_output_bitlen_per_field,
            )?;
            results.extend(value);
        }

        Ok(BinaryBundle::new(results))
    }

    /// Slice two field elements in chunks, then ANDs the slices and rotates them (over u64), a specific circuit for the plookup accumulator in the builder. The field elements are represented as bitdecompositions x1s, x2s, y1s and y2s which need to be added first get the two inputs. The output is composed using wires_c. Base_bit is the size of the slice, rotation the the length of the rotation and total_output_bitlen_per_field is the amount of bits the output field elements have.
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn slice_and_get_sparse_table_with_rotation_values<
        G: FancyBinary + FancyBinaryConstant,
        F: PrimeField,
    >(
        g: &mut G,
        x1s: &[G::Item],
        x2s: &[G::Item],
        y1s: &[G::Item],
        y2s: &[G::Item],
        wires_c: &[G::Item],
        base_bits: &[u64],
        rotation: &[u32],
        total_output_bitlen_per_field: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        let mut base_bits = base_bits.to_vec();
        let base_bits = base_bits.iter_mut().map(|x| x.ilog2()).collect::<Vec<_>>();
        let num_decomps_per_field = base_bits.len();
        debug_assert_eq!(x1s.len(), input_bitlen);
        debug_assert_eq!(x2s.len(), input_bitlen);
        debug_assert_eq!(y1s.len(), input_bitlen);
        debug_assert_eq!(y2s.len(), input_bitlen);
        debug_assert_eq!(
            wires_c.len(),
            (2 * num_decomps_per_field + 32 * 2 * num_decomps_per_field) * input_bitlen
        );
        debug_assert_eq!(base_bits.len(), rotation.len());
        // Combine the inputs
        let input_bits_1 =
            Self::adder_mod_p_with_output_size::<_, F>(g, x1s, x2s, total_output_bitlen_per_field)?;
        let input_bits_2 =
            Self::adder_mod_p_with_output_size::<_, F>(g, y1s, y2s, total_output_bitlen_per_field)?;
        let mut results = Vec::with_capacity(input_bitlen * num_decomps_per_field);
        let mut rands = wires_c.chunks(input_bitlen);
        let mut offset = 0;
        for &bits in base_bits.iter() {
            let end = offset + bits as usize;

            let inp = &input_bits_1[offset..end];
            results.extend(Self::compose_field_element::<_, F>(
                g,
                inp,
                rands.next().unwrap(),
            )?);
            offset = end;
        }
        let mut offset = 0;
        for &bits in base_bits.iter() {
            let end = offset + bits as usize;
            let inp = &input_bits_2[offset..end];
            results.extend(Self::compose_field_element::<_, F>(
                g,
                inp,
                rands.next().unwrap(),
            )?);

            offset = end;
        }
        let mut offset = 0;
        // Compose the results
        for (&bits, rot) in base_bits.iter().zip(rotation.iter()) {
            let end = offset + bits as usize;
            if end > input_bits_1.len() {
                break;
            }
            let xs = &input_bits_1[offset..end];
            let mut resized = xs.to_owned();
            resized.resize(32, g.const_zero()?);
            for bit in resized.iter() {
                results.extend(Self::compose_field_element::<_, F>(
                    g,
                    std::slice::from_ref(bit),
                    rands.next().unwrap(),
                )?);
            }
            if *rot == 0 {
                for bit in resized.iter() {
                    results.extend(Self::compose_field_element::<_, F>(
                        g,
                        std::slice::from_ref(bit),
                        rands.next().unwrap(),
                    )?);
                }
            } else {
                let mut rotated = resized.to_owned();
                rotated.rotate_left(*rot as usize);
                for bit in rotated.iter() {
                    results.extend(Self::compose_field_element::<_, F>(
                        g,
                        std::slice::from_ref(bit),
                        rands.next().unwrap(),
                    )?);
                }
            }
            offset = end;
        }
        Ok(results)
    }

    /// Slice two field elements in chunks, then ANDs the slices and rotates them (over u64), a specific circuit for the plookup accumulator in the builder. The field elements are represented as bitdecompositions x1s, x2s, y1s and y2s which need to be added first get the two inputs. The output is composed using wires_c. Base_bit is the size of the slice, rotation the the length of the rotation and total_output_bitlen_per_field is the amount of bits the output field elements have.
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn slice_and_get_sparse_normalization_values_many<
        G: FancyBinary + FancyBinaryConstant,
        F: PrimeField,
    >(
        g: &mut G,
        wires_x1: &BinaryBundle<G::Item>,
        wires_x2: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        base_bits: &[u64],
        base: u64,
        total_output_bitlen_per_field: usize,
        table_type: &SHA256Table,
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        debug_assert_eq!(wires_x1.size(), wires_x2.size());
        let length = wires_x1.size();
        debug_assert_eq!(length % 2, 0);
        let num_decomps_per_field = base_bits.len();
        let num_inputs = length / input_bitlen;

        let total_output_elements = 3 * num_decomps_per_field * (num_inputs / 2);
        debug_assert_eq!(wires_c.size(), total_output_elements * input_bitlen);
        debug_assert_eq!(length % input_bitlen, 0);

        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_x1, chunk_x2, chunk_y1, chunk_y2, chunk_c) in izip!(
            wires_x1.wires()[0..length / 2].chunks(input_bitlen),
            wires_x2.wires()[0..length / 2].chunks(input_bitlen),
            wires_x1.wires()[length / 2..].chunks(input_bitlen),
            wires_x2.wires()[length / 2..].chunks(input_bitlen),
            wires_c
                .wires()
                .chunks((3 * num_decomps_per_field) * input_bitlen),
        ) {
            let value = Self::slice_and_get_sparse_normalization_values::<G, F>(
                g,
                chunk_x1,
                chunk_x2,
                chunk_y1,
                chunk_y2,
                chunk_c,
                base_bits,
                base,
                total_output_bitlen_per_field,
                table_type,
            )?;
            results.extend(value);
        }

        Ok(BinaryBundle::new(results))
    }

    /// Slice two field elements in chunks, then ANDs the slices and rotates them (over u64), a specific circuit for the plookup accumulator in the builder. The field elements are represented as bitdecompositions x1s, x2s, y1s and y2s which need to be added first get the two inputs. The output is composed using wires_c. Base_bit is the size of the slice, rotation the the length of the rotation and total_output_bitlen_per_field is the amount of bits the output field elements have.
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn slice_and_get_sparse_normalization_values<
        G: FancyBinary + FancyBinaryConstant,
        F: PrimeField,
    >(
        g: &mut G,
        x1s: &[G::Item],
        x2s: &[G::Item],
        y1s: &[G::Item],
        y2s: &[G::Item],
        wires_c: &[G::Item],
        base_bits: &[u64],
        base: u64,
        total_output_bitlen_per_field: usize,
        table_type: &SHA256Table,
    ) -> Result<Vec<G::Item>, G::Error> {
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        let base_bit = base_bits[0] as usize; // For SHA all base_bits are the same
        if !base_bits.iter().all(|&x| x as usize == base_bit) {
            panic!("Base bits are not all the same");
        }
        let base_bit_log = base_bit.next_power_of_two().ilog2() as usize;
        let base_log = base.next_power_of_two().ilog2() as usize;
        let num_decomps_per_field = base_bits.len();

        debug_assert_eq!(x1s.len(), input_bitlen);
        debug_assert_eq!(x2s.len(), input_bitlen);
        debug_assert_eq!(y1s.len(), input_bitlen);
        debug_assert_eq!(y2s.len(), input_bitlen);
        debug_assert_eq!(wires_c.len(), (3 * num_decomps_per_field) * input_bitlen);

        // Combine the inputs
        let mut input_bits_1 =
            Self::adder_mod_p_with_output_size::<_, F>(g, x1s, x2s, total_output_bitlen_per_field)?;
        let mut input_bits_2 =
            Self::adder_mod_p_with_output_size::<_, F>(g, y1s, y2s, total_output_bitlen_per_field)?;
        if total_output_bitlen_per_field < base_bit_log * num_decomps_per_field {
            input_bits_1.resize(base_bit_log * num_decomps_per_field, g.const_zero()?);
            input_bits_2.resize(base_bit_log * num_decomps_per_field, g.const_zero()?);
        }
        let mut results = Vec::with_capacity(input_bitlen * num_decomps_per_field);
        let mut rands = wires_c.chunks(input_bitlen);

        // Compose the inputs
        if base_bit.count_ones() == 1 {
            for inp in input_bits_1.chunks(base_bit_log) {
                results.extend(Self::compose_field_element::<_, F>(
                    g,
                    inp,
                    rands.next().unwrap(),
                )?);
            }
            for inp in input_bits_2.chunks(base_bit_log) {
                results.extend(Self::compose_field_element::<_, F>(
                    g,
                    inp,
                    rands.next().unwrap(),
                )?);
            }

            for chunk in input_bits_1.chunks(base_bit_log) {
                let mut accumulator = vec![g.const_zero()?; 64];
                if base.count_ones() != 1 {
                    panic!("Base is not a power of 2");
                }
                let base = base.ilog2() as usize;
                for (count, slice) in chunk.chunks(base).enumerate() {
                    let mut bit = if *table_type == SHA256Table::Choose {
                        Self::get_choose_normalization_table_value(g, slice)?
                    } else if *table_type == SHA256Table::Majority {
                        Self::get_majority_normalization_table_value(g, slice)?
                    } else {
                        Self::get_witness_extension_normalization_table_value(g, slice)?
                    };
                    debug_assert_eq!(bit.len(), 2);
                    bit.resize(bit.len() + count, g.const_zero()?);
                    bit.rotate_left(2);
                    bit.resize(64, g.const_zero()?);
                    accumulator = Self::bin_addition_no_carry(g, &accumulator, &bit)?;
                }
                results.extend(Self::compose_field_element::<_, F>(
                    g,
                    &accumulator,
                    rands.next().unwrap(),
                )?);
            }
        } else {
            let slices_inp1 = Self::bin_slicing_using_arbitrary_base(
                g,
                &input_bits_1,
                base_bit as u64,
                num_decomps_per_field,
            )?;
            for slice in slices_inp1.iter() {
                results.extend(Self::compose_field_element::<_, F>(
                    g,
                    slice,
                    rands.next().unwrap(),
                )?);
            }

            let slices_inp2 = Self::bin_slicing_using_arbitrary_base(
                g,
                &input_bits_2,
                base_bit as u64,
                num_decomps_per_field,
            )?;
            for slice in slices_inp2.iter() {
                results.extend(Self::compose_field_element::<_, F>(
                    g,
                    slice,
                    rands.next().unwrap(),
                )?);
            }
            if base_bit.count_ones() == 1 {
                panic!("Base is not a power of 2, should not happen");
            }
            for chunk in slices_inp1 {
                let num_decomps = chunk.len().div_ceil(base_log);
                let sliced_bits =
                    Self::bin_slicing_using_arbitrary_base(g, &chunk, base, num_decomps)?;
                let mut accumulator = vec![g.const_zero()?; 64];
                for (count, slice) in sliced_bits.iter().enumerate() {
                    let mut bit = if *table_type == SHA256Table::Choose {
                        Self::get_choose_normalization_table_value(g, slice)?
                    } else if *table_type == SHA256Table::Majority {
                        Self::get_majority_normalization_table_value(g, slice)?
                    } else {
                        Self::get_witness_extension_normalization_table_value(g, slice)?
                    };
                    debug_assert_eq!(bit.len(), 2);
                    bit.resize(bit.len() + count, g.const_zero()?);
                    bit.rotate_left(2);
                    bit.resize(64, g.const_zero()?);
                    accumulator = Self::bin_addition_no_carry(g, &accumulator, &bit)?;
                }
                results.extend(Self::compose_field_element::<_, F>(
                    g,
                    &accumulator,
                    rands.next().unwrap(),
                )?);
            }
        }

        Ok(results)
    }

    /// Slices field elements in chunks, then slices these again according to base, a specific circuit for the plookup accumulator in the builder. The field elements are represented as bitdecompositions x1s, x2s, y1s and y2s which need to be added first get the two inputs. The output is composed using wires_c. Base_bit is the size of the slice, rotation the the length of the rotation and total_output_bitlen_per_field is the amount of bits the output field elements have. return_type specifies whether it is then used as arithmetic shares of the binary representation or as one arithmetic share, depending on whether it is used for normalization or sbox.
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn slice_and_map_from_sparse_form_many<
        G: FancyBinary + FancyBinaryConstant,
        F: PrimeField,
    >(
        g: &mut G,
        wires_x1: &BinaryBundle<G::Item>,
        wires_x2: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        base_bits: &[u64],
        base: u64,
        total_output_bitlen_per_field: usize,
        return_type: ReturnType,
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        debug_assert_eq!(wires_x1.size(), wires_x2.size());
        let length = wires_x1.size();
        debug_assert_eq!(length % 2, 0);
        let num_decomps_per_field = base_bits.len();
        let num_inputs = length / input_bitlen;

        let total_output_elements = match return_type {
            ReturnType::BinaryAsArithmetic => {
                num_inputs * num_decomps_per_field + 8 * (num_inputs / 2) * num_decomps_per_field
            }
            ReturnType::Arithmetic => {
                num_inputs * num_decomps_per_field + (num_inputs / 2) * num_decomps_per_field
            }
        };
        debug_assert_eq!(wires_c.size(), total_output_elements * input_bitlen);
        debug_assert_eq!(length % input_bitlen, 0);

        let mut results = Vec::with_capacity(wires_c.size());
        let chunk_size = match return_type {
            ReturnType::BinaryAsArithmetic => (10 * num_decomps_per_field) * input_bitlen,
            ReturnType::Arithmetic => (3 * num_decomps_per_field) * input_bitlen,
        };
        for (chunk_x1, chunk_x2, chunk_y1, chunk_y2, chunk_c) in izip!(
            wires_x1.wires()[0..length / 2].chunks(input_bitlen),
            wires_x2.wires()[0..length / 2].chunks(input_bitlen),
            wires_x1.wires()[length / 2..].chunks(input_bitlen),
            wires_x2.wires()[length / 2..].chunks(input_bitlen),
            wires_c.wires().chunks(chunk_size),
        ) {
            let value = Self::slice_and_map_from_sparse_form::<G, F>(
                g,
                chunk_x1,
                chunk_x2,
                chunk_y1,
                chunk_y2,
                chunk_c,
                base_bits,
                base,
                total_output_bitlen_per_field,
                return_type,
            )?;
            results.extend(value);
        }

        Ok(BinaryBundle::new(results))
    }

    /// Slices field elements in chunks, then slices these again according to base, a specific circuit for the plookup accumulator in the builder. The field elements are represented as bitdecompositions x1s, x2s, y1s and y2s which need to be added first get the two inputs. The output is composed using wires_c. Base_bit is the size of the slice, rotation the the length of the rotation and total_output_bitlen_per_field is the amount of bits the output field elements have. return_type specifies whether it is then used as arithmetic shares of the binary representation or as one arithmetic share, depending on whether it is used for normalization or sbox.
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn slice_and_map_from_sparse_form<
        G: FancyBinary + FancyBinaryConstant,
        F: PrimeField,
    >(
        g: &mut G,
        x1s: &[G::Item],
        x2s: &[G::Item],
        y1s: &[G::Item],
        y2s: &[G::Item],
        wires_c: &[G::Item],
        base_bits: &[u64],
        base: u64,
        total_output_bitlen_per_field: usize,
        return_type: ReturnType,
    ) -> Result<Vec<G::Item>, G::Error> {
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        let base_bit = base_bits[0] as usize; // For AES all base_bits are the same
        if !base_bits.iter().all(|&x| x as usize == base_bit) {
            panic!("Base bits are not all the same");
        }
        let base_bit_log = base_bit.next_power_of_two().ilog2() as usize;
        let base_log = base.next_power_of_two().ilog2() as usize;
        let num_decomps_per_field = base_bits.len();

        debug_assert_eq!(x1s.len(), input_bitlen);
        debug_assert_eq!(x2s.len(), input_bitlen);
        debug_assert_eq!(y1s.len(), input_bitlen);
        debug_assert_eq!(y2s.len(), input_bitlen);
        if return_type == ReturnType::BinaryAsArithmetic {
            debug_assert_eq!(wires_c.len(), (10 * num_decomps_per_field) * input_bitlen);
        } else {
            debug_assert_eq!(wires_c.len(), (3 * num_decomps_per_field) * input_bitlen);
        }

        // Combine the inputs
        let mut input_bits_1 =
            Self::adder_mod_p_with_output_size::<_, F>(g, x1s, x2s, total_output_bitlen_per_field)?;
        let mut input_bits_2 =
            Self::adder_mod_p_with_output_size::<_, F>(g, y1s, y2s, total_output_bitlen_per_field)?;
        if total_output_bitlen_per_field < base_bit_log * num_decomps_per_field {
            input_bits_1.resize(base_bit_log * num_decomps_per_field, g.const_zero()?);
            input_bits_2.resize(base_bit_log * num_decomps_per_field, g.const_zero()?);
        }
        let mut results = Vec::with_capacity(input_bitlen * num_decomps_per_field);
        let mut rands = wires_c.chunks(input_bitlen);

        // Compose the inputs
        if base_bit.count_ones() == 1 {
            for inp in input_bits_1.chunks(base_bit_log) {
                results.extend(Self::compose_field_element::<_, F>(
                    g,
                    inp,
                    rands.next().unwrap(),
                )?);
            }
            for inp in input_bits_2.chunks(base_bit_log) {
                results.extend(Self::compose_field_element::<_, F>(
                    g,
                    inp,
                    rands.next().unwrap(),
                )?);
            }
            let zero = g.const_zero()?;
            if base.count_ones() == 1 {
                for chunk in input_bits_1.chunks(base_bit_log) {
                    let base = base.ilog2() as usize;
                    let mut counter = 0;
                    if return_type == ReturnType::BinaryAsArithmetic {
                        for slice in chunk.chunks(base) {
                            results.extend(Self::compose_field_element::<_, F>(
                                g,
                                &[slice[0].clone()],
                                rands.next().unwrap(),
                            )?);
                            counter += 1;
                        }
                        for _ in 0..8 - counter {
                            results.extend(Self::compose_field_element::<_, F>(
                                g,
                                std::slice::from_ref(&zero),
                                rands.next().unwrap(),
                            )?);
                        }
                    } else {
                        let mut result = Vec::with_capacity(chunk.len().div_ceil(base));
                        for slice in chunk.chunks(base) {
                            result.push(slice[0].clone());
                        }

                        results.extend(Self::compose_field_element::<_, F>(
                            g,
                            &result,
                            rands.next().unwrap(),
                        )?);
                    }
                }
            } else {
                for chunk in input_bits_1.chunks(base_bit_log) {
                    let num_decomps = chunk.len().next_power_of_two().div_ceil(base_log);

                    // TODO: we can optimize this slicing since we only need the first bit (by doing a modified subtraction and mul).
                    let mut sliced_bits =
                        Self::bin_slicing_using_arbitrary_base(g, chunk, base, num_decomps)?;
                    if return_type == ReturnType::BinaryAsArithmetic {
                        sliced_bits.resize(8, vec![g.const_zero()?]);

                        for slice in sliced_bits {
                            results.extend(Self::compose_field_element::<_, F>(
                                g,
                                &[slice[0].clone()],
                                rands.next().unwrap(),
                            )?);
                        }
                    } else {
                        let result: Vec<_> =
                            sliced_bits.iter().map(|slice| slice[0].clone()).collect();
                        results.extend(Self::compose_field_element::<_, F>(
                            g,
                            &result,
                            rands.next().unwrap(),
                        )?);
                    }
                }
            }
        } else {
            let slices_inp1 = Self::bin_slicing_using_arbitrary_base(
                g,
                &input_bits_1,
                base_bit as u64,
                num_decomps_per_field,
            )?;
            for slice in slices_inp1.iter() {
                results.extend(Self::compose_field_element::<_, F>(
                    g,
                    slice,
                    rands.next().unwrap(),
                )?);
            }

            let slices_inp2 = Self::bin_slicing_using_arbitrary_base(
                g,
                &input_bits_2,
                base_bit as u64,
                num_decomps_per_field,
            )?;

            for slice in slices_inp2.iter() {
                results.extend(Self::compose_field_element::<_, F>(
                    g,
                    slice,
                    rands.next().unwrap(),
                )?);
            }

            for chunk in slices_inp1 {
                let num_decomps = chunk.len().next_power_of_two().div_ceil(base_log);

                // TODO: we can optimize this slicing since we only need the first bit (by doing a modified subtraction and mul).
                let mut sliced_bits =
                    Self::bin_slicing_using_arbitrary_base(g, &chunk, base, num_decomps)?;
                if return_type == ReturnType::BinaryAsArithmetic {
                    sliced_bits.resize(8, vec![g.const_zero()?]);
                    for slice in sliced_bits {
                        results.extend(Self::compose_field_element::<_, F>(
                            g,
                            &[slice[0].clone()],
                            rands.next().unwrap(),
                        )?);
                    }
                } else {
                    let result: Vec<_> = sliced_bits.iter().map(|slice| slice[0].clone()).collect();
                    results.extend(Self::compose_field_element::<_, F>(
                        g,
                        &result,
                        rands.next().unwrap(),
                    )?);
                }
            }
        }

        Ok(results)
    }

    /// A custom circuit for the AES blackbox function. Slices the input in base chunks and then composes these together into one element.
    pub(crate) fn accumulate_from_sparse_bytes<
        G: FancyBinary + FancyBinaryConstant,
        F: PrimeField,
    >(
        g: &mut G,
        wires_x1: &BinaryBundle<G::Item>,
        wires_x2: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        input_bitsize: usize,
        output_bitsize: usize,
        base: u64,
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        debug_assert_eq!(wires_x1.size(), wires_x2.size());
        let length = wires_x1.size();
        let base_log = base.next_power_of_two().ilog2() as usize;
        let num_decomps_per_field = input_bitsize.div_ceil(base_log);

        let total_output_elements = 1;
        debug_assert_eq!(wires_c.size(), total_output_elements * input_bitlen);
        debug_assert_eq!(length % input_bitlen, 0);

        let mut result = Vec::with_capacity(input_bitlen * num_decomps_per_field);
        for (chunk_a, chunk_b) in izip!(
            wires_x1.wires().chunks(input_bitlen),
            wires_x2.wires().chunks(input_bitlen),
        ) {
            let input_bits =
                Self::adder_mod_p_with_output_size::<_, F>(g, chunk_a, chunk_b, input_bitsize)?;

            let mut value = Self::bin_slicing_using_arbitrary_base::<G>(
                g,
                &input_bits,
                base,
                num_decomps_per_field,
            )?;

            value.resize(output_bitsize, vec![g.const_zero()?]);
            value.reverse();
            for slice in value {
                result.insert(0, slice[0].clone());
            }
        }

        Ok(BinaryBundle::new(Self::compose_field_element::<_, F>(
            g,
            &result,
            wires_c.wires(),
        )?))
    }

    /// Slices a field element wrt to 'base' into 'num_decomps_per_field' many slices. Should be used for bases which are not powers of 2, because in that case you can just take the bits directly from the wire.
    pub fn bin_slicing_using_arbitrary_base<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        x: &[G::Item],
        base: u64,
        num_decomps_per_field: usize,
    ) -> Result<Vec<Vec<G::Item>>, G::Error> {
        let mut slices_inp: Vec<Vec<_>> = Vec::with_capacity(num_decomps_per_field);
        let mut input = x.to_vec();
        for _ in 0..num_decomps_per_field {
            let (b, k) = Self::bin_modulo_reduction(g, &input, base)?;
            slices_inp.push(b);
            input = k;
        }

        Ok(slices_inp)
    }

    /// Does a modulo reduction on the input 'x' using the modulus 'modulus'. Also returns the integer division of 'x' by 'modulus' as a vector, in case it is needed (e.g. for slicing).
    #[expect(clippy::type_complexity)]
    pub fn bin_modulo_reduction<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        x: &[G::Item],
        modulus: u64,
    ) -> Result<(Vec<G::Item>, Vec<G::Item>), G::Error> {
        let mut base_bit_vec: Vec<bool> = (0..u64::BITS)
            .rev()
            .map(|i| (modulus & (1 << i)) != 0)
            .skip_while(|&b| !b)
            .collect();
        base_bit_vec.reverse();
        if x.len() < base_bit_vec.len() {
            let zero = g.const_zero()?;
            let k = vec![zero.clone(); x.len()];
            return Ok((x.to_vec(), k.to_vec()));
        }
        let next_power_of_two = modulus.next_power_of_two();
        let base_ceil = next_power_of_two.ilog2() as usize;
        base_bit_vec.resize(x.len(), false);
        let k = Self::bin_div_by_public(g, x, &base_bit_vec)?;
        let km = Self::bin_mul_with_public(g, &k, &base_bit_vec)?;
        let b = Self::bin_subtraction(g, x, &km[..x.len()])?.0;
        Ok((b[..base_ceil].to_vec(), k))
    }

    /// Computes the Majority Normalization Table value for the given input. The input is expected to be of length 3. The arithmetization comes from a Moebius Transformation on the truth table.
    pub(crate) fn get_majority_normalization_table_value<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        x: &[G::Item],
    ) -> Result<Vec<G::Item>, G::Error> {
        debug_assert!(x.len() >= 3);
        let x1_and_x2 = g.and(&x[1], &x[2])?;
        let x1_xor_x2 = g.xor(&x[1], &x[2])?;
        Ok([x1_xor_x2, x1_and_x2].to_vec())
    }

    /// Computes the Choose Normalization Table value for the given input. The input is expected to be of length 5. The arithmetization comes from a Moebius Transformation on the truth table.
    pub(crate) fn get_choose_normalization_table_value<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        x: &[G::Item],
    ) -> Result<Vec<G::Item>, G::Error> {
        debug_assert_eq!(x.len(), 5);
        let x0_and_x1 = g.and(&x[0], &x[1])?;
        let x0_and_x2 = g.and(&x[0], &x[2])?;
        let x1_and_x2 = g.and(&x[1], &x[2])?;
        let x1_and_x3 = g.and(&x[1], &x[3])?;
        let x2_and_x3 = g.and(&x[2], &x[3])?;
        let x0_and_x4 = g.and(&x[0], &x[4])?;
        let x2_and_x4 = g.and(&x[2], &x[4])?;
        let x3_and_x4 = g.and(&x[3], &x[4])?;
        let x0_and_x1_and_x3 = g.and(&x0_and_x1, &x[3])?;
        let x0_and_x2_and_x3 = g.and(&x0_and_x2, &x[3])?;
        let x0_and_x1_and_x4 = g.and(&x0_and_x1, &x[4])?;
        let x0_and_x3_and_x4 = g.and(&x0_and_x4, &x[3])?;
        let x1_and_x3_and_x4 = g.and(&x1_and_x3, &x[4])?;
        let x1_and_x2_and_x4 = g.and(&x1_and_x2, &x[4])?;
        let x0_and_x1_and_x2_and_x3 = g.and(&x0_and_x1_and_x3, &x[2])?;
        let x0_and_x1_and_x3_and_x4 = g.and(&x0_and_x1_and_x3, &x[4])?;

        let mut shared_sum = g.xor(&x1_and_x3, &x1_and_x3_and_x4)?;
        shared_sum = g.xor(&shared_sum, &x2_and_x3)?;
        shared_sum = g.xor(&shared_sum, &x0_and_x1_and_x2_and_x3)?;
        shared_sum = g.xor(&shared_sum, &x3_and_x4)?;

        let mut f1 = g.xor(&shared_sum, &x0_and_x1)?;

        f1 = g.xor(&f1, &x0_and_x2)?;
        f1 = g.xor(&f1, &x1_and_x2)?;
        f1 = g.xor(&f1, &x[3])?;
        f1 = g.xor(&f1, &x0_and_x2_and_x3)?;
        f1 = g.xor(&f1, &x0_and_x4)?;
        f1 = g.xor(&f1, &x0_and_x1_and_x4)?;
        f1 = g.xor(&f1, &x2_and_x4)?;
        f1 = g.xor(&f1, &x1_and_x2_and_x4)?;
        f1 = g.xor(&f1, &x0_and_x1_and_x3_and_x4)?;

        let mut f2 = g.xor(&shared_sum, &x0_and_x1_and_x3)?;
        f2 = g.xor(&f2, &x0_and_x3_and_x4)?;

        Ok([f1, f2].to_vec())
    }

    /// Computes the Witness Extension Normalization Table value for the given input. The input is expected to be of length 3. The arithmetization comes from a Moebius Transformation on the truth table.
    pub(crate) fn get_witness_extension_normalization_table_value<
        G: FancyBinary + FancyBinaryConstant,
    >(
        g: &mut G,
        x: &[G::Item],
    ) -> Result<Vec<G::Item>, G::Error> {
        debug_assert!(x.len() >= 3);
        let x0_and_x2 = g.and(&x[0], &x[2])?;
        let x0_xor_x2 = g.xor(&x[0], &x[2])?;
        Ok([x0_xor_x2, x0_and_x2].to_vec())
    }

    /// The sha256 round constants, used by [`Self::sha256_block_sparse_trace`].
    const SHA256_ROUND_CONSTANTS: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    /// Number of output bits produced by [`Self::sha256_block_sparse_trace`]:
    /// 193 rotation reads x 32 key bits + 64 ChOutput reads x 32 x (5 + 2) bits
    /// + 64 MajOutput reads x 32 x (4 + 2) bits + 48 WitnessOutput reads x 32 x (4 + 2) bits.
    pub const SHA256_BLOCK_SPARSE_TRACE_OUTPUT_BITS: usize = 42_016;

    /// Multiplies a 2-bit value s = lo + 2 * hi (s <= 3) by the public constant 7, returning the
    /// 5-bit result 7 * s <= 21. Used for the choose-digit weighting in
    /// [`Self::sha256_block_sparse_trace`]. Costs 1 AND gate.
    fn sha256_mul7_2bit<G: FancyBinary>(
        g: &mut G,
        lo: &G::Item,
        hi: &G::Item,
    ) -> Result<Vec<G::Item>, G::Error> {
        let both = g.and(lo, hi)?;
        let m1 = g.xor(lo, hi)?;
        // lo | hi == (lo ^ hi) ^ (lo & hi)
        let m2 = g.xor(&m1, &both)?;
        // hi & !lo == hi ^ (lo & hi)
        let m3 = g.xor(hi, &both)?;
        // 7 * 0 = 00000, 7 * 1 = 00111, 7 * 2 = 01110, 7 * 3 = 10101 (LSB first below)
        Ok(vec![lo.to_owned(), m1, m2, m3, both])
    }

    /// Computes e + 2f + 3g (<= 6) of three input bits as 3 output bits (LSB first).
    /// Costs 3 AND gates.
    fn sha256_e_plus_2f_plus_3g<G: FancyBinary>(
        g: &mut G,
        e: &G::Item,
        f: &G::Item,
        gg: &G::Item,
    ) -> Result<Vec<G::Item>, G::Error> {
        // e + 2f + 3g = (e + g) + 2 * (f + g)
        let (u0, u1) = Self::half_adder(g, e, gg)?;
        let (v0, v1) = Self::half_adder(g, f, gg)?;
        // No carry out of bit 2: v1 = 1 forces f = g = 1, hence v0 = 0 and the bit-1 carry c = 0.
        let (r1, c) = Self::half_adder(g, &u1, &v0)?;
        let r2 = g.xor(&v1, &c)?;
        Ok(vec![u0, r1, r2])
    }

    /// Adds a 5-bit value (<= 21) and a 3-bit value (<= 6). The sum is < 32, so the result is 5
    /// bits with no output carry. Costs 4 AND gates.
    fn sha256_add_5bit_3bit<G: FancyBinary>(
        g: &mut G,
        m: &[G::Item],
        r: &[G::Item],
    ) -> Result<Vec<G::Item>, G::Error> {
        debug_assert_eq!(m.len(), 5);
        debug_assert_eq!(r.len(), 3);
        let (d0, c) = Self::half_adder(g, &m[0], &r[0])?;
        let (d1, c) = Self::full_adder(g, &m[1], &r[1], &c)?;
        let (d2, c) = Self::full_adder(g, &m[2], &r[2], &c)?;
        let (d3, c) = Self::half_adder(g, &m[3], &c)?;
        let d4 = g.xor(&m[4], &c)?;
        Ok(vec![d0, d1, d2, d3, d4])
    }

    /// Adds the public 32-bit constant `c` to the 32-bit value `xs`, mod 2^32.
    ///
    /// NOTE: [`Self::bin_addition_constant_no_carry`] is NOT used here because its underlying
    /// [`Self::half_adder_const`] returns carry = a even for b = false (wrong: the carry of
    /// a + 0 is 0). All existing callers pass constants with LSB 1, so that path is unreached
    /// today; this function handles arbitrary constants by skipping the low zero run of `c`.
    /// Costs at most 30 AND gates.
    fn sha256_add_constant_low32<G: FancyBinary>(
        g: &mut G,
        xs: &[G::Item],
        c: u32,
    ) -> Result<Vec<G::Item>, G::Error> {
        debug_assert_eq!(xs.len(), 32);
        if c == 0 {
            return Ok(xs.to_vec());
        }
        let lowest = c.trailing_zeros() as usize;
        let mut result = Vec::with_capacity(32);
        // below the lowest set bit of c no carries can occur
        for x in xs.iter().take(lowest) {
            result.push(x.to_owned());
        }
        // at the lowest set bit: x + 1 has sum !x and carry x (the b = true half-adder path)
        let (s, mut carry) = Self::half_adder_const(g, &xs[lowest], true)?;
        result.push(s);
        for (i, x) in xs.iter().enumerate().take(31).skip(lowest + 1) {
            let (s, c_) = Self::full_adder_const(g, x, (c >> i) & 1 == 1, &carry)?;
            carry = c_;
            result.push(s);
        }
        if lowest < 31 {
            // top bit: sum only, no carry out needed
            let z = if (c >> 31) & 1 == 1 {
                g.negate(&xs[31])?
            } else {
                xs[31].to_owned()
            };
            result.push(g.xor(&z, &carry)?);
        }
        debug_assert_eq!(result.len(), 32);
        Ok(result)
    }

    /// Given the per-digit Moebius output bits f1, f2 (with table[d_i] = f1_i + 2 * f2_i) of all
    /// 32 digits of a sha256 normalization read, computes the normalized value
    /// sum_i table[d_i] * 2^i mod 2^32, i.e. the low 32 bits of f1 + 2 * f2 over the integers.
    /// Costs 30 AND gates.
    fn sha256_normalization_value_low32<G: FancyBinary>(
        g: &mut G,
        f1: &[G::Item],
        f2: &[G::Item],
    ) -> Result<Vec<G::Item>, G::Error> {
        debug_assert_eq!(f1.len(), 32);
        debug_assert_eq!(f2.len(), 32);
        let mut result = Vec::with_capacity(32);
        result.push(f1[0].to_owned());
        let (s, mut c) = Self::half_adder(g, &f1[1], &f2[0])?;
        result.push(s);
        for i in 2..31 {
            let (s, c_) = Self::full_adder(g, &f1[i], &f2[i - 1], &c)?;
            c = c_;
            result.push(s);
        }
        let z = g.xor(&f1[31], &f2[30])?;
        result.push(g.xor(&z, &c)?);
        Ok(result)
    }

    /// Computes, in ONE circuit, the bits underlying ALL 369 sha256 plookup reads that the
    /// builder gadget `sha256_block` (co-builder sha_compression.rs) performs for one compression
    /// call with shared state and message. Every witness value the gadget needs (key slices,
    /// sparse forms, rotated sparse forms, normalized values) is a public-weight linear
    /// combination of these bits, so a driver can serve all 369 reads from a single invocation.
    ///
    /// Inputs: `wires_x1`/`wires_x2` are the bit decompositions of two field-share summands per
    /// input (added mod p inside the circuit, exactly as in [`Self::sha256_compression`]) for the
    /// 24 inputs `h_init[0..8] || w_in[0..16]`; each input is taken mod 2^32.
    ///
    /// Output layout (one group per plookup read, in the gadget's exact read order; all bit
    /// vectors LSB first):
    /// 1. The 4 init sparse-form reads (sha_compression.rs:133-138): Sha256MajInput keyed on
    ///    h_init[1], MajInput on h_init[2], Sha256ChInput on h_init[5], ChInput on h_init[6];
    ///    32 key bits each.
    /// 2. The message schedule (extend_witness, sha_compression.rs:200-336), iterations
    ///    i = 16..64. Per iteration, in order: a Sha256WitnessInput read of w[i-15] and/or of
    ///    w[i-2] (32 key bits each) if not yet converted (lazy `has_sparse_limbs` order; 61 reads
    ///    total), then the Sha256WitnessOutput read: 32 digit groups `[d0, d1, d2, d3, f1, f2]`
    ///    where d is the base-16 digit of the read key (d = sigma1_popcount + 4 * sigma0_popcount,
    ///    always <= 15) and table[d] = f1 + 2 * f2 is its
    ///    WITNESS_EXTENSION_NORMALIZATION_TABLE value; 192 bits per read.
    /// 3. The round loop (sha_compression.rs:144-158), rounds i = 0..64. Per round, in order: the
    ///    Sha256ChInput read (32 bits of register e); the Sha256ChOutput read: 32 digit groups
    ///    `[d0..d4, f1, f2]` with d = e + 2f + 3g + 7 * Sigma1_popcount <= 27 the base-28 digit
    ///    and table[d] = f1 + 2 * f2 its CHOOSE_NORMALIZATION_TABLE value (224 bits); the
    ///    Sha256MajInput read (32 bits of register a); the Sha256MajOutput read: 32 digit groups
    ///    `[d0..d3, f1, f2]` with d = a + b + c + 4 * Sigma0_popcount <= 15 the base-16 digit and
    ///    table[d] = f1 + 2 * f2 its MAJORITY_NORMALIZATION_TABLE value (192 bits).
    ///
    /// Totals [`Self::SHA256_BLOCK_SPARSE_TRACE_OUTPUT_BITS`] = 42,016 bits.
    ///
    /// Carry-freeness of the digit forms is structural (the bb plookup encoding sizes the
    /// normalization tables so that no base digit ever carries); it is re-verified exhaustively
    /// against the carry-generic plain accumulation in the co-builder unit tests
    /// (sha_compression_sparse_trace_tests.rs).
    pub fn sha256_block_sparse_trace<G: FancyBinary + FancyBinaryConstant, F: PrimeField>(
        g: &mut G,
        wires_x1: &BinaryBundle<G::Item>,
        wires_x2: &BinaryBundle<G::Item>,
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        debug_assert_eq!(wires_x1.size(), 24 * input_bitlen);
        debug_assert_eq!(wires_x2.size(), 24 * input_bitlen);

        // Input stage: recombine the two share summands of each input mod p, keep the low 32 bits
        let mut words = Vec::with_capacity(24);
        for (chunk_x1, chunk_x2) in izip!(
            wires_x1.wires().chunks(input_bitlen),
            wires_x2.wires().chunks(input_bitlen)
        ) {
            words.push(Self::adder_mod_p_with_output_size::<_, F>(
                g, chunk_x1, chunk_x2, 32,
            )?);
        }
        // regs = [a, b, c, d, e, f, g, h] (sha_compression.rs:132-139), w = message schedule
        let mut w: Vec<Vec<G::Item>> = words.split_off(8);
        let mut regs = words;

        let mut outputs: Vec<G::Item> =
            Vec::with_capacity(Self::SHA256_BLOCK_SPARSE_TRACE_OUTPUT_BITS);

        // 1. Init sparse-form reads: MajInput(b), MajInput(c), ChInput(f), ChInput(g)
        outputs.extend_from_slice(&regs[1]);
        outputs.extend_from_slice(&regs[2]);
        outputs.extend_from_slice(&regs[5]);
        outputs.extend_from_slice(&regs[6]);

        // 2. Message schedule, mirroring extend_witness's value flow
        let mut converted = [false; 64];
        for i in 16..64 {
            // lazy WitnessInput conversion reads (sha_compression.rs:201-208)
            for j in [i - 15, i - 2] {
                if !converted[j] {
                    outputs.extend_from_slice(&w[j]);
                    converted[j] = true;
                }
            }
            let mut f1 = Vec::with_capacity(32);
            let mut f2 = Vec::with_capacity(32);
            {
                let (wl, wr) = (&w[i - 15], &w[i - 2]);
                for k in 0..32 {
                    // WitnessOutput key digit_k = right_k + 4 * left_k with
                    // left_k  = wl[(k+7)%32] + wl[(k+18)%32] + wl[k+3]   (sigma0; shr-3 term
                    //           absent for k > 28)
                    // right_k = wr[(k+17)%32] + wr[(k+19)%32] + wr[k+10] (sigma1; shr-10 term
                    //           absent for k > 21)
                    let left = if k + 3 < 32 {
                        Self::full_adder(g, &wl[(k + 7) % 32], &wl[(k + 18) % 32], &wl[k + 3])?
                    } else {
                        Self::half_adder(g, &wl[(k + 7) % 32], &wl[(k + 18) % 32])?
                    };
                    let right = if k + 10 < 32 {
                        Self::full_adder(g, &wr[(k + 17) % 32], &wr[(k + 19) % 32], &wr[k + 10])?
                    } else {
                        Self::half_adder(g, &wr[(k + 17) % 32], &wr[(k + 19) % 32])?
                    };
                    let digit = [right.0, right.1, left.0, left.1];
                    let moebius = Self::get_witness_extension_normalization_table_value(g, &digit)?;
                    outputs.extend_from_slice(&digit);
                    outputs.extend_from_slice(&moebius);
                    f1.push(moebius[0].to_owned());
                    f2.push(moebius[1].to_owned());
                }
            }
            // xor_result = sigma0(w[i-15]) + sigma1(w[i-2]) (integer sum); the gadget's
            // w_out = (xor_result + w[i-16] + w[i-7]) & (2^32 - 1) (sha_compression.rs:304-333)
            let xor_result = Self::sha256_normalization_value_low32(g, &f1, &f2)?;
            let tmp = Self::bin_addition_no_carry(g, &xor_result, &w[i - 16])?;
            let w_out = Self::bin_addition_no_carry(g, &tmp, &w[i - 7])?;
            w.push(w_out);
        }

        // 3. Round loop
        for (i, k_const) in Self::SHA256_ROUND_CONSTANTS.iter().enumerate() {
            // choose: ChInput read on e, then the ChOutput read digits
            outputs.extend_from_slice(&regs[4]);
            let mut ch_f1 = Vec::with_capacity(32);
            let mut ch_f2 = Vec::with_capacity(32);
            {
                let (e_reg, f_reg, g_reg) = (&regs[4], &regs[5], &regs[6]);
                for k in 0..32 {
                    let rot = Self::full_adder(
                        g,
                        &e_reg[(k + 6) % 32],
                        &e_reg[(k + 11) % 32],
                        &e_reg[(k + 25) % 32],
                    )?;
                    let m = Self::sha256_mul7_2bit(g, &rot.0, &rot.1)?;
                    let r = Self::sha256_e_plus_2f_plus_3g(g, &e_reg[k], &f_reg[k], &g_reg[k])?;
                    // digit = e + 2f + 3g + 7 * (rot6 + rot11 + rot25) <= 27
                    let digit = Self::sha256_add_5bit_3bit(g, &m, &r)?;
                    let moebius = Self::get_choose_normalization_table_value(g, &digit)?;
                    outputs.extend_from_slice(&digit);
                    outputs.extend_from_slice(&moebius);
                    ch_f1.push(moebius[0].to_owned());
                    ch_f2.push(moebius[1].to_owned());
                }
            }
            // ch = Sigma1(e) + Ch(e, f, g) (integer sum), reduced mod 2^32
            let ch = Self::sha256_normalization_value_low32(g, &ch_f1, &ch_f2)?;

            // majority: MajInput read on a, then the MajOutput read digits
            outputs.extend_from_slice(&regs[0]);
            let mut maj_f1 = Vec::with_capacity(32);
            let mut maj_f2 = Vec::with_capacity(32);
            {
                let (a_reg, b_reg, c_reg) = (&regs[0], &regs[1], &regs[2]);
                for k in 0..32 {
                    let sum = Self::full_adder(g, &a_reg[k], &b_reg[k], &c_reg[k])?;
                    let rot = Self::full_adder(
                        g,
                        &a_reg[(k + 2) % 32],
                        &a_reg[(k + 13) % 32],
                        &a_reg[(k + 22) % 32],
                    )?;
                    // digit = (a + b + c) + 4 * (rot2 + rot13 + rot22) <= 15: a free concat
                    let digit = [sum.0, sum.1, rot.0, rot.1];
                    let moebius = Self::get_majority_normalization_table_value(g, &digit)?;
                    outputs.extend_from_slice(&digit);
                    outputs.extend_from_slice(&moebius);
                    maj_f1.push(moebius[0].to_owned());
                    maj_f2.push(moebius[1].to_owned());
                }
            }
            // maj = Sigma0(a) + Maj(a, b, c) (integer sum), reduced mod 2^32
            let maj = Self::sha256_normalization_value_low32(g, &maj_f1, &maj_f2)?;

            // temp1 = ch + h + w[i] + K[i]; e' = d + temp1; a' = temp1 + maj, all mod 2^32
            // (add_normalize_unsafe reduces mod 2^32, field_ct.rs:1944-1993)
            let wk = Self::sha256_add_constant_low32(g, &w[i], *k_const)?;
            let tmp = Self::bin_addition_no_carry(g, &ch, &regs[7])?;
            let temp1 = Self::bin_addition_no_carry(g, &tmp, &wk)?;
            let e_new = Self::bin_addition_no_carry(g, &regs[3], &temp1)?;
            let a_new = Self::bin_addition_no_carry(g, &temp1, &maj)?;

            // register shift (sha_compression.rs:150-157)
            regs[7] = regs[6].to_owned();
            regs[6] = regs[5].to_owned();
            regs[5] = regs[4].to_owned();
            regs[4] = e_new;
            regs[3] = regs[2].to_owned();
            regs[2] = regs[1].to_owned();
            regs[1] = regs[0].to_owned();
            regs[0] = a_new;
        }

        debug_assert_eq!(outputs.len(), Self::SHA256_BLOCK_SPARSE_TRACE_OUTPUT_BITS);
        Ok(BinaryBundle::new(outputs))
    }

    /// Evaluates [`Self::sha256_block_sparse_trace`] on cleartext inputs using
    /// [`CleartextBinaryEvaluator`] (two field summands per input, added mod p inside the
    /// circuit; order h_init[0..8] || w_in[0..16]). Returns the output bits in the documented
    /// order together with the number of AND gates of the composed circuit. Test/KAT support: no
    /// garbling, no networking.
    pub fn sha256_block_sparse_trace_cleartext<F: PrimeField>(
        x1: &[F],
        x2: &[F],
    ) -> Result<(Vec<bool>, usize), FancyError> {
        assert_eq!(x1.len(), 24);
        assert_eq!(x2.len(), 24);
        let encode = |xs: &[F]| {
            BinaryBundle::new(
                xs.iter()
                    .flat_map(|x| GCUtils::field_to_bits(*x))
                    .map(CleartextBit)
                    .collect(),
            )
        };
        let mut g = CleartextBinaryEvaluator::default();
        let result =
            Self::sha256_block_sparse_trace::<_, F>(&mut g, &encode(x1), &encode(x2))?;
        Ok((
            result.wires().iter().map(|bit| bit.0).collect(),
            g.num_and_gates,
        ))
    }

    /// Computes the SHA256 compression using a Bristol fashion circuit which is first parsed from a .txt file. The field elements are represented as bitdecompositions x1s, x2s, y1s and y2s which need to be added first to get the two inputs. The output is composed using wires_c.
    pub(crate) fn sha256_compression<
        G: FancyBinary + FancyBinaryConstant + BristolFashionEvaluator<WireValue = G::Item>,
        F: PrimeField,
    >(
        g: &mut G,
        wires_x1: &BinaryBundle<G::Item>,
        wires_x2: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        state_length: usize,
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;

        // Reading the circuit from txt file
        let circuit = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/protocols/rep3/yao/bristol_fashion/circuit_files/sha256.txt"
        ));
        let circuit_read =
            BristolFashionCircuit::from_reader(circuit.as_bytes()).expect("sha256 circuit works");

        let mut state = Vec::new();
        let mut message = Vec::new();

        for (chunk_x1, chunk_x2) in izip!(
            wires_x1.wires()[..state_length * input_bitlen].chunks(input_bitlen),
            wires_x2.wires()[..state_length * input_bitlen].chunks(input_bitlen)
        ) {
            let mut state_bits =
                Self::adder_mod_p_with_output_size::<_, F>(g, chunk_x1, chunk_x2, 32)?;
            state_bits.reverse();
            state.extend(state_bits);
        }
        for (chunk_y1, chunk_y2) in izip!(
            wires_x1.wires()[state_length * input_bitlen..].chunks(input_bitlen),
            wires_x2.wires()[state_length * input_bitlen..].chunks(input_bitlen),
        ) {
            let mut message_bits =
                Self::adder_mod_p_with_output_size::<_, F>(g, chunk_y1, chunk_y2, 32)?;
            message_bits.reverse();
            message.extend(message_bits);
        }

        message.reverse();
        state.reverse();

        let input = [message, state];
        let zero = g.const_zero()?;
        let mut output = circuit_read
            .evaluate_with_default::<G::Item>(&input, g, zero)
            .map_err(|e| e.into())?;
        let mut result = output.pop().ok_or(FancyError::InvalidArg(
            "No output found in circuit evaluation".to_string(),
        ))?;
        let mut results = Vec::with_capacity(result.len());

        // the input (and the output) for the bristol circuit is in reversed order
        result.reverse();
        for chunk in result.chunks_mut(32) {
            chunk.reverse();
        }

        for (xs, ys) in izip!(result.chunks(32), wires_c.wires().chunks(input_bitlen)) {
            let result = Self::compose_field_element::<_, F>(g, xs, ys)?;
            results.extend(result);
        }

        Ok(BinaryBundle::new(results))
    }

    /// Computes the BLAKE2s hash of 'num_inputs' inputs, each of 'num_bits' bits (rounded to next multiple of 8). The inputs are given as two bitdecompositions wires_a and wires_b, and the output is composed using wires_c. The output is then compose into size 32 Vec of field elements.
    pub(crate) fn blake2s<G: FancyBinary + FancyBinaryConstant, F: PrimeField>(
        g: &mut G,
        wires_a: &BinaryBundle<G::Item>,
        wires_b: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        num_inputs: usize,
        num_bits: usize,
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        let mut input = Vec::new();
        let mut rands = wires_c.wires().chunks(input_bitlen);
        let bits = num_bits.div_ceil(8) * 8; // We need to round to the next byte
        for (chunk_x1, chunk_x2) in izip!(
            wires_a.wires().chunks(input_bitlen),
            wires_b.wires().chunks(input_bitlen),
        ) {
            let tmp = Self::adder_mod_p_with_output_size::<_, F>(g, chunk_x1, chunk_x2, bits)?;
            for chunk in tmp.chunks(8) {
                input.push(chunk.to_owned())
            }
        }

        // The actual hash
        debug_assert_eq!(input.len(), num_inputs);
        let blocks = num_inputs.div_ceil(64);
        let mut counter: u64 = 0;
        let mut h = Vec::with_capacity(Self::IV.len());
        for inp in Self::IV {
            h.push(Self::constant_bundle_from_u32(g, inp, 32)?);
        }

        let zero = vec![g.const_zero()?; 32];
        let tmp = Self::constant_bundle_from_u32(g, 0x01010020, 32)?; // no key provided; = 0x0101kknn where kk is key length and nn is output length
        h[0] = Self::xor_many_as_wires(g, &h[0], &tmp)?;

        if num_inputs > 0 {
            let mut tmp: [_; 16] = core::array::from_fn(|_| zero.clone());
            for inp in input.chunks(64).take(blocks - 1) {
                counter += 64;
                let t = [counter as u32, (counter >> 32) as u32];

                for (i, inp) in inp.iter().enumerate() {
                    let shift = (i % 4) * 8;
                    tmp[i / 4]
                        .iter_mut()
                        .skip(shift)
                        .zip(inp.iter())
                        .for_each(|(a, b)| {
                            *a = b.clone();
                        });
                }
                h = Self::blake2s_compress(g, &tmp, &h, t, [0, 0])?;
            }
        }

        let mut bytes = num_inputs % 64;
        if num_inputs > 0 && bytes == 0 {
            bytes = 64;
        }
        counter += bytes as u64;
        let t = [counter as u32, (counter >> 32) as u32];

        let mut tmp: [_; 16] = core::array::from_fn(|_| zero.clone());
        if num_inputs > 0 {
            for (i, inp) in input.iter().skip(64 * (blocks - 1)).enumerate() {
                let shift = (i % 4) * 8;
                tmp[i / 4]
                    .iter_mut()
                    .skip(shift)
                    .zip(inp.iter())
                    .for_each(|(a, b)| {
                        *a = b.clone();
                    });
            }
        }

        h = Self::blake2s_compress(g, &tmp, &h, t, [0xFFFFFFFF, 0])?;

        // Compose the output
        let mut result = Vec::new();
        for res in h {
            for chunk in res.chunks(8) {
                result.extend(Self::compose_field_element::<_, F>(
                    g,
                    chunk,
                    rands.next().unwrap(),
                )?)
            }
        }
        Ok(BinaryBundle::new(result))
    }

    pub(crate) fn blake2s_compress<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        input: &[Vec<G::Item>],
        h: &[Vec<G::Item>],
        t: [u32; 2],
        f: [u32; 2],
    ) -> Result<Vec<Vec<G::Item>>, G::Error> {
        let mut state = Vec::with_capacity(16);
        for inp in h {
            state.push(inp.to_vec());
        }
        for inp in Self::IV.iter().take(4) {
            state.push(Self::constant_bundle_from_u32(g, *inp, 32)?);
        }
        state.push(Self::constant_bundle_from_u32(g, Self::IV[4] ^ t[0], 32)?);
        state.push(Self::constant_bundle_from_u32(g, Self::IV[5] ^ t[1], 32)?);
        state.push(Self::constant_bundle_from_u32(g, Self::IV[6] ^ f[0], 32)?);
        state.push(Self::constant_bundle_from_u32(g, Self::IV[7] ^ f[1], 32)?);

        for r in 0..10 {
            let sr = Self::SIGMA_BLAKE2[r];
            let res = Self::blake2s_mix(
                g,
                &state[0],
                &state[4],
                &state[8],
                &state[12],
                &input[sr[0] as usize],
                &input[sr[1] as usize],
            )?; // Column 0
            state[0] = res.0;
            state[4] = res.1;
            state[8] = res.2;
            state[12] = res.3;
            let res = Self::blake2s_mix(
                g,
                &state[1],
                &state[5],
                &state[9],
                &state[13],
                &input[sr[2] as usize],
                &input[sr[3] as usize],
            )?; // Column 1
            state[1] = res.0;
            state[5] = res.1;
            state[9] = res.2;
            state[13] = res.3;
            let res = Self::blake2s_mix(
                g,
                &state[2],
                &state[6],
                &state[10],
                &state[14],
                &input[sr[4] as usize],
                &input[sr[5] as usize],
            )?; // Column 2
            state[2] = res.0;
            state[6] = res.1;
            state[10] = res.2;
            state[14] = res.3;
            let res = Self::blake2s_mix(
                g,
                &state[3],
                &state[7],
                &state[11],
                &state[15],
                &input[sr[6] as usize],
                &input[sr[7] as usize],
            )?; // Column 3
            state[3] = res.0;
            state[7] = res.1;
            state[11] = res.2;
            state[15] = res.3;
            let res = Self::blake2s_mix(
                g,
                &state[0],
                &state[5],
                &state[10],
                &state[15],
                &input[sr[8] as usize],
                &input[sr[9] as usize],
            )?; // Diagonal 1 (main diagonal)
            state[0] = res.0;
            state[5] = res.1;
            state[10] = res.2;
            state[15] = res.3;
            let res = Self::blake2s_mix(
                g,
                &state[1],
                &state[6],
                &state[11],
                &state[12],
                &input[sr[10] as usize],
                &input[sr[11] as usize],
            )?; // Diagonal 2
            state[1] = res.0;
            state[6] = res.1;
            state[11] = res.2;
            state[12] = res.3;
            let res = Self::blake2s_mix(
                g,
                &state[2],
                &state[7],
                &state[8],
                &state[13],
                &input[sr[12] as usize],
                &input[sr[13] as usize],
            )?; // Diagonal 3
            state[2] = res.0;
            state[7] = res.1;
            state[8] = res.2;
            state[13] = res.3;
            let res = Self::blake2s_mix(
                g,
                &state[3],
                &state[4],
                &state[9],
                &state[14],
                &input[sr[14] as usize],
                &input[sr[15] as usize],
            )?; // Diagonal 4
            state[3] = res.0;
            state[4] = res.1;
            state[9] = res.2;
            state[14] = res.3;
        }
        let mut result = Vec::new();
        for (i, inp) in h.iter().enumerate() {
            let tmp = Self::xor_many_as_wires(g, &state[i], &state[i + 8])?;
            let tmp = Self::xor_many_as_wires(g, inp, &tmp)?;
            result.push(tmp);
        }
        Ok(result)
    }

    #[expect(clippy::type_complexity)]
    fn blake2s_mix<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        a: &[G::Item],
        b: &[G::Item],
        c: &[G::Item],
        d: &[G::Item],
        x: &[G::Item],
        y: &[G::Item],
    ) -> Result<(Vec<G::Item>, Vec<G::Item>, Vec<G::Item>, Vec<G::Item>), G::Error> {
        let mut a = Self::bin_addition_no_carry(g, a, b)?;
        a = Self::bin_addition_no_carry(g, &a, x)?;
        let mut d = Self::xor_many_as_wires(g, d, &a)?;
        d.rotate_left(16);
        let mut c = Self::bin_addition_no_carry(g, c, &d)?;
        let mut b = Self::xor_many_as_wires(g, b, &c)?;
        b.rotate_left(12);
        a = Self::bin_addition_no_carry(g, &a, &b)?;
        a = Self::bin_addition_no_carry(g, &a, y)?;
        d = Self::xor_many_as_wires(g, &d, &a)?;
        d.rotate_left(8);
        c = Self::bin_addition_no_carry(g, &c, &d)?;
        b = Self::xor_many_as_wires(g, &b, &c)?;
        b.rotate_left(7);

        Ok((a, b, c, d))
    }
    const IV: [u32; 8] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
        0x5BE0CD19,
    ];

    const SIGMA_BLAKE2: [[u8; 16]; 10] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    ];

    /// Computes the BLAKE3 hash of 'num_inputs' inputs, each of 'num_bits' bits (rounded to next multiple of 8). The inputs are given as two bitdecompositions wires_a and wires_b, and the output is composed using wires_c. The output is then compose into size 32 Vec of field elements.
    pub(crate) fn blake3<G: FancyBinary + FancyBinaryConstant, F: PrimeField>(
        g: &mut G,
        wires_a: &BinaryBundle<G::Item>,
        wires_b: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        num_inputs: usize,
        num_bits: usize,
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        let mut input = Vec::new();
        let mut rands = wires_c.wires().chunks(input_bitlen);
        let bits = num_bits.div_ceil(8) * 8; // We need to round to the next byte
        for (chunk_x1, chunk_x2) in izip!(
            wires_a.wires().chunks(input_bitlen),
            wires_b.wires().chunks(input_bitlen),
        ) {
            let tmp = Self::adder_mod_p_with_output_size::<_, F>(g, chunk_x1, chunk_x2, bits)?;
            for chunk in tmp.chunks(8) {
                input.push(chunk.to_owned())
            }
        }

        // The actual hash
        debug_assert_eq!(input.len(), num_inputs);

        let root_flag: u32 = 8;
        let parent_flag: u32 = 4;

        let mut result = Vec::new();
        if num_inputs <= 1024 {
            let h = Self::blake3_chunk_chaining(g, &input, 0, root_flag)?;

            // Compose the output
            for res in h {
                for chunk in res.chunks(8) {
                    result.extend(Self::compose_field_element::<_, F>(
                        g,
                        chunk,
                        rands.next().unwrap(),
                    )?)
                }
            }

            return Ok(BinaryBundle::new(result));
        }

        // At least two chunks
        let num_chunks = num_inputs.div_ceil(1024);
        let mut nodes = Vec::with_capacity(num_chunks);
        for (i, inp) in input.chunks(1024).take(num_chunks - 1).enumerate() {
            nodes.push(Self::blake3_chunk_chaining(g, inp, i as u64, 0)?);
        }

        let start = (num_chunks - 1) * 1024;
        nodes.push(Self::blake3_chunk_chaining(
            g,
            &input[start..],
            num_chunks as u64 - 1,
            0,
        )?);

        // Merkle tree
        let mut iv_as_wires = Vec::with_capacity(Self::IV.len());
        for inp in Self::IV.iter() {
            iv_as_wires.push(Self::constant_bundle_from_u32(g, *inp, 32)?);
        }

        let mut len = num_chunks;
        let mut input = vec![Vec::new(); 16];
        while len != 1 {
            let mut new_len = len / 2;
            for i in 0..new_len {
                let flag = if len == 2 {
                    root_flag | parent_flag
                } else {
                    parent_flag
                };

                input[..8].clone_from_slice(&nodes[2 * i]);
                input[8..].clone_from_slice(&nodes[2 * i + 1]);
                nodes[i] = Self::blake3_compress(g, &input, &iv_as_wires, [0, 0], 64, flag)?;
            }

            if len % 2 == 1 {
                nodes[new_len] = nodes[len - 1].clone();
                new_len += 1;
            }

            len = new_len;
        }

        // Compose the output
        for res in &nodes[0] {
            for chunk in res.chunks(8) {
                result.extend(Self::compose_field_element::<_, F>(
                    g,
                    chunk,
                    rands.next().unwrap(),
                )?)
            }
        }

        Ok(BinaryBundle::new(result))
    }

    pub(crate) fn blake3_chunk_chaining<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        input: &[Vec<G::Item>],
        chunk_index: u64,
        flag: u32,
    ) -> Result<Vec<Vec<G::Item>>, G::Error> {
        let num_inputs = input.len();
        assert!(num_inputs <= 1024);
        let blocks = num_inputs.div_ceil(64);
        let mut h = Vec::with_capacity(Self::IV.len());
        for inp in Self::IV {
            h.push(Self::constant_bundle_from_u32(g, inp, 32)?);
        }

        let chunk_start: u32 = 1;
        let chunk_end: u32 = 2;
        let root_flag: u32 = 8;
        assert!((flag == 0) | (flag == root_flag));

        let t = [chunk_index as u32, (chunk_index >> 32) as u32];
        let zero = vec![g.const_zero()?; 32];

        let mut used_flag = chunk_start;
        if num_inputs > 0 {
            let mut tmp: [_; 16] = core::array::from_fn(|_| zero.clone());
            for inp in input.chunks(64).take(blocks - 1) {
                for (i, inp) in inp.iter().enumerate() {
                    let shift = (i % 4) * 8;
                    tmp[i / 4]
                        .iter_mut()
                        .skip(shift)
                        .zip(inp.iter())
                        .for_each(|(a, b)| {
                            *a = b.clone();
                        });
                }
                h = Self::blake3_compress(g, &tmp, &h, t, 64, used_flag)?;
                used_flag = 0;
            }
        }

        let mut bytes = num_inputs % 64;
        if num_inputs > 0 && bytes == 0 {
            bytes = 64;
        }

        used_flag |= chunk_end | flag;

        let mut tmp: [_; 16] = core::array::from_fn(|_| zero.clone());
        if num_inputs > 0 {
            for (i, inp) in input.iter().skip(64 * (blocks - 1)).enumerate() {
                let shift = (i % 4) * 8;
                tmp[i / 4]
                    .iter_mut()
                    .skip(shift)
                    .zip(inp.iter())
                    .for_each(|(a, b)| {
                        *a = b.clone();
                    });
            }
        }

        Self::blake3_compress(g, &tmp, &h, t, bytes as u32, used_flag)
    }

    pub(crate) fn blake3_compress<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        input: &[Vec<G::Item>],
        h: &[Vec<G::Item>],
        t: [u32; 2],
        blocklen: u32,
        flags: u32,
    ) -> Result<Vec<Vec<G::Item>>, G::Error> {
        let mut state = Vec::with_capacity(16);
        for inp in h {
            state.push(inp.to_vec());
        }
        for inp in Self::IV.iter().take(4) {
            state.push(Self::constant_bundle_from_u32(g, *inp, 32)?);
        }
        state.push(Self::constant_bundle_from_u32(g, t[0], 32)?);
        state.push(Self::constant_bundle_from_u32(g, t[1], 32)?);
        state.push(Self::constant_bundle_from_u32(g, blocklen, 32)?);
        state.push(Self::constant_bundle_from_u32(g, flags, 32)?);

        for r in 0..7 {
            let sr = Self::SIGMA_BLAKE3[r];
            let res = Self::blake3_mix(
                g,
                &state[0],
                &state[4],
                &state[8],
                &state[12],
                &input[sr[0] as usize],
                &input[sr[1] as usize],
            )?; // Column 0
            state[0] = res.0;
            state[4] = res.1;
            state[8] = res.2;
            state[12] = res.3;
            let res = Self::blake3_mix(
                g,
                &state[1],
                &state[5],
                &state[9],
                &state[13],
                &input[sr[2] as usize],
                &input[sr[3] as usize],
            )?; // Column 1
            state[1] = res.0;
            state[5] = res.1;
            state[9] = res.2;
            state[13] = res.3;
            let res = Self::blake3_mix(
                g,
                &state[2],
                &state[6],
                &state[10],
                &state[14],
                &input[sr[4] as usize],
                &input[sr[5] as usize],
            )?; // Column 2
            state[2] = res.0;
            state[6] = res.1;
            state[10] = res.2;
            state[14] = res.3;
            let res = Self::blake3_mix(
                g,
                &state[3],
                &state[7],
                &state[11],
                &state[15],
                &input[sr[6] as usize],
                &input[sr[7] as usize],
            )?; // Column 3
            state[3] = res.0;
            state[7] = res.1;
            state[11] = res.2;
            state[15] = res.3;
            let res = Self::blake3_mix(
                g,
                &state[0],
                &state[5],
                &state[10],
                &state[15],
                &input[sr[8] as usize],
                &input[sr[9] as usize],
            )?; // Diagonal 1 (main diagonal)
            state[0] = res.0;
            state[5] = res.1;
            state[10] = res.2;
            state[15] = res.3;
            let res = Self::blake3_mix(
                g,
                &state[1],
                &state[6],
                &state[11],
                &state[12],
                &input[sr[10] as usize],
                &input[sr[11] as usize],
            )?; // Diagonal 2
            state[1] = res.0;
            state[6] = res.1;
            state[11] = res.2;
            state[12] = res.3;
            let res = Self::blake3_mix(
                g,
                &state[2],
                &state[7],
                &state[8],
                &state[13],
                &input[sr[12] as usize],
                &input[sr[13] as usize],
            )?; // Diagonal 3
            state[2] = res.0;
            state[7] = res.1;
            state[8] = res.2;
            state[13] = res.3;
            let res = Self::blake3_mix(
                g,
                &state[3],
                &state[4],
                &state[9],
                &state[14],
                &input[sr[14] as usize],
                &input[sr[15] as usize],
            )?; // Diagonal 4
            state[3] = res.0;
            state[4] = res.1;
            state[9] = res.2;
            state[14] = res.3;
        }
        let mut result = Vec::new();
        for i in 0..8 {
            result.push(Self::xor_many_as_wires(g, &state[i], &state[i + 8])?);
        }
        Ok(result)
    }

    #[expect(clippy::type_complexity)]
    fn blake3_mix<G: FancyBinary + FancyBinaryConstant>(
        g: &mut G,
        a: &[G::Item],
        b: &[G::Item],
        c: &[G::Item],
        d: &[G::Item],
        x: &[G::Item],
        y: &[G::Item],
    ) -> Result<(Vec<G::Item>, Vec<G::Item>, Vec<G::Item>, Vec<G::Item>), G::Error> {
        let mut a = Self::bin_addition_no_carry(g, a, b)?;
        a = Self::bin_addition_no_carry(g, &a, x)?;
        let mut d = Self::xor_many_as_wires(g, d, &a)?;
        d.rotate_left(16);
        let mut c = Self::bin_addition_no_carry(g, c, &d)?;
        let mut b = Self::xor_many_as_wires(g, b, &c)?;
        b.rotate_left(12);
        a = Self::bin_addition_no_carry(g, &a, &b)?;
        a = Self::bin_addition_no_carry(g, &a, y)?;
        d = Self::xor_many_as_wires(g, &d, &a)?;
        d.rotate_left(8);
        c = Self::bin_addition_no_carry(g, &c, &d)?;
        b = Self::xor_many_as_wires(g, &b, &c)?;
        b.rotate_left(7);

        Ok((a, b, c, d))
    }

    const SIGMA_BLAKE3: [[u8; 16]; 7] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
        [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
        [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
        [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
        [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
        [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
    ];

    /// Computes AES ct with given pt, iv and key which are represented as wires_x1 and wires_x2 which need to be added first get the inputs. The output is composed using wires_c. If the plaintext is not of size 0 mod 16 it is padded using PKCS7 padding.
    pub(crate) fn aes128<
        G: FancyBinary + FancyBinaryConstant + BristolFashionEvaluator<WireValue = G::Item>,
        F: PrimeField,
    >(
        g: &mut G,
        wires_x1: &BinaryBundle<G::Item>,
        wires_x2: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        pt_length: usize,
        key_length: usize,
        bitsize: usize,
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        const AES_BLOCK_SIZE: usize = 16;
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;

        // Reading the circuit from txt file
        let circuit = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/protocols/rep3/yao/bristol_fashion/circuit_files/aes_128.txt"
        ));
        let circuit_read =
            BristolFashionCircuit::from_reader(circuit.as_bytes()).expect("aes128 circuit works");

        let mut plaintext = Vec::new();
        let mut key = Vec::new();
        let mut iv = Vec::new();

        for (chunk_x1, chunk_x2) in izip!(
            wires_x1.wires()[..pt_length * input_bitlen].chunks(input_bitlen),
            wires_x2.wires()[..pt_length * input_bitlen].chunks(input_bitlen)
        ) {
            let mut plaintext_bits =
                Self::adder_mod_p_with_output_size::<_, F>(g, chunk_x1, chunk_x2, bitsize)?;
            plaintext_bits.reverse();
            plaintext.extend(plaintext_bits);
        }
        for (chunk_y1, chunk_y2, chunk_z1, chunk_z2) in izip!(
            wires_x1.wires()
                [pt_length * input_bitlen..pt_length * input_bitlen + key_length * input_bitlen]
                .chunks(input_bitlen),
            wires_x2.wires()
                [pt_length * input_bitlen..pt_length * input_bitlen + key_length * input_bitlen]
                .chunks(input_bitlen),
            wires_x1.wires()[pt_length * input_bitlen + key_length * input_bitlen..]
                .chunks(input_bitlen),
            wires_x2.wires()[pt_length * input_bitlen + key_length * input_bitlen..]
                .chunks(input_bitlen),
        ) {
            let mut key_bits =
                Self::adder_mod_p_with_output_size::<_, F>(g, chunk_y1, chunk_y2, bitsize)?;
            key_bits.reverse();
            let mut iv_bits =
                Self::adder_mod_p_with_output_size::<_, F>(g, chunk_z1, chunk_z2, bitsize)?;
            iv_bits.reverse();
            key.extend(key_bits);
            iv.extend(iv_bits);
        }
        // PKCS7 padding:
        let add = AES_BLOCK_SIZE - (pt_length % AES_BLOCK_SIZE);
        let mut add_bundle = Self::constant_bundle_from_usize(g, add, bitsize)?;
        add_bundle.reverse();
        for _ in 0..add {
            plaintext.extend(add_bundle.clone());
        }

        for block in plaintext.chunks_mut(bitsize * AES_BLOCK_SIZE) {
            block.reverse();
        }
        key.reverse();
        iv.reverse();

        debug_assert_eq!(plaintext.len() % AES_BLOCK_SIZE, 0);

        let mut my_iv = iv;
        let mut rest = &mut plaintext[..];

        while rest.len() >= AES_BLOCK_SIZE * bitsize {
            let (block, remain) = rest.split_at_mut(AES_BLOCK_SIZE * bitsize);

            block.iter_mut().zip(my_iv.iter()).try_for_each(|(x, y)| {
                *x = FancyBinary::xor(g, x, y)?;
                Ok::<(), G::Error>(())
            })?;

            block.clone_from_slice(&Self::aes128_block::<_>(g, &key, block, &circuit_read)?);

            my_iv.clone_from_slice(block);
            rest = remain;
        }

        // we need to reorder here, since we the input for the circuit is in reversed order
        for res in plaintext.chunks_mut(bitsize * AES_BLOCK_SIZE) {
            for i in 0..bitsize {
                for j in 0..bitsize {
                    res.swap(
                        i * bitsize + j,
                        AES_BLOCK_SIZE * bitsize - (i + 1) * bitsize + j,
                    );
                }
            }
        }

        let mut results =
            Vec::with_capacity(plaintext.len().div_ceil(bitsize) * F::MODULUS_BIT_SIZE as usize);
        for (xs, ys) in izip!(
            plaintext.chunks(bitsize),
            wires_c.wires().chunks(input_bitlen),
        ) {
            let result = Self::compose_field_element::<_, F>(g, xs, ys)?;
            results.extend(result);
        }

        Ok(BinaryBundle::new(results))
    }

    /// Computes one single AES block using the parsed Bristol circuit.
    pub(crate) fn aes128_block<
        G: FancyBinary + FancyBinaryConstant + BristolFashionEvaluator<WireValue = G::Item>,
    >(
        g: &mut G,
        key: &[G::Item],
        plaintext: &[G::Item],
        circuit: &BristolFashionCircuit,
    ) -> Result<Vec<G::Item>, G::Error> {
        debug_assert_eq!(key.len(), 128);
        debug_assert_eq!(plaintext.len(), 128);

        let input = [key, plaintext];
        let one = g.const_one()?;
        let result = match circuit.evaluate_with_default::<G::Item>(&input, g, one) {
            Ok(mut outputs) => match outputs.pop() {
                Some(output) => output,
                None => {
                    return Err(G::Error::from(FancyError::InvalidArg(
                        "No output found in circuit evaluation".to_string(),
                    )));
                }
            },
            Err(e) => return Err(G::Error::from(FancyError::from(e))),
        };
        Ok(result)
    }

    /// Computes wnaf digits and rows needed in the ECCVM builder.
    pub(crate) fn compute_wnaf_digits_many<G: FancyBinary + FancyBinaryConstant, F: PrimeField>(
        g: &mut G,
        wires_x1: &BinaryBundle<G::Item>,
        wires_x2: &BinaryBundle<G::Item>,
        wires_c: &BinaryBundle<G::Item>,
        total_output_bitlen_per_field: usize,
    ) -> Result<BinaryBundle<G::Item>, G::Error> {
        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        debug_assert_eq!(wires_x1.size(), wires_x2.size());
        let length = wires_x1.size();
        debug_assert_eq!(length % 2, 0);

        let mut results = Vec::with_capacity(wires_c.size());

        for (chunk_x1, chunk_x2, chunk_c) in izip!(
            wires_x1.wires().chunks(input_bitlen),
            wires_x2.wires().chunks(input_bitlen),
            wires_c.wires().chunks(
                32 * input_bitlen
                    + 32 * input_bitlen
                    + input_bitlen
                    + 8 * 8 * input_bitlen
                    + 8 * input_bitlen
                    + 8 * input_bitlen
            ),
        ) {
            let value = Self::compute_wnaf_digits::<G, F>(
                g,
                chunk_x1,
                chunk_x2,
                chunk_c,
                total_output_bitlen_per_field,
            )?;

            results.extend(value);
        }
        Ok(BinaryBundle::new(results))
    }

    /// Computes wnaf digits and rows needed in the ECCVM builder.
    fn compute_wnaf_digits<G: FancyBinary + FancyBinaryConstant, F: PrimeField>(
        g: &mut G,
        wires_a: &[G::Item],
        wires_b: &[G::Item],
        wires_c: &[G::Item],
        total_output_bitlen: usize,
    ) -> Result<Vec<G::Item>, G::Error> {
        const NUM_SCALAR_BITS: usize = 128; // The length of scalars handled by the ECCVVM
        const NUM_WNAF_DIGIT_BITS: usize = 4; // Scalars are decompose into base 16 in wNAF form
        const NUM_WNAF_DIGITS_PER_SCALAR: usize = NUM_SCALAR_BITS / NUM_WNAF_DIGIT_BITS; // 32
        const WNAF_DIGITS_PER_ROW: usize = 4;
        let num_rows_per_scalar = NUM_WNAF_DIGITS_PER_SCALAR / WNAF_DIGITS_PER_ROW;

        let input_bitlen = F::MODULUS_BIT_SIZE as usize;
        let mut rands = wires_c.chunks(input_bitlen);

        debug_assert_eq!(wires_a.len(), wires_b.len());

        let mut input_bits =
            Self::adder_mod_p_with_output_size::<_, F>(g, wires_a, wires_b, total_output_bitlen)?;
        let input_bitlen = input_bits.len();
        let mut previous_slice = vec![g.const_zero()?; 5];
        let constant_fifteen = [true, true, true, true, false];

        let mut results = Vec::with_capacity(wires_c.len());

        let is_even = g.negate(&input_bits[0])?; //Gives us whether the input is odd or even

        results.extend(Self::compose_field_element::<_, F>(
            g,
            &[is_even],
            rands.next().unwrap(),
        )?);
        let mut outputs = Vec::with_capacity(NUM_WNAF_DIGITS_PER_SCALAR - 1);
        let mut underflow_bits = Vec::with_capacity(NUM_WNAF_DIGITS_PER_SCALAR - 1);

        for i in 0..NUM_WNAF_DIGITS_PER_SCALAR {
            let raw_slice = &input_bits[..4];
            let is_even = g.negate(&raw_slice[0])?;
            let is_even = [is_even, g.const_zero()?, g.const_zero()?, g.const_zero()?];

            let mut wnaf_slice = raw_slice.to_owned();
            let mut underflow_bit = g.const_zero()?;

            wnaf_slice = Self::bin_addition_no_carry(g, &wnaf_slice, &is_even)?;
            if i != 0 {
                // We optimize the following code
                // let subtrahend = [
                //     g.const_zero()?,
                //     g.const_zero()?,
                //     g.const_zero()?,
                //     g.const_zero()?,
                //     is_even[0].clone(),
                // ]; // Either 0 or 16, depending on is_even
                // (previous_slice, underflow_bit) =
                //     Self::bin_subtraction(g, &previous_slice, &subtrahend)?;

                // Last bit with is_even[0]
                let y = g.negate(&is_even[0])?;
                let res = Self::full_adder_cin_set(g, &previous_slice[4], &y)?;
                previous_slice[4] = res.0;
                underflow_bit = res.1;
            }

            if i > 0 {
                outputs.push(previous_slice);
                underflow_bits.push(underflow_bit);
            }
            previous_slice = wnaf_slice;
            previous_slice.resize(5, g.const_zero()?);

            input_bits = input_bits[4..].to_vec();
            input_bits.resize(input_bitlen, g.const_zero()?);
        }
        outputs.push(previous_slice);
        outputs.reverse();
        underflow_bits.push(g.const_one()?);
        underflow_bits.reverse();

        for i in 0..num_rows_per_scalar {
            let slice0 = &outputs[i * WNAF_DIGITS_PER_ROW];
            let slice1 = &outputs[i * WNAF_DIGITS_PER_ROW + 1];
            let slice2 = &outputs[i * WNAF_DIGITS_PER_ROW + 2];
            let slice3 = &outputs[i * WNAF_DIGITS_PER_ROW + 3];
            let underflow0 = &underflow_bits[i * WNAF_DIGITS_PER_ROW];
            let underflow1 = &underflow_bits[i * WNAF_DIGITS_PER_ROW + 1];
            let underflow2 = &underflow_bits[i * WNAF_DIGITS_PER_ROW + 2];
            let underflow3 = &underflow_bits[i * WNAF_DIGITS_PER_ROW + 3];

            let mut slice0base2 =
                Self::bin_addition_constant_no_carry(g, slice0, &constant_fifteen)?; // The results of this later get (x + 15) / 2. Since these are always even, we can just add 15 and shift
            let mut slice1base2 =
                Self::bin_addition_constant_no_carry(g, slice1, &constant_fifteen)?; // The results of this later get (x + 15) / 2. Since these are always even, we can just add 15 and shift
            let mut slice2base2 =
                Self::bin_addition_constant_no_carry(g, slice2, &constant_fifteen)?; // The results of this later get (x + 15) / 2. Since these are always even, we can just add 15 and shift
            let mut slice3base2 =
                Self::bin_addition_constant_no_carry(g, slice3, &constant_fifteen)?; // The results of this later get (x + 15) / 2. Since these are always even, we can just add 15 and shift
            for (slice, overflow) in [
                (&mut slice0base2, underflow0),
                (&mut slice1base2, underflow1),
                (&mut slice2base2, underflow2),
                (&mut slice3base2, underflow3),
            ] {
                slice.remove(0);
                slice.push(g.const_zero()?);
                results.extend(Self::compose_field_element::<_, F>(
                    g,
                    slice,
                    rands.next().unwrap(),
                )?);
                results.extend(Self::compose_field_element::<_, F>(
                    g,
                    std::slice::from_ref(overflow),
                    rands.next().unwrap(),
                )?);
            }

            let row_s1 = &slice0base2[2..];
            let row_s2 = &slice0base2[0..2];
            let row_s3 = &slice1base2[2..];
            let row_s4 = &slice1base2[0..2];
            let row_s5 = &slice2base2[2..];
            let row_s6 = &slice2base2[0..2];
            let row_s7 = &slice3base2[2..];
            let row_s8 = &slice3base2[0..2];
            for row in [
                row_s1, row_s2, row_s3, row_s4, row_s5, row_s6, row_s7, row_s8,
            ] {
                results.extend(Self::compose_field_element::<_, F>(
                    g,
                    row,
                    rands.next().unwrap(),
                )?);
            }
            // let row_chunk = slice3 + (slice2 << 4) + (slice1 << 8) + (slice0 << 12); but all slices have 5 bit and might be negative
            let mut slice3_ = vec![slice3[4].to_owned(); 32];
            let mut slice2_ = vec![slice2[4].to_owned(); 28];
            let mut slice1_ = vec![slice1[4].to_owned(); 24];
            let mut slice0_ = vec![slice0[4].to_owned(); 20];
            slice3_[..4].clone_from_slice(&slice3[..4]);
            slice2_[..4].clone_from_slice(&slice2[..4]);
            slice1_[..4].clone_from_slice(&slice1[..4]);
            slice0_[..4].clone_from_slice(&slice0[..4]);

            let add1 = Self::bin_addition_no_carry(g, &slice3_[4..], &slice2_)?;
            let add2 = Self::bin_addition_no_carry(g, &slice1_[4..], &slice0_)?;
            slice3_[4..].clone_from_slice(&add1);
            slice1_[4..].clone_from_slice(&add2);
            let add3 = Self::bin_addition_no_carry(g, &slice3_[8..], &slice1_)?;
            slice3_[8..].clone_from_slice(&add3);
            let mut row_chunk = slice3_;

            // twos complement if negative
            let is_negative_value = row_chunk.last().unwrap().to_owned();
            for x in &mut row_chunk {
                *x = g.xor(x, &is_negative_value)?;
            }

            let mut const_is_negative = vec![g.const_zero()?; 32];
            const_is_negative[0] = is_negative_value.clone();
            let row_chunk = Self::bin_addition_no_carry(g, &row_chunk, &const_is_negative)?;

            results.extend(Self::compose_field_element::<_, F>(
                g,
                &row_chunk,
                rands.next().unwrap(),
            )?);
            results.extend(Self::compose_field_element::<_, F>(
                g,
                &[is_negative_value],
                rands.next().unwrap(),
            )?);
        }

        Ok(results)
    }
}

/// A cleartext wire (a plain boolean) for [`CleartextBinaryEvaluator`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CleartextBit(pub bool);

impl HasModulus for CleartextBit {
    fn modulus(&self) -> u16 {
        2
    }
}

/// Evaluates garbled-circuit descriptions on cleartext (plain boolean) wires, counting the AND
/// gates on the way. Intended for unit tests/KATs of the circuits in this module: it lets a
/// reference implementation check every output wire of a circuit without any garbling or
/// networking, and measures the circuit's cost (under free-XOR, only AND gates cost anything).
#[derive(Default)]
pub struct CleartextBinaryEvaluator {
    /// Number of AND gates evaluated so far (XOR/NOT/constants are free under free-XOR).
    pub num_and_gates: usize,
}

impl Fancy for CleartextBinaryEvaluator {
    type Item = CleartextBit;
    type Error = FancyError;

    fn constant(&mut self, x: u16, _q: u16) -> Result<Self::Item, Self::Error> {
        Ok(CleartextBit(x & 1 == 1))
    }

    fn output(&mut self, x: &Self::Item) -> Result<Option<u16>, Self::Error> {
        Ok(Some(x.0 as u16))
    }
}

impl FancyBinary for CleartextBinaryEvaluator {
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        Ok(CleartextBit(x.0 ^ y.0))
    }

    fn and(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        self.num_and_gates += 1;
        Ok(CleartextBit(x.0 & y.0))
    }

    fn negate(&mut self, x: &Self::Item) -> Result<Self::Item, Self::Error> {
        Ok(CleartextBit(!x.0))
    }
}

impl FancyBinaryConstant for CleartextBinaryEvaluator {
    fn const_zero(&mut self) -> Result<Self::Item, Self::Error> {
        Ok(CleartextBit(false))
    }

    fn const_one(&mut self) -> Result<Self::Item, Self::Error> {
        Ok(CleartextBit(true))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::protocols::rep3::yao::GCInputs;
    use fancy_garbling::BinaryGadgets;
    use fancy_garbling::{Evaluator, Fancy, Garbler, WireMod2};
    use rand::{CryptoRng, Rng, SeedableRng, thread_rng};
    use rand_chacha::ChaCha12Rng;
    use scuttlebutt::{AbstractChannel, Channel};
    use std::{
        io::{BufReader, BufWriter},
        os::unix::net::UnixStream,
    };

    const TESTRUNS: usize = 5;

    // The plain fancy-garbling Garbler/Evaluator do not implement FancyBinaryConstant (only the
    // Rep3 wrappers do). These test-only impls satisfy the trait bound for circuits which, like
    // sha256_block_sparse_trace, never actually emit constant wires.
    impl<C: AbstractChannel, R: Rng + CryptoRng> FancyBinaryConstant for Garbler<C, R, WireMod2> {
        fn const_zero(&mut self) -> Result<Self::Item, Self::Error> {
            self.constant(0, 2)
        }

        fn const_one(&mut self) -> Result<Self::Item, Self::Error> {
            self.constant(1, 2)
        }
    }

    impl<C: AbstractChannel> FancyBinaryConstant for Evaluator<C, WireMod2> {
        fn const_zero(&mut self) -> Result<Self::Item, Self::Error> {
            self.constant(0, 2)
        }

        fn const_one(&mut self) -> Result<Self::Item, Self::Error> {
            self.constant(1, 2)
        }
    }

    // This puts the X_0 values into garbler_wires and X_c values into evaluator_wires
    fn encode_field<F: PrimeField, C: AbstractChannel, R: Rng + CryptoRng>(
        field: F,
        garbler: &mut Garbler<C, R, WireMod2>,
    ) -> GCInputs<WireMod2> {
        let bits = GCUtils::field_to_bits_as_u16(field);
        let mut garbler_wires = Vec::with_capacity(bits.len());
        let mut evaluator_wires = Vec::with_capacity(bits.len());
        for bit in bits {
            let (mine, theirs) = garbler.encode_wire(bit, 2);
            garbler_wires.push(mine);
            evaluator_wires.push(theirs);
        }
        GCInputs {
            garbler_wires: BinaryBundle::new(garbler_wires),
            evaluator_wires: BinaryBundle::new(evaluator_wires),
            delta: garbler.delta(2),
        }
    }

    fn gc_test<F: PrimeField>() {
        let mut rng = thread_rng();

        let a = F::rand(&mut rng);
        let b = F::rand(&mut rng);
        let is_result = a + b;

        let (sender, receiver) = UnixStream::pair().unwrap();

        std::thread::spawn(move || {
            let rng = ChaCha12Rng::from_entropy();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let channel_sender = Channel::new(reader, writer);

            let mut garbler = Garbler::<_, _, WireMod2>::new(channel_sender, rng);

            // This is without OT, just a simulation
            let a = encode_field(a, &mut garbler);
            let b = encode_field(b, &mut garbler);
            for a in a.evaluator_wires.wires().iter() {
                garbler.send_wire(a).unwrap();
            }
            for b in b.evaluator_wires.wires().iter() {
                garbler.send_wire(b).unwrap();
            }

            let garble_result = GarbledCircuits::adder_mod_p::<_, F>(
                &mut garbler,
                &a.garbler_wires,
                &b.garbler_wires,
            )
            .unwrap();

            // Output
            garbler.outputs(garble_result.wires()).unwrap();
        });

        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let channel_rcv = Channel::new(reader, writer);

        let mut evaluator = Evaluator::<_, WireMod2>::new(channel_rcv);

        // This is without OT, just a simulation
        let n_bits = F::MODULUS_BIT_SIZE as usize;
        let mut a = Vec::with_capacity(n_bits);
        let mut b = Vec::with_capacity(n_bits);
        for _ in 0..n_bits {
            let a_ = evaluator.read_wire(2).unwrap();
            a.push(a_);
        }
        for _ in 0..n_bits {
            let b_ = evaluator.read_wire(2).unwrap();
            b.push(b_);
        }
        let a = BinaryBundle::new(a);
        let b = BinaryBundle::new(b);

        let eval_result = GarbledCircuits::adder_mod_p::<_, F>(&mut evaluator, &a, &b).unwrap();

        let result = evaluator.outputs(eval_result.wires()).unwrap().unwrap();
        let result = GCUtils::u16_bits_to_field::<F>(result).unwrap();
        assert_eq!(result, is_result);
    }

    #[test]
    fn gc_test_bn254() {
        for _ in 0..TESTRUNS {
            gc_test::<ark_bn254::Fr>();
        }
    }

    fn gc_test_div_int<F: PrimeField>()
    where
        num_bigint::BigUint: std::convert::From<F>,
    {
        let mut rng = thread_rng();

        let a = F::rand(&mut rng);
        let b = F::rand(&mut rng);
        let is_result = F::from(BigUint::from(a) / BigUint::from(b));
        let (sender, receiver) = UnixStream::pair().unwrap();

        std::thread::spawn(move || {
            let rng = ChaCha12Rng::from_entropy();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let channel_sender = Channel::new(reader, writer);

            let mut garbler = Garbler::<_, _, WireMod2>::new(channel_sender, rng);

            // This is without OT, just a simulation
            let a = encode_field(a, &mut garbler);
            let b = encode_field(b, &mut garbler);
            for a in a.evaluator_wires.wires().iter() {
                garbler.send_wire(a).unwrap();
            }
            for b in b.evaluator_wires.wires().iter() {
                garbler.send_wire(b).unwrap();
            }

            let garble_result =
                BinaryGadgets::bin_div(&mut garbler, &a.garbler_wires, &b.garbler_wires).unwrap();

            // Output
            garbler.outputs(garble_result.wires()).unwrap();
        });

        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let channel_rcv = Channel::new(reader, writer);

        let mut evaluator = Evaluator::<_, WireMod2>::new(channel_rcv);

        // This is without OT, just a simulation
        let n_bits = F::MODULUS_BIT_SIZE as usize;
        let mut a = Vec::with_capacity(n_bits);
        let mut b = Vec::with_capacity(n_bits);
        for _ in 0..n_bits {
            let a_ = evaluator.read_wire(2).unwrap();
            a.push(a_);
        }
        for _ in 0..n_bits {
            let b_ = evaluator.read_wire(2).unwrap();
            b.push(b_);
        }
        let a = BinaryBundle::new(a);
        let b = BinaryBundle::new(b);

        let eval_result = BinaryGadgets::bin_div(&mut evaluator, &a, &b).unwrap();

        let result = evaluator.outputs(eval_result.wires()).unwrap().unwrap();
        let result = GCUtils::u16_bits_to_field::<F>(result).unwrap();
        assert_eq!(result, is_result);
    }

    #[test]
    fn gc_test_bn254_div_int() {
        for _ in 0..TESTRUNS {
            gc_test_div_int::<ark_bn254::Fr>();
        }
    }

    /// Referee for [`CleartextBinaryEvaluator`]: the sha256_block_sparse_trace circuit evaluated
    /// on cleartext wires must agree bit-for-bit with a real garbled execution (WireMod2
    /// garbler/evaluator pair) of the same circuit on the same inputs. The value-level referee
    /// against the plain plookup table functions lives in co-builder
    /// (sha_compression_sparse_trace_tests.rs).
    #[test]
    fn gc_sha256_block_sparse_trace_matches_cleartext() {
        use ark_ff::UniformRand;
        type F = ark_bn254::Fr;
        let mut rng = thread_rng();

        // 24 random 32-bit inputs (h_init[0..8] || w_in[0..16]), split into two field summands
        let values: Vec<u32> = (0..24).map(|_| rng.r#gen()).collect();
        let x1: Vec<F> = (0..24).map(|_| F::rand(&mut rng)).collect();
        let x2: Vec<F> = values
            .iter()
            .zip(x1.iter())
            .map(|(v, x1)| F::from(*v) - x1)
            .collect();

        let (clear_bits, num_ands) =
            GarbledCircuits::sha256_block_sparse_trace_cleartext::<F>(&x1, &x2).unwrap();
        assert_eq!(
            clear_bits.len(),
            GarbledCircuits::SHA256_BLOCK_SPARSE_TRACE_OUTPUT_BITS
        );
        assert!(num_ands > 0);

        let (sender, receiver) = UnixStream::pair().unwrap();
        let x1_garbler = x1.clone();
        let x2_garbler = x2.clone();

        std::thread::spawn(move || {
            let rng = ChaCha12Rng::from_entropy();
            let reader = BufReader::new(sender.try_clone().unwrap());
            let writer = BufWriter::new(sender);
            let channel_sender = Channel::new(reader, writer);

            let mut garbler = Garbler::<_, _, WireMod2>::new(channel_sender, rng);

            // This is without OT, just a simulation
            let mut x1_garbler_wires = Vec::new();
            let mut x2_garbler_wires = Vec::new();
            for (x1, x2) in x1_garbler.iter().zip(x2_garbler.iter()) {
                let x1 = encode_field(*x1, &mut garbler);
                let x2 = encode_field(*x2, &mut garbler);
                for wire in x1.evaluator_wires.wires().iter() {
                    garbler.send_wire(wire).unwrap();
                }
                for wire in x2.evaluator_wires.wires().iter() {
                    garbler.send_wire(wire).unwrap();
                }
                x1_garbler_wires.extend_from_slice(x1.garbler_wires.wires());
                x2_garbler_wires.extend_from_slice(x2.garbler_wires.wires());
            }

            let garble_result = GarbledCircuits::sha256_block_sparse_trace::<_, F>(
                &mut garbler,
                &BinaryBundle::new(x1_garbler_wires),
                &BinaryBundle::new(x2_garbler_wires),
            )
            .unwrap();

            // Output
            garbler.outputs(garble_result.wires()).unwrap();
        });

        let reader = BufReader::new(receiver.try_clone().unwrap());
        let writer = BufWriter::new(receiver);
        let channel_rcv = Channel::new(reader, writer);

        let mut evaluator = Evaluator::<_, WireMod2>::new(channel_rcv);

        // This is without OT, just a simulation
        let n_bits = F::MODULUS_BIT_SIZE as usize;
        let mut x1_wires = Vec::with_capacity(24 * n_bits);
        let mut x2_wires = Vec::with_capacity(24 * n_bits);
        for _ in 0..24 {
            for _ in 0..n_bits {
                x1_wires.push(evaluator.read_wire(2).unwrap());
            }
            for _ in 0..n_bits {
                x2_wires.push(evaluator.read_wire(2).unwrap());
            }
        }

        let eval_result = GarbledCircuits::sha256_block_sparse_trace::<_, F>(
            &mut evaluator,
            &BinaryBundle::new(x1_wires),
            &BinaryBundle::new(x2_wires),
        )
        .unwrap();

        let result = evaluator.outputs(eval_result.wires()).unwrap().unwrap();
        assert_eq!(result.len(), clear_bits.len());
        for (i, (gc_bit, clear_bit)) in result.iter().zip(clear_bits.iter()).enumerate() {
            assert_eq!(*gc_bit == 1, *clear_bit, "output bit {i} differs");
        }
    }
}

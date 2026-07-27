//! Lookup Table
//!
//! This module contains implementation of a LUT

use super::{Rep3RingShare, ring::int_ring::IntRing2k};
use crate::{
    lut::LookupTableProvider,
    protocols::{
        rep3::{
            self, Rep3BigUintShare, Rep3PrimeFieldShare, Rep3State, arithmetic,
            network::Rep3NetworkExt,
        },
        rep3_ring::{conversion, gadgets, ring::bit::Bit},
    },
};
use ark_ff::PrimeField;
use mpc_net::Network;
use rand::{distributions::Standard, prelude::Distribution};
use std::marker::PhantomData;

/// Implements an enum which stores a lookup table, either consisting of public or private values.
pub enum PublicPrivateLut<F: PrimeField> {
    /// The lookup table has public values
    Public(Vec<F>),
    /// The lookup table has secret-shared values
    Shared(Vec<Rep3PrimeFieldShare<F>>),
}

impl<F: PrimeField> Default for PublicPrivateLut<F> {
    fn default() -> Self {
        PublicPrivateLut::Public(Vec::new())
    }
}

impl<F: PrimeField> PublicPrivateLut<F> {
    /// Returns the number of elements contained in the lookup table
    pub fn len(&self) -> usize {
        match self {
            PublicPrivateLut::Public(lut) => lut.len(),
            PublicPrivateLut::Shared(lut) => lut.len(),
        }
    }

    /// Returns true if the lut is empty
    pub fn is_empty(&self) -> bool {
        match self {
            PublicPrivateLut::Public(lut) => lut.is_empty(),
            PublicPrivateLut::Shared(lut) => lut.is_empty(),
        }
    }
}

/// Rep3 lookup table
pub struct Rep3FieldLookupTable<F: PrimeField> {
    phantom: PhantomData<F>,
}

impl<F: PrimeField> Default for Rep3FieldLookupTable<F> {
    fn default() -> Self {
        Self {
            phantom: PhantomData::<F>,
        }
    }
}

impl<F: PrimeField> Rep3FieldLookupTable<F> {
    /// Construct a new [`Rep3FieldLookupTable`]
    pub fn new() -> Self {
        Self::default()
    }

    /// This is an optimized protocol that takes multiple public LUTs and looks them up with the same index. It only creates the OHV once.
    pub fn get_from_public_luts<N: Network>(
        index: Rep3PrimeFieldShare<F>,
        luts: &[Vec<F>],
        net0: &N,
        net1: &N,
        state0: &mut Rep3State,
        state1: &mut Rep3State,
    ) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
        let len = luts.iter().map(|l| l.len()).max().unwrap();
        tracing::debug!("doing read on LUT-map of size {}", len);
        let bits = rep3::conversion::a2b_selector(index, net0, state0)?;
        let k = len.next_power_of_two().ilog2() as usize;

        let result = if k == 1 {
            Self::get_from_public_luts_internal::<Bit, _>(bits, luts, net0, net1, state0, state1)?
        } else if k <= 8 {
            Self::get_from_public_luts_internal::<u8, _>(bits, luts, net0, net1, state0, state1)?
        } else if k <= 16 {
            Self::get_from_public_luts_internal::<u16, _>(bits, luts, net0, net1, state0, state1)?
        } else if k <= 32 {
            Self::get_from_public_luts_internal::<u32, _>(bits, luts, net0, net1, state0, state1)?
        } else {
            panic!("Table is too large")
        };
        tracing::debug!("got a result!");
        Ok(result)
    }

    fn get_from_public_luts_internal<T: IntRing2k, N: Network>(
        index: Rep3BigUintShare<F>,
        luts: &[Vec<F>],
        net0: &N,
        net1: &N,
        state0: &mut Rep3State,
        state1: &mut Rep3State,
    ) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>>
    where
        Standard: Distribution<T>,
    {
        let a = T::cast_from_biguint(&index.a);
        let b = T::cast_from_biguint(&index.b);
        let share = Rep3RingShare::new(a, b);

        let bins_a = gadgets::lut_field::read_multiple_public_lut_low_depth(
            luts, share, net0, net1, state0, state1,
        )?;
        let bins_b = net0.reshare_many(&bins_a)?;

        let mut result = Vec::with_capacity(luts.len());

        // TODO parallelize this at some point
        for (bin_a, bin_b) in bins_a.into_iter().zip(bins_b) {
            let bin = Rep3BigUintShare::new(bin_a, bin_b);
            let res = rep3::conversion::b2a_selector(&bin, net0, state0)?;
            result.push(res);
        }

        Ok(result)
    }

    fn get_from_lut_internal<T: IntRing2k, N: Network>(
        index: Rep3BigUintShare<F>,
        lut: &PublicPrivateLut<F>,
        net0: &N,
        net1: &N,
        state0: &mut Rep3State,
        state1: &mut Rep3State,
    ) -> eyre::Result<Rep3PrimeFieldShare<F>>
    where
        Standard: Distribution<T>,
    {
        let a = T::cast_from_biguint(&index.a);
        let b = T::cast_from_biguint(&index.b);
        let share = Rep3RingShare::new(a, b);
        let val = match lut {
            PublicPrivateLut::Public(vec) => {
                let bin_a = gadgets::lut_field::read_public_lut_low_depth(
                    vec.as_ref(),
                    share,
                    net0,
                    net1,
                    state0,
                    state1,
                )?;
                let bin_b = net0.reshare(bin_a.to_owned())?;
                let bin = Rep3BigUintShare::new(bin_a, bin_b);
                rep3::conversion::b2a_selector(&bin, net0, state0)?
            }
            PublicPrivateLut::Shared(vec) => {
                let f_a = gadgets::lut_field::read_shared_lut(vec.as_ref(), share, net0, state0)?;
                let f_b = net0.reshare(f_a)?;
                Rep3PrimeFieldShare::new(f_a, f_b)
            }
        };

        Ok(val)
    }

    /// This is a protocol which reads from a public LUT without converting the result back to the arithmetic domain.
    pub fn get_from_public_lut_no_b2a_conversion<T: IntRing2k, N: Network>(
        index: Rep3BigUintShare<F>,
        lut: &PublicPrivateLut<F>,
        net0: &N,
        net1: &N,
        state0: &mut Rep3State,
        state1: &mut Rep3State,
    ) -> eyre::Result<Rep3BigUintShare<F>>
    where
        Standard: Distribution<T>,
    {
        let a = T::cast_from_biguint(&index.a);
        let b = T::cast_from_biguint(&index.b);
        let share = Rep3RingShare::new(a, b);

        match lut {
            PublicPrivateLut::Public(vec) => {
                let bin_a = gadgets::lut_field::read_public_lut_low_depth(
                    vec.as_ref(),
                    share,
                    net0,
                    net1,
                    state0,
                    state1,
                )?;
                let bin_b = net0.reshare(bin_a.to_owned())?;
                Ok(Rep3BigUintShare::new(bin_a, bin_b))
            }
            PublicPrivateLut::Shared(_) => {
                panic!("LUT is not public")
            }
        }
    }

    fn write_to_lut_internal<T: IntRing2k, N: Network>(
        index: Rep3BigUintShare<F>,
        lut: &mut PublicPrivateLut<F>,
        value: &Rep3PrimeFieldShare<F>,
        net0: &N,
        _net1: &N,
        state0: &mut Rep3State,
        _state1: &mut Rep3State,
    ) -> eyre::Result<()>
    where
        Standard: Distribution<T>,
    {
        let a = T::cast_from_biguint(&index.a);
        let b = T::cast_from_biguint(&index.b);
        let share = Rep3RingShare::new(a, b);
        match lut {
            PublicPrivateLut::Public(vec) => {
                // There is not really a performance difference (i.e., more multiplications) when both lut and value are secret shared compared to public lut and private value. Thus we promote
                let id = state0.id;
                let mut shared = vec
                    .iter()
                    .map(|v| arithmetic::promote_to_trivial_share(id, *v))
                    .collect::<Vec<_>>();
                gadgets::lut_field::write_lut(value, &mut shared, share, net0, state0)?;
                *lut = PublicPrivateLut::Shared(shared);
            }
            PublicPrivateLut::Shared(shared) => {
                gadgets::lut_field::write_lut(value, shared, share, net0, state0)?;
            }
        }
        Ok(())
    }

    fn ohv_from_index_internal<T: IntRing2k, N: Network>(
        index: Rep3BigUintShare<F>,
        k: usize,
        net0: &N,
        _net1: &N,
        state0: &mut Rep3State,
        _state1: &mut Rep3State,
    ) -> eyre::Result<Vec<Rep3RingShare<Bit>>> {
        let a = T::cast_from_biguint(&index.a);
        let b = T::cast_from_biguint(&index.b);
        let bits = Rep3RingShare::new(a, b);

        gadgets::ohv::ohv(k, bits, net0, state0)
    }

    /// Creates a shared one-hot-encoded vector from a given shared index
    pub fn ohv_from_index<N: Network>(
        index: Rep3PrimeFieldShare<F>,
        len: usize,
        net0: &N,
        net1: &N,
        state0: &mut Rep3State,
        state1: &mut Rep3State,
    ) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
        let bits = rep3::conversion::a2b_selector(index, net0, state0)?;
        let k = len.next_power_of_two().ilog2() as usize;

        let e = if k == 1 {
            Self::ohv_from_index_internal::<Bit, _>(bits, k, net0, net1, state0, state1)?
        } else if k <= 8 {
            Self::ohv_from_index_internal::<u8, _>(bits, k, net0, net1, state0, state1)?
        } else if k <= 16 {
            Self::ohv_from_index_internal::<u16, _>(bits, k, net0, net1, state0, state1)?
        } else if k <= 32 {
            Self::ohv_from_index_internal::<u32, _>(bits, k, net0, net1, state0, state1)?
        } else {
            panic!("Table is too large")
        };

        conversion::bit_inject_from_bits_to_field_many::<F, _>(&e, net0, state0)
    }

    /// Creates shared one-hot-encoded vectors from the given shared indices (`indices[i]`
    /// indexes a table of `lens[i]` entries), batching ALL communication across the whole
    /// slice into a constant number of rounds:
    /// - (i) ONE Direct [`rep3::conversion::a2b_many`] bit-decomposition for every index
    ///   (the singular path above goes through `a2b_selector`, whose default is one garbled
    ///   Yao adder circuit PER index — size-linear garbling with nothing to amortise, see
    ///   the L0a/b measurement);
    /// - (ii) ONE level-synchronous [`gadgets::ohv::ohv_many`], which collapses the OHV
    ///   recursion from `Σ_g (k_g − 1)` rounds to `k_max − 1`;
    /// - (iii) [`conversion::bit_inject_from_bits_to_field_many`] over all indices'
    ///   concatenated OHV bits, split into frames of at most `INJECT_CHUNK` elements to
    ///   bound peak per-frame memory at large scale (see the note on the constant).
    ///
    /// Values are identical to calling [`Self::ohv_from_index`] per index: both a2b variants
    /// produce a binary sharing of the same field value, `ohv_many` reproduces the per-index
    /// doubling algebra verbatim, and bit injection is elementwise (chunking preserves both
    /// the values and the per-bit draw order because injection is independent per bit).
    pub fn ohv_from_index_many<N: Network>(
        indices: &[Rep3PrimeFieldShare<F>],
        lens: &[usize],
        net0: &N,
        _net1: &N,
        state0: &mut Rep3State,
        _state1: &mut Rep3State,
    ) -> eyre::Result<Vec<Vec<Rep3PrimeFieldShare<F>>>> {
        assert_eq!(indices.len(), lens.len());
        if indices.is_empty() {
            // No communication at all for an empty batch (callers with only public
            // indices must not move any comms fence).
            return Ok(Vec::new());
        }

        // (i) ONE batched bit-decomposition round-trip set for all indices.
        let bits_many = rep3::conversion::a2b_many(indices, net0, state0)?;

        // Extract each index's `k` low bits (LSB first) as bit-shares — local, no comms.
        // `k <= 32` always holds (larger tables panic, matching the singular path).
        let mut bits_per_gate: Vec<Vec<Rep3RingShare<Bit>>> = Vec::with_capacity(bits_many.len());
        for (bits, len) in bits_many.iter().zip(lens.iter()) {
            let k = len.next_power_of_two().ilog2() as usize;
            assert!(k <= 32, "Table is too large");
            let a = u32::cast_from_biguint(&bits.a);
            let b = u32::cast_from_biguint(&bits.b);
            let ring = Rep3RingShare::new(a, b);
            bits_per_gate.push((0..k).map(|i| ring.get_bit(i)).collect());
        }

        // (ii) ONE level-synchronous batched OHV recursion across ALL indices.
        let es = gadgets::ohv::ohv_many(&bits_per_gate, net0, state0)?;

        let mut chunk_sizes = Vec::with_capacity(es.len());
        let mut all_bits: Vec<Rep3RingShare<Bit>> = Vec::new();
        for e in es {
            chunk_sizes.push(e.len());
            all_bits.extend(e);
        }

        // (iii) bit injection over all OHV bits, chunked. At the sha256_2e16 scale the
        // single frame would be ~3.7 GB; capping at INJECT_CHUNK elements bounds it to
        // ~0.5 GB/frame (16.78M * 32 B) while leaving every KAT circuit (< ~8M OHV bits)
        // a single frame — so no small-circuit fence moves. Chunking is value- and
        // draw-order-preserving: each bit's injection is independent and the chunks are
        // consumed in order.
        const INJECT_CHUNK: usize = 1 << 24;
        let injected: Vec<Rep3PrimeFieldShare<F>> = if all_bits.len() <= INJECT_CHUNK {
            conversion::bit_inject_from_bits_to_field_many::<F, _>(&all_bits, net0, state0)?
        } else {
            let mut out = Vec::with_capacity(all_bits.len());
            for chunk in all_bits.chunks(INJECT_CHUNK) {
                out.extend(conversion::bit_inject_from_bits_to_field_many::<F, _>(
                    chunk, net0, state0,
                )?);
            }
            out
        };

        // Split back per index (each chunk has lens[i].next_power_of_two() entries,
        // exactly like the singular path's output).
        let mut res = Vec::with_capacity(chunk_sizes.len());
        let mut injected = injected.into_iter();
        for size in chunk_sizes {
            res.push(injected.by_ref().take(size).collect());
        }
        Ok(res)
    }

    /// Writes to a shared lookup table with the index already being transformed into the shared one-hot-encoded vector
    pub fn write_to_shared_lut_from_ohv<N: Network>(
        ohv: &[Rep3PrimeFieldShare<F>],
        value: Rep3PrimeFieldShare<F>,
        lut: &mut [Rep3PrimeFieldShare<F>],
        net: &N,
        state: &mut Rep3State,
    ) -> eyre::Result<()> {
        let len = lut.len();
        tracing::debug!("doing write on LUT-map of size {}", len);
        gadgets::lut_field::write_lut_from_ohv(&value, lut, ohv, net, state)?;
        tracing::debug!("we are done");
        Ok(())
    }

    /// Returns true if LUT is public
    pub fn is_public_lut(lut: &PublicPrivateLut<F>) -> bool {
        match lut {
            PublicPrivateLut::Public(_) => true,
            PublicPrivateLut::Shared(_) => false,
        }
    }
}

impl<F: PrimeField> LookupTableProvider<F> for Rep3FieldLookupTable<F> {
    type SecretShare = Rep3PrimeFieldShare<F>;
    type IndexSecretShare = Rep3PrimeFieldShare<F>;
    type LutType = PublicPrivateLut<F>;
    type State = Rep3State;

    fn init_private(&self, values: Vec<Self::SecretShare>) -> Self::LutType {
        tracing::debug!("initiating LUT-map (private)");
        PublicPrivateLut::Shared(values)
    }

    fn init_public(&self, values: Vec<F>) -> Self::LutType {
        tracing::debug!("initiating LUT-map (public)");
        PublicPrivateLut::Public(values)
    }

    fn get_from_lut<N: Network>(
        &mut self,
        index: Self::IndexSecretShare,
        lut: &Self::LutType,
        net0: &N,
        net1: &N,
        state0: &mut Rep3State,
        state1: &mut Rep3State,
    ) -> eyre::Result<Self::SecretShare> {
        let len = lut.len();
        tracing::debug!("doing read on LUT-map of size {}", len);
        let bits = rep3::conversion::a2b_selector(index, net0, state0)?;
        let k = len.next_power_of_two().ilog2() as usize;

        let result = if k == 1 {
            Self::get_from_lut_internal::<Bit, _>(bits, lut, net0, net1, state0, state1)?
        } else if k <= 8 {
            Self::get_from_lut_internal::<u8, _>(bits, lut, net0, net1, state0, state1)?
        } else if k <= 16 {
            Self::get_from_lut_internal::<u16, _>(bits, lut, net0, net1, state0, state1)?
        } else if k <= 32 {
            Self::get_from_lut_internal::<u32, _>(bits, lut, net0, net1, state0, state1)?
        } else {
            panic!("Table is too large")
        };
        tracing::debug!("got a result!");
        Ok(result)
    }

    fn write_to_lut<N: Network>(
        &mut self,
        index: Self::IndexSecretShare,
        value: Self::SecretShare,
        lut: &mut Self::LutType,
        net0: &N,
        net1: &N,
        state0: &mut Rep3State,
        state1: &mut Rep3State,
    ) -> eyre::Result<()> {
        let len = lut.len();
        tracing::debug!("doing write on LUT-map of size {}", len);
        let bits = rep3::conversion::a2b_selector(index, net0, state0)?;
        let k = len.next_power_of_two().ilog2();

        if k == 1 {
            Self::write_to_lut_internal::<Bit, _>(bits, lut, &value, net0, net1, state0, state1)?
        } else if k <= 8 {
            Self::write_to_lut_internal::<u8, _>(bits, lut, &value, net0, net1, state0, state1)?
        } else if k <= 16 {
            Self::write_to_lut_internal::<u16, _>(bits, lut, &value, net0, net1, state0, state1)?
        } else if k <= 32 {
            Self::write_to_lut_internal::<u32, _>(bits, lut, &value, net0, net1, state0, state1)?
        } else {
            panic!("Table is too large")
        };

        tracing::debug!("we are done");
        Ok(())
    }

    fn get_lut_len(lut: &Self::LutType) -> usize {
        match lut {
            PublicPrivateLut::Public(items) => items.len(),
            PublicPrivateLut::Shared(shares) => shares.len(),
        }
    }

    fn get_public_lut(lut: &Self::LutType) -> eyre::Result<&Vec<F>> {
        match lut {
            PublicPrivateLut::Public(items) => Ok(items),
            PublicPrivateLut::Shared(_) => Err(eyre::eyre!("Expected public LUT")),
        }
    }
}

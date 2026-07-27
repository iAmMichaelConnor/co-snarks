//! OHV
//!
//! This module contains some algorithms to create a random one-hot encoded vector for the Rep3 protocol.

use ark_ff::{One, Zero};
use mpc_net::Network;
use rand::{distributions::Standard, prelude::Distribution};

use crate::protocols::{
    rep3::{Rep3State, network::Rep3NetworkExt},
    rep3_ring::{
        Rep3RingShare, binary,
        ring::{bit::Bit, int_ring::IntRing2k, ring_impl::RingElement},
    },
};

/// Generates a random one-hot-encoded vector of size k bits.
/// The output is (r, e), where r is a binary sharing of the index of the set bit, whereas e is a vector of size 2^k with all bits zero except at index r.
/// The algorithm is a rewrite of Protocol 5 from [https://eprint.iacr.org/2024/1317.pdf](https://eprint.iacr.org/2024/1317.pdf) for rep3.
pub fn rand_ohv<T: IntRing2k, N: Network>(
    k: usize,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<(Rep3RingShare<T>, Vec<Rep3RingShare<Bit>>)>
where
    Standard: Distribution<T>,
{
    debug_assert!(k >= 1);
    debug_assert!(k <= T::K); // Make sure datatype is large enough for bitsize
    let (mut a, mut b) = state.rngs.rand.random_elements::<T>();
    if k != T::K {
        let mask = (T::one() << k) - T::one();
        a &= mask;
        b &= mask
    }

    let bits = Rep3RingShare::new(a, b);
    let e = ohv(k, bits, net, state)?;

    Ok((bits, e))
}

/// Generates a one-hot-encoded vector of size k bits from a given secret shared index which is already decomposed into shared bits.
/// The output is (r, e), where r is a binary sharing of the index of the set bit, whereas e is a vector of size 2^k with all bits zero except at index r.
/// The algorithm is a rewrite of Protocol 5 from [https://eprint.iacr.org/2024/1317.pdf](https://eprint.iacr.org/2024/1317.pdf) for rep3.
pub fn ohv<T: IntRing2k, N: Network>(
    k: usize,
    mut bits: Rep3RingShare<T>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3RingShare<Bit>>> {
    debug_assert!(k > 0);
    debug_assert!(k <= T::K); // Make sure datatype is large enough for bitsize

    let new_k = k - 1;
    let vk = bits.get_bit(new_k);

    if new_k == 0 {
        return Ok(vec![!vk, vk]);
    }

    let mask = (RingElement::one() << new_k) - RingElement::one();
    bits &= mask; // Remove the vk

    let mut f = ohv(new_k, bits, net, state)?; // ohv is recursively called k - 1 times
    let mut e = pack_and(&f[..f.len() - 1], &vk, net, state)?; // This has communication (2^new_k - 1 bits)
    e.push(e.iter().fold(vk, |a, b| &a ^ b));

    for (e, f) in e.iter().zip(f.iter_mut()) {
        *f ^= e;
    }
    f.extend(e);
    Ok(f)
}

/// Batched, level-synchronous variant of [`ohv`]: builds the one-hot vectors for
/// many indices at once. Each gate's level-`j` `pack_and` is independent of every
/// other gate's, so at every level all still-active gates' AND payloads are
/// concatenated into ONE `reshare`. The communication collapses from
/// `Σ_g (k_g − 1)` rounds (the per-gate recursion run sequentially) to `k_max − 1`
/// rounds, independent of the number of gates; the total bytes exchanged are
/// unchanged (the same bits are reshared, only regrouped per level).
///
/// `bits_per_gate[g]` holds the `k_g` bit-shares of index `g` (LSB first, exactly
/// the bits [`ohv`] extracts via `get_bit`). The returned vector `g` is the one-hot
/// vector of length `2^{k_g}`, elementwise value-identical to `ohv(k_g, ·)` (the
/// local doubling algebra is reproduced verbatim; only the reshare grouping differs,
/// so the reconstructed values match while the individual share splits may not).
pub fn ohv_many<N: Network>(
    bits_per_gate: &[Vec<Rep3RingShare<Bit>>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Vec<Rep3RingShare<Bit>>>> {
    let g = bits_per_gate.len();
    if g == 0 {
        return Ok(Vec::new());
    }
    debug_assert!(bits_per_gate.iter().all(|b| !b.is_empty()));

    // Base level (the `new_k == 0` base case of `ohv`): f_g = [!b0, b0], no comms.
    let mut fs: Vec<Vec<Rep3RingShare<Bit>>> = bits_per_gate
        .iter()
        .map(|b| {
            let b0 = b[0];
            vec![!b0, b0]
        })
        .collect();

    let k_max = bits_per_gate.iter().map(|b| b.len()).max().unwrap();

    // Level j incorporates bit j (doubling each active f from length 2^j to 2^{j+1}).
    // A gate is active while it still has a bit j to process (k_g > j).
    for j in 1..k_max {
        let active: Vec<usize> = (0..g).filter(|&gi| bits_per_gate[gi].len() > j).collect();
        if active.is_empty() {
            continue;
        }
        let len_j = (1usize << j) - 1; // = 2^j - 1, the prefix length ANDed at this level

        // Gather each active gate's AND operands: the length-(2^j-1) prefix of its
        // current f, ANDed with its bit j; ONE batched reshare across all of them.
        let prefixes: Vec<&[Rep3RingShare<Bit>]> =
            active.iter().map(|&gi| &fs[gi][..len_j]).collect();
        let rhss: Vec<Rep3RingShare<Bit>> = active.iter().map(|&gi| bits_per_gate[gi][j]).collect();

        let padded = len_j.next_power_of_two();
        let es = match padded {
            1 | 2 | 4 | 8 => pack_and_many_small::<u8, _>(&prefixes, &rhss, len_j, net, state)?,
            16 => pack_and_many_small::<u16, _>(&prefixes, &rhss, len_j, net, state)?,
            32 => pack_and_many_small::<u32, _>(&prefixes, &rhss, len_j, net, state)?,
            64 => pack_and_many_small::<u64, _>(&prefixes, &rhss, len_j, net, state)?,
            128 => pack_and_many_small::<u128, _>(&prefixes, &rhss, len_j, net, state)?,
            _ => pack_and_many_large(&prefixes, &rhss, len_j, net, state)?,
        };
        drop(prefixes); // release the immutable borrow of `fs` before mutating it below

        // Finish each active gate's level locally (mirrors the tail of `ohv`).
        for (idx, &gi) in active.iter().enumerate() {
            let vk = rhss[idx];
            let mut e = es[idx].clone();
            let last = e.iter().fold(vk, |a, b| &a ^ b);
            e.push(last);
            for (f, e) in fs[gi].iter_mut().zip(e.iter()) {
                *f ^= e;
            }
            fs[gi].extend(e);
        }
    }

    Ok(fs)
}

/// Batched `pack_and` for the small case (`len <= 128`, one `RingElement<T>` per
/// gate, `T` chosen to hold `len.next_power_of_two()` bits). Packs every gate's
/// prefix, applies the local masked AND, and reshares ALL gates in one round.
fn pack_and_many_small<T: IntRing2k, N: Network>(
    prefixes: &[&[Rep3RingShare<Bit>]],
    rhss: &[Rep3RingShare<Bit>],
    len: usize,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Vec<Rep3RingShare<Bit>>>>
where
    Standard: Distribution<T>,
{
    let mut to_send = Vec::with_capacity(prefixes.len());
    for (pre, rhs) in prefixes.iter().zip(rhss.iter()) {
        let packed = pack::<T>(pre);
        to_send.push(and_pre_bit(&packed, rhs, state));
    }
    let received = net.reshare(to_send.clone())?;
    Ok(to_send
        .into_iter()
        .zip(received)
        .map(|(a, b)| unpack(Rep3RingShare::new_ring(a, b), len))
        .collect())
}

/// Batched `pack_and` for the large case (`len > 128`, `u64` chunks per gate,
/// exactly mirroring [`pack_and`]'s chunked branch). Every gate's chunks are
/// concatenated so the whole level reshares in one round.
fn pack_and_many_large<N: Network>(
    prefixes: &[&[Rep3RingShare<Bit>]],
    rhss: &[Rep3RingShare<Bit>],
    len: usize,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Vec<Rep3RingShare<Bit>>>> {
    type Packtype = u64;
    const BITLEN: usize = std::mem::size_of::<Packtype>() * 8;
    let chunks_per_gate = len.div_ceil(BITLEN);

    let mut to_send = Vec::with_capacity(prefixes.len() * chunks_per_gate);
    for (pre, rhs) in prefixes.iter().zip(rhss.iter()) {
        for els in pre.chunks(BITLEN) {
            let packed = pack::<Packtype>(els);
            to_send.push(and_pre_bit(&packed, rhs, state));
        }
    }
    let received = net.reshare(to_send.clone())?;

    let mut res = Vec::with_capacity(prefixes.len());
    let mut it = to_send.into_iter().zip(received);
    for _ in 0..prefixes.len() {
        let mut remaining = len;
        let mut gate_bits = Vec::with_capacity(len);
        for _ in 0..chunks_per_gate {
            let (a, b) = it.next().expect("chunk count matches gate count");
            let take = std::cmp::min(BITLEN, remaining);
            gate_bits.extend(unpack(Rep3RingShare::new_ring(a, b), take));
            remaining -= take;
        }
        res.push(gate_bits);
    }
    Ok(res)
}

fn pack<T: IntRing2k>(input: &[Rep3RingShare<Bit>]) -> Rep3RingShare<T> {
    let mut share_a = RingElement::<T>::zero();
    let mut share_b = RingElement::<T>::zero();
    for (i, bit) in input.iter().enumerate() {
        share_a |= RingElement(T::from(bit.a.convert().convert()) << i);
        share_b |= RingElement(T::from(bit.b.convert().convert()) << i);
    }
    Rep3RingShare::new_ring(share_a, share_b)
}

fn unpack<T: IntRing2k>(input: Rep3RingShare<T>, len: usize) -> Vec<Rep3RingShare<Bit>> {
    debug_assert!(len <= T::K);
    let mut res = Vec::with_capacity(len);
    for i in 0..len {
        res.push(input.get_bit(i));
    }
    res
}

fn and_pre_bit<T: IntRing2k>(
    a: &Rep3RingShare<T>,
    b: &Rep3RingShare<Bit>,
    state: &mut Rep3State,
) -> RingElement<T>
where
    Standard: Distribution<T>,
{
    let (mut res, mask_b) = state.rngs.rand.random_elements::<RingElement<T>>();
    res ^= mask_b;
    if b.a.0.convert() {
        res ^= &a.a;
        res ^= &a.b;
    }
    if b.b.0.convert() {
        res ^= &a.a;
    }
    res
}

fn pack_and<N: Network>(
    input: &[Rep3RingShare<Bit>],
    rhs: &Rep3RingShare<Bit>,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3RingShare<Bit>>> {
    let len = input.len();
    debug_assert!(len >= 1);

    if len <= 128 {
        let padded_len = len.next_power_of_two();
        let result = match padded_len {
            1 => {
                vec![binary::and(&input[0], rhs, net, state)?]
            }
            2 | 4 | 8 => {
                let packed = pack::<u8>(input);
                let local_a = and_pre_bit(&packed, rhs, state);
                let local_b = net.reshare(local_a)?;
                unpack(Rep3RingShare::new_ring(local_a, local_b), len)
            }
            16 => {
                let packed = pack::<u16>(input);
                let local_a = and_pre_bit(&packed, rhs, state);
                let local_b = net.reshare(local_a)?;
                unpack(Rep3RingShare::new_ring(local_a, local_b), len)
            }
            32 => {
                let packed = pack::<u32>(input);
                let local_a = and_pre_bit(&packed, rhs, state);
                let local_b = net.reshare(local_a)?;
                unpack(Rep3RingShare::new_ring(local_a, local_b), len)
            }
            64 => {
                let packed = pack::<u64>(input);
                let local_a = and_pre_bit(&packed, rhs, state);
                let local_b = net.reshare(local_a)?;
                unpack(Rep3RingShare::new_ring(local_a, local_b), len)
            }
            128 => {
                let packed = pack::<u128>(input);
                let local_a = and_pre_bit(&packed, rhs, state);
                let local_b = net.reshare(local_a)?;
                unpack(Rep3RingShare::new_ring(local_a, local_b), len)
            }
            _ => {
                unreachable!()
            }
        };
        Ok(result)
    } else {
        type Packtype = u64;
        const BITLEN: usize = std::mem::size_of::<Packtype>() * 8;

        let mut result = Vec::with_capacity(len);
        let mut to_send = Vec::with_capacity(len.div_ceil(BITLEN));
        for els in input.chunks(BITLEN) {
            let packed = pack::<Packtype>(els);
            let u64_a = and_pre_bit(&packed, rhs, state);
            to_send.push(u64_a);
        }
        let received = net.reshare(to_send.to_owned())?;

        let mut remeining = len;
        for (a, b) in to_send.into_iter().zip(received) {
            let rcv = std::cmp::min(BITLEN, remeining);
            result.extend(unpack(Rep3RingShare::new_ring(a, b), rcv));
            remeining -= rcv;
        }
        debug_assert_eq!(remeining, 0);
        Ok(result)
    }
}

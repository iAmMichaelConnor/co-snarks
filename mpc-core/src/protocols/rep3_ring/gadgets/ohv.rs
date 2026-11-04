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

/// [`ohv`] for many indices at once. `bits[i]` holds the k_i bit shares of index i (LSB
/// first); the result i is its one-hot-encoded vector of size 2^(k_i), with the same values as
/// [`ohv`]. The level-j ANDs of all indices are independent, so each level is one reshare for
/// all indices: max_i k_i - 1 rounds in total instead of the sum of k_i - 1 over the indices.
/// The bits reshared are the same as in [`ohv`], regrouped per level.
pub fn ohv_many<N: Network>(
    bits: &[Vec<Rep3RingShare<Bit>>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Vec<Rep3RingShare<Bit>>>> {
    eyre::ensure!(
        bits.iter().all(|bits| !bits.is_empty()),
        "Every index needs at least one bit"
    );
    // The base case of ohv: [!b_0, b_0]
    let mut fs = bits
        .iter()
        .map(|bits| vec![!bits[0], bits[0]])
        .collect::<Vec<_>>();
    let max_k = bits.iter().map(Vec::len).max().unwrap_or(0);

    // Level j doubles the vectors of all indices with more than j bits from 2^j to 2^(j+1).
    for j in 1..max_k {
        let active = (0..bits.len())
            .filter(|&i| bits[i].len() > j)
            .collect::<Vec<_>>();
        let len = (1 << j) - 1;
        let inputs = active.iter().map(|&i| &fs[i][..len]).collect::<Vec<_>>();
        let rhs = active.iter().map(|&i| bits[i][j]).collect::<Vec<_>>();
        let es = match len.next_power_of_two() {
            1 | 2 | 4 | 8 => pack_and_many::<u8, _>(&inputs, &rhs, net, state)?,
            16 => pack_and_many::<u16, _>(&inputs, &rhs, net, state)?,
            32 => pack_and_many::<u32, _>(&inputs, &rhs, net, state)?,
            64 => pack_and_many::<u64, _>(&inputs, &rhs, net, state)?,
            _ => pack_and_many::<u128, _>(&inputs, &rhs, net, state)?,
        };
        for (&i, vk, mut e) in itertools::izip!(&active, rhs, es) {
            e.push(e.iter().fold(vk, |a, b| &a ^ b));
            for (e, f) in e.iter().zip(fs[i].iter_mut()) {
                *f ^= e;
            }
            fs[i].extend(e);
        }
    }
    Ok(fs)
}

/// ANDs each of the `inputs` with its bit in `rhs`, packing the bits of each input into
/// elements of `T` (several elements for inputs longer than `T::K`), in one reshare for all.
fn pack_and_many<T: IntRing2k, N: Network>(
    inputs: &[&[Rep3RingShare<Bit>]],
    rhs: &[Rep3RingShare<Bit>],
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Vec<Rep3RingShare<Bit>>>>
where
    Standard: Distribution<T>,
{
    let mut local_a = Vec::new();
    for (input, rhs) in inputs.iter().zip(rhs) {
        for chunk in input.chunks(T::K) {
            local_a.push(and_pre_bit(&pack::<T>(chunk), rhs, state));
        }
    }
    let local_b = net.reshare_many(&local_a)?;
    let mut shares = local_a
        .into_iter()
        .zip(local_b)
        .map(|(a, b)| Rep3RingShare::new_ring(a, b));
    Ok(inputs
        .iter()
        .map(|input| {
            input
                .chunks(T::K)
                .flat_map(|chunk| unpack(shares.next().expect("one share per chunk"), chunk.len()))
                .collect()
        })
        .collect())
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

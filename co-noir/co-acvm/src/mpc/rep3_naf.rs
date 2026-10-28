//! Fixed-schedule signed-digit witnesses for the recursive curve gadget.
use ark_ff::PrimeField;
use mpc_core::protocols::rep3::{Rep3PrimeFieldShare, Rep3State, Rep3UintShare, conversion};
use mpc_core::uint::{FieldUint, UintBackend};
use mpc_net::Network;

pub(super) fn entries<F: PrimeField + FieldUint, N: Network>(
    scalar: Rep3PrimeFieldShare<F>,
    max_num_bits: usize,
    net: &N,
    state: &mut Rep3State,
) -> eyre::Result<Vec<Rep3PrimeFieldShare<F>>> {
    let rounds = if max_num_bits == 0 {
        F::MODULUS_BIT_SIZE as usize
    } else {
        max_num_bits
    };
    eyre::ensure!(
        rounds <= F::MODULUS_BIT_SIZE as usize,
        "NAF width exceeds scalar field width"
    );
    let bits = conversion::a2b_selector(scalar, net, state)?;
    // Entry zero is skew = !bit(0); later entries are !bit(i).
    // For an even integer adding skew changes only bit zero, so no secret
    // addition or zero special case is needed. In particular scalar zero has
    // skew one and all inverted upper bits one, at the same public width.
    // The caller constrains the signed-digit sum to equal the input scalar.
    let inverted: Vec<_> = (0..rounds)
        .map(|i| {
            Rep3UintShare::<F>::new(
                F::Uint::from(u64::from(!bits.a.bit(i))),
                F::Uint::from(u64::from(!bits.b.bit(i))),
            )
        })
        .collect();
    // Flipping every additive XOR component flips the reconstructed bit:
    // there are exactly three components. No bit or scalar is opened.
    conversion::bit_inject_many(&inverted, net, state)
}

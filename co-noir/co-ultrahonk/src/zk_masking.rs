//! The source of the prover's ZK masking values.
//!
//! The masking values are normally fresh random shares. For tests, they can be derived from a
//! seed instead (see `CoUltraHonk::prove_with_seeded_zk_masking`, available with the `test-utils`
//! feature): then a ZK proof is a deterministic function of the witness, so the proofs of
//! different MPC protocols can be compared byte by byte. A seeded proof is not zero-knowledge.
//!
//! Only the masking values go through this source; other randomness of the protocols (e.g. for
//! masking openings) cancels out and does not affect the proof.
use co_noir_common::{
    honk_curve::HonkCurve, honk_proof::TranscriptFieldType, mpc::NoirUltraHonkProver,
};
use mpc_core::MpcState;
use mpc_net::Network;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;

/// The masking values of a ZK proof.
#[derive(Clone, Debug, Default)]
pub(crate) enum ZkMasking {
    /// Fresh random shares.
    #[default]
    Random,
    /// Public values derived from the seed: each masking site (see [`ZkMasking::values`]) has its
    /// own stream, so the values do not depend on the order in which the sites are reached.
    #[cfg_attr(not(any(test, feature = "test-utils")), expect(dead_code))]
    Seeded([u8; 32]),
}

impl ZkMasking {
    /// `n` masking values for the masking site `site`. Every site must have its own label.
    pub(crate) fn values<
        T: NoirUltraHonkProver<P>,
        P: HonkCurve<TranscriptFieldType>,
        N: Network,
    >(
        &self,
        site: &str,
        n: usize,
        net: &N,
        state: &mut T::State,
    ) -> eyre::Result<Vec<T::ArithmeticShare>> {
        match self {
            ZkMasking::Random => (0..n).map(|_| T::rand(net, state)).collect(),
            ZkMasking::Seeded(seed) => {
                let mut rng = ChaCha12Rng::from_seed(*seed);
                rng.set_stream(site_stream(site));
                let id = state.id();
                Ok((0..n)
                    .map(|_| T::promote_to_trivial_share(id, ark_ff::UniformRand::rand(&mut rng)))
                    .collect())
            }
        }
    }
}

/// The ChaCha stream of a masking site: the 64-bit FNV-1a hash of its label.
fn site_stream(site: &str) -> u64 {
    site.bytes().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fr, G1Projective};
    use co_noir_common::mpc::plain::PlainUltraHonkDriver;

    fn values(masking: &ZkMasking, site: &str) -> Vec<Fr> {
        masking
            .values::<PlainUltraHonkDriver, G1Projective, _>(site, 4, &(), &mut Default::default())
            .unwrap()
    }

    #[test]
    fn seeded_values_are_reproducible_and_differ_between_sites_and_seeds() {
        let seeded = ZkMasking::Seeded([7; 32]);
        assert_eq!(values(&seeded, "a"), values(&seeded, "a"));
        assert_ne!(values(&seeded, "a"), values(&seeded, "b"));
        assert_ne!(
            values(&seeded, "a"),
            values(&ZkMasking::Seeded([8; 32]), "a")
        );
        assert_ne!(
            values(&ZkMasking::Random, "a"),
            values(&ZkMasking::Random, "a")
        );
    }
}

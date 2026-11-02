//! The privacy that proofs with a proving key must have.
use crate::{honk_proof::HonkProofResult, types::ZeroKnowledge};

/// The privacy that proofs with a proving key must have. This is part of the proving key, not of
/// the verification key.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProofPrivacy {
    /// The circuit is the same as barretenberg's; any proof mode may be used.
    #[default]
    Standard,
    /// The circuit was built with the private recursion profile: its witness contains the secret
    /// recursion inputs, so proofs must be zero-knowledge with fresh masking values.
    PrivateRecursion,
}

impl ProofPrivacy {
    /// Checks that a proof with `has_zk` (and, if `seeded_masking`, masking values derived from a
    /// seed instead of fresh randomness) has the privacy this key requires.
    pub fn validate_proving_mode(
        self,
        has_zk: ZeroKnowledge,
        seeded_masking: bool,
    ) -> HonkProofResult<()> {
        if self == Self::PrivateRecursion && (has_zk != ZeroKnowledge::Yes || seeded_masking) {
            return Err(eyre::eyre!(
                "The proving key was built for private recursion and requires a zero-knowledge proof with fresh masking (co-noir: --zk)"
            )
            .into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_recursion_requires_fresh_zero_knowledge() {
        for privacy in [ProofPrivacy::Standard, ProofPrivacy::PrivateRecursion] {
            for has_zk in [ZeroKnowledge::No, ZeroKnowledge::Yes] {
                for seeded_masking in [false, true] {
                    assert_eq!(
                        privacy
                            .validate_proving_mode(has_zk, seeded_masking)
                            .is_ok(),
                        privacy == ProofPrivacy::Standard
                            || (has_zk == ZeroKnowledge::Yes && !seeded_masking),
                        "{privacy:?} {has_zk:?} seeded {seeded_masking}"
                    );
                }
            }
        }
    }
}

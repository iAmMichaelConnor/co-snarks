//! Proving-key privacy policy. This is local key metadata, not part of the BB VK.
use crate::{honk_proof::HonkProofResult, types::ZeroKnowledge};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The mandatory prefix versions the serialized co-proving-key format. Older
/// keys have no privacy policy and must be regenerated rather than guessed safe.
const KEY_FORMAT: [u8; 8] = *b"COPK0001";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProofPrivacy {
    #[default]
    Standard,
    PrivateRecursion,
}

impl ProofPrivacy {
    pub fn validate_proving_mode(self, has_zk: ZeroKnowledge, seeded: bool) -> HonkProofResult<()> {
        if self == Self::PrivateRecursion && (has_zk != ZeroKnowledge::Yes || seeded) {
            return Err(eyre::eyre!(
                "Private recursion requires a zero-knowledge outer proof with fresh masking; use --zk (seeded masking is not permitted)"
            ).into());
        }
        Ok(())
    }
}

impl Serialize for ProofPrivacy {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (KEY_FORMAT, *self == Self::PrivateRecursion).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ProofPrivacy {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let (format, private): ([u8; 8], bool) = Deserialize::deserialize(deserializer)?;
        if format != KEY_FORMAT {
            return Err(serde::de::Error::custom(
                "Unsupported co-proving-key format: regenerate the key with explicit recursion privacy metadata",
            ));
        }
        Ok(if private {
            Self::PrivateRecursion
        } else {
            Self::Standard
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_recursion_requires_fresh_zero_knowledge() {
        for policy in [ProofPrivacy::Standard, ProofPrivacy::PrivateRecursion] {
            for zk in [ZeroKnowledge::No, ZeroKnowledge::Yes] {
                for seeded in [false, true] {
                    assert_eq!(
                        policy.validate_proving_mode(zk, seeded).is_ok(),
                        policy == ProofPrivacy::Standard || (zk == ZeroKnowledge::Yes && !seeded)
                    );
                }
            }
        }
    }
}

use crate::crs::ProverCrs;
use crate::keys::plain_proving_key::PlainProvingKey;
use crate::keys::proof_privacy::ProofPrivacy;
use crate::keys::types::ActiveRegionData;
use crate::keys::verification_key::VerifyingKey;
use crate::keys::verification_key::VerifyingKeyBarretenberg;
use crate::mpc::rep3::Rep3UltraHonkDriver;
use crate::mpc::shamir::ShamirUltraHonkDriver;
use crate::polynomials::entities::Polynomials;
use crate::polynomials::entities::PrecomputedEntities;
use crate::polynomials::entities::ProverWitnessEntities;
use crate::polynomials::polynomial::Polynomial;
use crate::utils::Utils;
use crate::{HonkCurve, TranscriptFieldType};
use ark_ec::CurveGroup;
use ark_ec::pairing::Pairing;
use eyre::Result;
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;
use std::marker::PhantomData;

use crate::mpc::NoirUltraHonkProver;

/// A proving key with a secret-shared witness.
///
/// In serialized form, a key of the [`ProofPrivacy::Standard`] profile is the sequence of its
/// fields. A key of another profile starts with [`PRIVACY_MARKER`] in place of the circuit size,
/// followed by the format version, the profile and the circuit size, so that it cannot be read as
/// a standard key.
pub struct ProvingKey<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub circuit_size: u32,
    pub public_inputs: Vec<P::ScalarField>,
    pub num_public_inputs: u32,
    pub pub_inputs_offset: u32,
    pub polynomials: Polynomials<T::ArithmeticShare, P::ScalarField>,
    pub memory_read_records: Vec<u32>,
    pub memory_write_records: Vec<u32>,
    pub rom_logup_records: Vec<u32>,
    pub memory_records_shared: BTreeMap<u32, T::ArithmeticShare>,
    pub final_active_wire_idx: usize,
    pub active_region_data: ActiveRegionData,
    /// The privacy that proofs with this key must have.
    pub proof_privacy: ProofPrivacy,
    pub phantom: PhantomData<T>,
}

/// Replaces the circuit size at the start of a serialized proving key that is not of the
/// [`ProofPrivacy::Standard`] profile. Circuit sizes are powers of two, so this is never one.
pub const PRIVACY_MARKER: u32 = u32::MAX;
const PRIVACY_FORMAT_VERSION: u32 = 1;
const PRIVATE_RECURSION_TAG: u32 = 1;

/// The serialized circuit size and privacy profile of a proving key: the circuit size alone for
/// [`ProofPrivacy::Standard`], otherwise ([`PRIVACY_MARKER`], version, profile, circuit size).
struct KeyHeader {
    circuit_size: u32,
    proof_privacy: ProofPrivacy,
}

impl Serialize for KeyHeader {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.proof_privacy {
            ProofPrivacy::Standard if self.circuit_size == PRIVACY_MARKER => {
                Err(serde::ser::Error::custom("invalid circuit size"))
            }
            ProofPrivacy::Standard => serializer.serialize_u32(self.circuit_size),
            ProofPrivacy::PrivateRecursion => (
                PRIVACY_MARKER,
                PRIVACY_FORMAT_VERSION,
                PRIVATE_RECURSION_TAG,
                self.circuit_size,
            )
                .serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for KeyHeader {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct HeaderVisitor;
        impl<'de> Visitor<'de> for HeaderVisitor {
            type Value = KeyHeader;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a circuit size or a proving key privacy header")
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> Result<KeyHeader, E> {
                match u32::try_from(value) {
                    Ok(circuit_size) if circuit_size != PRIVACY_MARKER => Ok(KeyHeader {
                        circuit_size,
                        proof_privacy: ProofPrivacy::Standard,
                    }),
                    _ => Err(E::custom("invalid circuit size")),
                }
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<KeyHeader, A::Error> {
                let mut next = |what| {
                    seq.next_element::<u32>()?
                        .ok_or_else(|| de::Error::custom(format!("missing {what}")))
                };
                let first = next("circuit size")?;
                if first != PRIVACY_MARKER {
                    return self.visit_u64(first.into());
                }
                let version = next("format version")?;
                let tag = next("privacy profile")?;
                let circuit_size = next("circuit size")?;
                if version != PRIVACY_FORMAT_VERSION {
                    return Err(de::Error::custom(format!(
                        "unsupported proving key format version {version}"
                    )));
                }
                if tag != PRIVATE_RECURSION_TAG {
                    return Err(de::Error::custom(format!(
                        "unknown proving key privacy profile {tag}"
                    )));
                }
                self.visit_u64(circuit_size.into()).map(|header| KeyHeader {
                    proof_privacy: ProofPrivacy::PrivateRecursion,
                    ..header
                })
            }
        }
        if deserializer.is_human_readable() {
            deserializer.deserialize_any(HeaderVisitor)
        } else {
            // A standard key has only the first element; binary formats read it on demand.
            deserializer.deserialize_tuple(4, HeaderVisitor)
        }
    }
}

/// The serialized form of [`ProvingKey`], for serializing.
#[derive(Serialize)]
#[serde(bound = "", rename = "ProvingKey")]
struct ProvingKeyRef<'a, T: NoirUltraHonkProver<P>, P: CurveGroup> {
    circuit_size: KeyHeader,
    #[serde(serialize_with = "mpc_core::serde_compat::ark_se")]
    public_inputs: &'a Vec<P::ScalarField>,
    num_public_inputs: u32,
    pub_inputs_offset: u32,
    polynomials: &'a Polynomials<T::ArithmeticShare, P::ScalarField>,
    memory_read_records: &'a [u32],
    memory_write_records: &'a [u32],
    rom_logup_records: &'a [u32],
    #[serde(serialize_with = "mpc_core::serde_compat::ark_se")]
    memory_records_shared: &'a BTreeMap<u32, T::ArithmeticShare>,
    final_active_wire_idx: usize,
    active_region_data: &'a ActiveRegionData,
    phantom: PhantomData<T>,
}

/// The serialized form of [`ProvingKey`], for deserializing.
#[derive(Deserialize)]
#[serde(bound = "", rename = "ProvingKey")]
struct ProvingKeyData<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    circuit_size: KeyHeader,
    #[serde(deserialize_with = "mpc_core::serde_compat::ark_de")]
    public_inputs: Vec<P::ScalarField>,
    num_public_inputs: u32,
    pub_inputs_offset: u32,
    polynomials: Polynomials<T::ArithmeticShare, P::ScalarField>,
    memory_read_records: Vec<u32>,
    memory_write_records: Vec<u32>,
    rom_logup_records: Vec<u32>,
    #[serde(deserialize_with = "mpc_core::serde_compat::ark_de")]
    memory_records_shared: BTreeMap<u32, T::ArithmeticShare>,
    final_active_wire_idx: usize,
    active_region_data: ActiveRegionData,
    phantom: PhantomData<T>,
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Serialize for ProvingKey<T, P> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        ProvingKeyRef::<T, P> {
            circuit_size: KeyHeader {
                circuit_size: self.circuit_size,
                proof_privacy: self.proof_privacy,
            },
            public_inputs: &self.public_inputs,
            num_public_inputs: self.num_public_inputs,
            pub_inputs_offset: self.pub_inputs_offset,
            polynomials: &self.polynomials,
            memory_read_records: &self.memory_read_records,
            memory_write_records: &self.memory_write_records,
            rom_logup_records: &self.rom_logup_records,
            memory_records_shared: &self.memory_records_shared,
            final_active_wire_idx: self.final_active_wire_idx,
            active_region_data: &self.active_region_data,
            phantom: PhantomData,
        }
        .serialize(serializer)
    }
}

impl<'de, T: NoirUltraHonkProver<P>, P: CurveGroup> Deserialize<'de> for ProvingKey<T, P> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let data = ProvingKeyData::<T, P>::deserialize(deserializer)?;
        Ok(Self {
            circuit_size: data.circuit_size.circuit_size,
            public_inputs: data.public_inputs,
            num_public_inputs: data.num_public_inputs,
            pub_inputs_offset: data.pub_inputs_offset,
            polynomials: data.polynomials,
            memory_read_records: data.memory_read_records,
            memory_write_records: data.memory_write_records,
            rom_logup_records: data.rom_logup_records,
            memory_records_shared: data.memory_records_shared,
            final_active_wire_idx: data.final_active_wire_idx,
            active_region_data: data.active_region_data,
            proof_privacy: data.circuit_size.proof_privacy,
            phantom: PhantomData,
        })
    }
}

impl<T: NoirUltraHonkProver<C>, C: CurveGroup> Default for ProvingKey<T, C> {
    fn default() -> Self {
        Self {
            proof_privacy: ProofPrivacy::Standard,
            circuit_size: 0,
            public_inputs: Vec::new(),
            num_public_inputs: 0,
            pub_inputs_offset: 0,
            polynomials: Polynomials::default(),
            memory_read_records: Vec::new(),
            memory_write_records: Vec::new(),
            rom_logup_records: Vec::new(),
            memory_records_shared: BTreeMap::new(),
            final_active_wire_idx: 0,
            active_region_data: ActiveRegionData::default(),
            phantom: PhantomData,
        }
    }
}

pub type Rep3ProvingKey<P> = ProvingKey<Rep3UltraHonkDriver, P>;
pub type ShamirProvingKey<P> = ProvingKey<ShamirUltraHonkDriver, P>;

impl<T: NoirUltraHonkProver<C>, C: CurveGroup> ProvingKey<T, C> {
    pub const PUBLIC_INPUT_WIRE_INDEX: usize = ProverWitnessEntities::<T::ArithmeticShare>::W_R;

    pub fn from_plain_key_and_shares(
        plain_key: &PlainProvingKey<C>,
        shares: Vec<T::ArithmeticShare>,
    ) -> Result<Self> {
        let circuit_size = plain_key.circuit_size;
        let public_inputs = plain_key.public_inputs.to_owned();
        let num_public_inputs = plain_key.num_public_inputs;
        let pub_inputs_offset = plain_key.pub_inputs_offset;
        let memory_read_records = plain_key.memory_read_records.to_owned();
        let memory_write_records = plain_key.memory_write_records.to_owned();
        let rom_logup_records = plain_key.rom_logup_records.to_owned();
        let final_active_wire_idx = plain_key.final_active_wire_idx;
        let active_region_data = plain_key.active_region_data.to_owned();

        if shares.len() != circuit_size as usize * 6 {
            eyre::bail!("Share length is not 6 times circuit size");
        }

        let mut polynomials = Polynomials::default();
        for (src, des) in plain_key
            .polynomials
            .precomputed
            .iter()
            .zip(polynomials.precomputed.iter_mut())
        {
            *des = src.to_owned();
        }

        for (src, des) in shares
            .chunks_exact(circuit_size as usize)
            .zip(polynomials.witness.iter_mut())
        {
            *des = Polynomial::new(src.to_owned());
        }
        Ok(Self {
            proof_privacy: plain_key.proof_privacy,
            circuit_size,
            public_inputs,
            num_public_inputs,
            pub_inputs_offset,
            polynomials,
            memory_read_records,
            memory_write_records,
            rom_logup_records,
            final_active_wire_idx,
            phantom: PhantomData,
            memory_records_shared: BTreeMap::new(),
            active_region_data,
        })
    }

    pub fn create_vk<P: Pairing<G1Affine = C::Affine, G1 = C>>(
        &self,
        prover_crs: &ProverCrs<C>,
        verifier_crs: P::G2Affine,
    ) -> Result<VerifyingKey<P>>
    where
        C: HonkCurve<TranscriptFieldType>,
    {
        let mut commitments = PrecomputedEntities::default();
        for (des, src) in commitments
            .iter_mut()
            .zip(self.polynomials.precomputed.iter())
        {
            let comm = Utils::commit(src.as_ref(), prover_crs)?;
            *des = C::Affine::from(comm);
        }
        Ok(VerifyingKey {
            crs: verifier_crs,
            inner_vk: VerifyingKeyBarretenberg {
                log_circuit_size: Utils::get_msb64(self.circuit_size as u64) as u64,
                num_public_inputs: self.num_public_inputs as u64,
                pub_inputs_offset: self.pub_inputs_offset as u64,
                commitments,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ZeroKnowledge;
    use ark_bn254::{Fr, G1Projective};
    use mpc_core::protocols::rep3::Rep3PrimeFieldShare;

    /// The ROM and memory metadata of a proving key must survive the conversion from a plain key and a bincode
    /// round trip, since the MPC parties receive the key in that form.
    fn rom_metadata_round_trip<T: NoirUltraHonkProver<G1Projective>>(proof_privacy: ProofPrivacy) {
        let mut plain = PlainProvingKey::<G1Projective> {
            proof_privacy,
            circuit_size: 16,
            public_inputs: vec![Fr::from(17u64), Fr::from(23u64)],
            num_public_inputs: 2,
            pub_inputs_offset: 4,
            polynomials: crate::polynomials::polynomial::Polynomials::new(16),
            memory_read_records: vec![12],
            memory_write_records: vec![13],
            rom_logup_records: vec![5, 6, 8, 9, 10],
            final_active_wire_idx: 14,
            ..Default::default()
        };
        plain.active_region_data.add_range(4, 14);
        // The ROM array ids live in q_c of the table rows.
        plain.polynomials.precomputed.q_c_mut()[5] = Fr::from(31u64);
        plain.polynomials.precomputed.q_c_mut()[8] = Fr::from(37u64);
        let shares = vec![T::ArithmeticShare::default(); 6 * 16];
        let mut shared = ProvingKey::<T, G1Projective>::from_plain_key_and_shares(&plain, shares)
            .expect("convert plain key to shared key");
        assert_eq!(shared.rom_logup_records, plain.rom_logup_records);
        // Also fill the neighbouring variable-length field to detect a layout change.
        shared
            .memory_records_shared
            .insert(13, T::ArithmeticShare::default());

        let mut bytes = Vec::new();
        bincode::serialize_into(&mut bytes, &shared).unwrap();
        let loaded: ProvingKey<T, G1Projective> =
            bincode::deserialize_from(bytes.as_slice()).unwrap();
        assert_eq!(loaded.rom_logup_records, plain.rom_logup_records);
        assert_eq!(loaded.proof_privacy, proof_privacy);
        assert_eq!(loaded.memory_read_records, plain.memory_read_records);
        assert_eq!(loaded.memory_write_records, plain.memory_write_records);
        assert_eq!(
            loaded
                .memory_records_shared
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            vec![13]
        );
        assert_eq!(loaded.final_active_wire_idx, plain.final_active_wire_idx);
        assert_eq!(loaded.active_region_data, plain.active_region_data);
        assert_eq!(loaded.public_inputs, plain.public_inputs);
        assert_eq!(loaded.polynomials.precomputed.q_c()[5], Fr::from(31u64));
        assert_eq!(loaded.polynomials.precomputed.q_c()[8], Fr::from(37u64));
        assert_eq!(bincode::serialize(&loaded).unwrap(), bytes);
    }

    #[test]
    fn rep3_rom_metadata_survives_conversion_and_serialization() {
        for proof_privacy in [ProofPrivacy::Standard, ProofPrivacy::PrivateRecursion] {
            rom_metadata_round_trip::<Rep3UltraHonkDriver>(proof_privacy);
        }
    }

    #[test]
    fn shamir_rom_metadata_survives_conversion_and_serialization() {
        for proof_privacy in [ProofPrivacy::Standard, ProofPrivacy::PrivateRecursion] {
            rom_metadata_round_trip::<ShamirUltraHonkDriver>(proof_privacy);
        }
    }

    /// A REP3 key with every field set: `test_data/rep3_proving_key.bin` is its serialization
    /// in the format without privacy metadata.
    fn example_key(proof_privacy: ProofPrivacy) -> Rep3ProvingKey<G1Projective> {
        let share = |a: u64| Rep3PrimeFieldShare::new(Fr::from(a), Fr::from(a + 1));
        let mut polynomials = Polynomials::new(2);
        for (i, poly) in polynomials.witness.iter_mut().enumerate() {
            poly[1] = share(40 + i as u64);
        }
        for (i, poly) in polynomials.precomputed.iter_mut().enumerate() {
            poly[0] = Fr::from(60 + i as u64);
        }
        let mut key = Rep3ProvingKey::<G1Projective> {
            circuit_size: 2,
            public_inputs: vec![Fr::from(17u64), Fr::from(23u64)],
            num_public_inputs: 2,
            pub_inputs_offset: 1,
            polynomials,
            memory_read_records: vec![1],
            memory_write_records: vec![0],
            rom_logup_records: vec![1],
            final_active_wire_idx: 1,
            proof_privacy,
            ..Default::default()
        };
        key.memory_records_shared.insert(1, share(90));
        key.active_region_data.add_range(0, 2);
        key
    }

    const STANDARD_KEY: &[u8] = include_bytes!("test_data/rep3_proving_key.bin");

    #[test]
    fn keys_without_privacy_metadata_load_as_standard() {
        let key: Rep3ProvingKey<G1Projective> = bincode::deserialize(STANDARD_KEY).unwrap();
        assert_eq!(key.proof_privacy, ProofPrivacy::Standard);
        let expected = example_key(ProofPrivacy::Standard);
        assert_eq!(bincode::serialize(&expected).unwrap(), STANDARD_KEY);
        assert_eq!(key.public_inputs, expected.public_inputs);
        assert_eq!(key.memory_records_shared, expected.memory_records_shared);
        assert_eq!(key.active_region_data, expected.active_region_data);
        assert_eq!(bincode::serialize(&key).unwrap(), STANDARD_KEY);
    }

    #[test]
    fn private_recursion_keys_are_marked() {
        let bytes = bincode::serialize(&example_key(ProofPrivacy::PrivateRecursion)).unwrap();
        // Marker, version, profile and circuit size replace the circuit size; the rest is the
        // same as for a standard key.
        let header: Vec<u8> = [PRIVACY_MARKER, 1, 1, 2]
            .iter()
            .flat_map(|x| x.to_le_bytes())
            .collect();
        assert_eq!(bytes[..16], header);
        assert_eq!(bytes[16..], STANDARD_KEY[4..]);
        let key: Rep3ProvingKey<G1Projective> = bincode::deserialize(&bytes).unwrap();
        assert_eq!(key.proof_privacy, ProofPrivacy::PrivateRecursion);
        assert_eq!(key.circuit_size, 2);
        assert!(
            key.proof_privacy
                .validate_proving_mode(ZeroKnowledge::No, false)
                .is_err()
        );
        assert_eq!(bincode::serialize(&key).unwrap(), bytes);

        // An unknown version or profile, the marker as circuit size, or a truncated header is
        // rejected.
        let load = |bytes: &[u8]| bincode::deserialize::<Rep3ProvingKey<G1Projective>>(bytes);
        for (offset, value) in [(4, 0), (4, 2), (8, 0), (8, 2), (12, PRIVACY_MARKER)] {
            let mut bytes = bytes.clone();
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            assert!(load(&bytes).is_err(), "{offset} {value}");
        }
        for length in 0..16 {
            assert!(load(&bytes[..length]).is_err());
        }
    }
}

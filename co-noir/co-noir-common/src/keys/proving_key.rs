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
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::marker::PhantomData;

use crate::mpc::NoirUltraHonkProver;

#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct ProvingKey<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    /// Mandatory, versioned first field: old keys cannot silently lose policy.
    pub proof_privacy: ProofPrivacy,
    pub circuit_size: u32,
    #[serde(
        serialize_with = "mpc_core::serde_compat::ark_se",
        deserialize_with = "mpc_core::serde_compat::ark_de"
    )]
    pub public_inputs: Vec<P::ScalarField>,
    pub num_public_inputs: u32,
    pub pub_inputs_offset: u32,
    pub polynomials: Polynomials<T::ArithmeticShare, P::ScalarField>,
    pub memory_read_records: Vec<u32>,
    pub memory_write_records: Vec<u32>,
    /// Absolute trace rows whose fourth wire receives a ROM LogUp inverse.
    pub rom_logup_records: Vec<u32>,
    #[serde(
        serialize_with = "mpc_core::serde_compat::ark_se",
        deserialize_with = "mpc_core::serde_compat::ark_de"
    )]
    pub memory_records_shared: BTreeMap<u32, T::ArithmeticShare>,
    pub final_active_wire_idx: usize,
    pub active_region_data: ActiveRegionData,
    pub phantom: PhantomData<T>,
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
mod rom_metadata_tests {
    use super::*;
    use ark_bn254::{Fr, G1Projective};

    fn check_metadata_round_trip<T: NoirUltraHonkProver<G1Projective>>() {
        let mut plain = PlainProvingKey::<G1Projective> {
            proof_privacy: ProofPrivacy::PrivateRecursion,
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
        // Distinct array identifiers must remain bound to the public ROM rows.
        plain.polynomials.precomputed.q_c_mut()[5] = Fr::from(31u64);
        plain.polynomials.precomputed.q_c_mut()[8] = Fr::from(37u64);
        let shares = vec![T::ArithmeticShare::default(); 6 * 16];
        let mut shared = ProvingKey::<T, G1Projective>::from_plain_key_and_shares(&plain, shares)
            .expect("convert plain key to shared key");
        assert_eq!(shared.rom_logup_records, plain.rom_logup_records);
        assert_eq!(shared.proof_privacy, ProofPrivacy::PrivateRecursion);
        // Include the neighboring variable-length field to detect layout loss.
        shared
            .memory_records_shared
            .insert(13, T::ArithmeticShare::default());
        let mut bytes = Vec::new();
        bincode::serialize_into(&mut bytes, &shared).unwrap();
        let loaded: ProvingKey<T, G1Projective> =
            bincode::deserialize_from(bytes.as_slice()).unwrap();
        assert_eq!(loaded.rom_logup_records, plain.rom_logup_records);
        assert_eq!(loaded.proof_privacy, ProofPrivacy::PrivateRecursion);
        assert!(
            loaded
                .proof_privacy
                .validate_proving_mode(crate::types::ZeroKnowledge::No, false)
                .is_err()
        );
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
        check_metadata_round_trip::<Rep3UltraHonkDriver>();
    }

    #[test]
    fn shamir_rom_metadata_survives_conversion_and_serialization() {
        check_metadata_round_trip::<ShamirUltraHonkDriver>();
    }
}

#[cfg(test)]
mod privacy_format_tests {
    use super::*;
    use ark_bn254::G1Projective;

    #[test]
    fn proving_key_format_requires_version_and_policy() {
        type Key = ProvingKey<Rep3UltraHonkDriver, G1Projective>;
        for privacy in [ProofPrivacy::Standard, ProofPrivacy::PrivateRecursion] {
            let key = Key {
                proof_privacy: privacy,
                circuit_size: 16,
                ..Default::default()
            };
            let bytes = bincode::serialize(&key).unwrap();
            assert_eq!(&bytes[..8], b"COPK0001");
            let loaded: Key = bincode::deserialize(&bytes).unwrap();
            assert_eq!(loaded.proof_privacy, privacy);
            // This is the previous field layout: circuit_size was first. Never
            // deserialize it with an implicit Standard/default policy.
            assert!(bincode::deserialize::<Key>(&bytes[9..]).is_err());
            for length in 0..9 {
                assert!(bincode::deserialize::<Key>(&bytes[..length]).is_err());
            }
            let mut corrupt_version = bytes.clone();
            corrupt_version[7] = b'0';
            assert!(bincode::deserialize::<Key>(&corrupt_version).is_err());
            struct PrefixOnly<'a>(&'a [u8]);
            impl std::io::Read for PrefixOnly<'_> {
                fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                    assert!(
                        out.len() <= self.0.len(),
                        "decoder read payload before rejecting version"
                    );
                    let n = out.len();
                    out.copy_from_slice(&self.0[..n]);
                    self.0 = &self.0[n..];
                    Ok(n)
                }
            }
            // No payload read, length decoding, or large allocation is allowed
            // before the unsupported prefix is rejected.
            assert!(
                bincode::deserialize_from::<_, Key>(PrefixOnly(&corrupt_version[..9])).is_err()
            );
            let mut invalid_policy = bytes;
            invalid_policy[8] = 2;
            assert!(bincode::deserialize::<Key>(&invalid_policy).is_err());
        }
    }
}

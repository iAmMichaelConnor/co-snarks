use crate::polynomials::entities::PRECOMPUTED_ENTITIES_SIZE;
use ark_ec::AffineRepr;
use ark_ec::{CurveGroup, pairing::Pairing};
use ark_ff::PrimeField;
use ark_ff::Zero;
use noir_types::{SerializeF, U256};
use num_bigint::BigUint;

use crate::{
    honk_curve::HonkCurve,
    honk_proof::{HonkProofError, HonkProofResult, TranscriptFieldType},
    polynomials::entities::PrecomputedEntities,
    transcript::{Transcript, TranscriptHasher},
};

#[derive(Clone)]
pub struct VerifyingKey<P: Pairing> {
    pub crs: P::G2Affine,
    pub inner_vk: VerifyingKeyBarretenberg<P::G1>,
}

impl<P: Pairing> VerifyingKey<P> {
    pub fn from_barretenberg_and_crs(
        barretenberg_vk: VerifyingKeyBarretenberg<P::G1>,
        crs: P::G2Affine,
    ) -> Self {
        Self {
            crs,
            inner_vk: barretenberg_vk.clone(),
        }
    }

    pub fn to_barretenberg(self) -> VerifyingKeyBarretenberg<P::G1> {
        VerifyingKeyBarretenberg {
            log_circuit_size: self.inner_vk.log_circuit_size,
            num_public_inputs: self.inner_vk.num_public_inputs,
            pub_inputs_offset: self.inner_vk.pub_inputs_offset,
            commitments: self.inner_vk.commitments,
        }
    }

    pub fn hash_with_origin_tagging<H, C>(
        &self,
        domain_separator: &str,
        transcript: &mut Transcript<TranscriptFieldType, H>,
    ) -> C::ScalarField
    where
        H: TranscriptHasher<TranscriptFieldType>,
        C: HonkCurve<TranscriptFieldType, Affine = P::G1Affine>,
        P: Pairing<G1 = C>,
    {
        transcript.add_u64_to_independent_hash_buffer(
            domain_separator.to_string() + "vk_log_circuit_size",
            self.inner_vk.log_circuit_size,
        );
        transcript.add_u64_to_independent_hash_buffer(
            domain_separator.to_string() + "vk_num_public_inputs",
            self.inner_vk.num_public_inputs,
        );
        transcript.add_u64_to_independent_hash_buffer(
            domain_separator.to_string() + "vk_pub_inputs_offset",
            self.inner_vk.pub_inputs_offset,
        );

        for commitment in self.inner_vk.commitments.iter() {
            transcript.add_point_to_independent_hash_buffer::<C>(
                domain_separator.to_string() + "vk_commitment",
                *commitment,
            );
        }

        transcript.hash_independent_buffer::<C>()
    }
}

#[derive(Clone, Debug)]
pub struct VerifyingKeyBarretenberg<P: CurveGroup> {
    pub log_circuit_size: u64,
    pub num_public_inputs: u64,
    pub pub_inputs_offset: u64,
    pub commitments: PrecomputedEntities<P::Affine>,
}

impl<C: HonkCurve<TranscriptFieldType>> VerifyingKeyBarretenberg<C> {
    const NUM_64_LIMBS: u32 = TranscriptFieldType::MODULUS_BIT_SIZE.div_ceil(64);
    const FIELDSIZE_BYTES: u32 = Self::NUM_64_LIMBS * 8;
    const SER_FULL_SIZE: usize = 3 * Self::FIELDSIZE_BYTES as usize
        + PRECOMPUTED_ENTITIES_SIZE * 2 * 2 * Self::FIELDSIZE_BYTES as usize; // all elements are serialized as ScalarField elements
    const SER_FULL_SIZE_KECCAK: usize = 3 * 32 + PRECOMPUTED_ENTITIES_SIZE * 2 * 32; // all elements are serialized as U256 elements

    pub fn to_field_elements(&self) -> Vec<C::ScalarField> {
        let len = 3 + self.commitments.elements.len() * 2 * C::NUM_BASEFIELD_ELEMENTS;
        let mut field_elements = Vec::with_capacity(len);

        field_elements.push(C::ScalarField::from(self.log_circuit_size));
        field_elements.push(C::ScalarField::from(self.num_public_inputs));
        field_elements.push(C::ScalarField::from(self.pub_inputs_offset));

        for el in self.commitments.iter() {
            if el.is_zero() {
                let convert = C::convert_basefield_to_scalarfield(&C::BaseField::zero());
                field_elements.extend_from_slice(&convert);
                field_elements.extend(convert);
            } else {
                let (x, y) = C::g1_affine_to_xy(el);
                field_elements.extend(C::convert_basefield_to_scalarfield(&x));
                field_elements.extend(C::convert_basefield_to_scalarfield(&y));
            }
        }

        debug_assert_eq!(field_elements.len(), len);
        field_elements
    }

    pub fn to_buffer(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(Self::SER_FULL_SIZE);

        SerializeF::<C::ScalarField>::write_field_element(
            &mut buffer,
            C::ScalarField::from(self.log_circuit_size),
        );
        SerializeF::<C::ScalarField>::write_field_element(
            &mut buffer,
            C::ScalarField::from(self.num_public_inputs),
        );
        SerializeF::<C::ScalarField>::write_field_element(
            &mut buffer,
            C::ScalarField::from(self.pub_inputs_offset),
        );

        for el in self.commitments.iter() {
            if el.is_zero() {
                let convert = C::convert_basefield_into(&C::BaseField::zero());
                SerializeF::<TranscriptFieldType>::write_field_element(&mut buffer, convert[0]);
                SerializeF::<TranscriptFieldType>::write_field_element(&mut buffer, convert[1]);
                SerializeF::<TranscriptFieldType>::write_field_element(&mut buffer, convert[0]);
                SerializeF::<TranscriptFieldType>::write_field_element(&mut buffer, convert[1]);
            } else {
                let (x, y) = C::g1_affine_to_xy(el);
                let x_base = C::convert_basefield_into(&x);
                SerializeF::<TranscriptFieldType>::write_field_element(&mut buffer, x_base[0]);
                SerializeF::<TranscriptFieldType>::write_field_element(&mut buffer, x_base[1]);
                let y_base = C::convert_basefield_into(&y);
                SerializeF::<TranscriptFieldType>::write_field_element(&mut buffer, y_base[0]);
                SerializeF::<TranscriptFieldType>::write_field_element(&mut buffer, y_base[1]);
            }
        }

        debug_assert_eq!(buffer.len(), Self::SER_FULL_SIZE);
        buffer
    }

    pub fn to_buffer_keccak(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(Self::SER_FULL_SIZE_KECCAK);

        buffer.extend(U256::to_buffer(&[U256::from(self.log_circuit_size)]));
        buffer.extend(U256::to_buffer(&[U256::from(self.num_public_inputs)]));
        buffer.extend(U256::to_buffer(&[U256::from(self.pub_inputs_offset)]));

        for el in self.commitments.iter() {
            if el.is_zero() {
                buffer.extend(U256::to_buffer(&[U256::convert_field_into(
                    &C::BaseField::zero(),
                )]));
                buffer.extend(U256::to_buffer(&[U256::convert_field_into(
                    &C::BaseField::zero(),
                )]));
            } else {
                let (x, y) = C::g1_affine_to_xy(el);
                buffer.extend(U256::to_buffer(&[U256::convert_field_into(&x)]));
                buffer.extend(U256::to_buffer(&[U256::convert_field_into(&y)]));
            }
        }

        debug_assert_eq!(buffer.len(), Self::SER_FULL_SIZE_KECCAK);
        buffer
    }

    /// Decode final v6's field-based VK format. Every field word must be
    /// canonical, and integer metadata must fit in 64 bits.
    pub fn from_buffer(buf: &[u8]) -> HonkProofResult<Self> {
        let size = buf.len();
        let mut offset = 0;
        if size != Self::SER_FULL_SIZE {
            return Err(HonkProofError::InvalidKeyLength);
        }

        // Final BB rejects non-canonical serialized Fr words before decoding
        // either metadata or point-coordinate limbs.
        let modulus: BigUint = TranscriptFieldType::MODULUS.into();
        if buf
            .chunks_exact(32)
            .any(|word| BigUint::from_bytes_be(word) >= modulus)
        {
            return Err(HonkProofError::NonCanonicalFieldEncoding);
        }

        let log_circuit_size: BigUint = {
            let fe = SerializeF::<TranscriptFieldType>::read_field_element(buf, &mut offset);
            fe.into()
        };
        let log_circuit_size: u64 = log_circuit_size
            .try_into()
            .map_err(|_| HonkProofError::CorruptedKey)?;
        let num_public_inputs: BigUint = {
            let fe = SerializeF::<TranscriptFieldType>::read_field_element(buf, &mut offset);
            fe.into()
        };
        let num_public_inputs: u64 = num_public_inputs
            .try_into()
            .map_err(|_| HonkProofError::CorruptedKey)?;
        let pub_inputs_offset: BigUint = {
            let fe = SerializeF::<TranscriptFieldType>::read_field_element(buf, &mut offset);
            fe.into()
        };
        let pub_inputs_offset: u64 = pub_inputs_offset
            .try_into()
            .map_err(|_| HonkProofError::CorruptedKey)?;

        let mut commitments = PrecomputedEntities::default();

        for el in commitments.iter_mut() {
            let x0 = SerializeF::<TranscriptFieldType>::read_field_element(buf, &mut offset);
            let x1 = SerializeF::<TranscriptFieldType>::read_field_element(buf, &mut offset);
            let y0 = SerializeF::<TranscriptFieldType>::read_field_element(buf, &mut offset);
            let y1 = SerializeF::<TranscriptFieldType>::read_field_element(buf, &mut offset);
            // Untrusted input: reject non-canonical base-field limb encodings
            // before recombining (release builds skip convert_basefield_back's
            // debug_assert!s; bb rejects these in every build).
            C::validate_basefield_limbs(&[x0, x1])?;
            C::validate_basefield_limbs(&[y0, y1])?;
            let x = C::convert_basefield_back(&[x0, x1]);
            let y = C::convert_basefield_back(&[y0, y1]);
            // Untrusted input: reject off-curve VK commitments cleanly.
            *el = C::g1_affine_from_xy_checked(x, y)?;
        }

        debug_assert!(offset == Self::SER_FULL_SIZE);

        Ok(Self {
            log_circuit_size,
            num_public_inputs,
            pub_inputs_offset,
            commitments,
        })
    }

    /// Decode final v6's U256 VK format. Integer metadata must fit in 64 bits;
    /// point coordinates must be canonical base-field integers, including the
    /// all-zero encoding of infinity.
    pub fn from_buffer_keccak(buf: &[u8]) -> HonkProofResult<Self> {
        let size = buf.len();
        let mut offset = 0;
        if size != Self::SER_FULL_SIZE_KECCAK {
            return Err(HonkProofError::InvalidKeyLength);
        }

        let read_metadata = |word: &[u8]| -> HonkProofResult<u64> {
            BigUint::from_bytes_be(word)
                .try_into()
                .map_err(|_| HonkProofError::CorruptedKey)
        };
        let log_circuit_size = read_metadata(&buf[offset..offset + 32])?;
        offset += 32;
        let num_public_inputs = read_metadata(&buf[offset..offset + 32])?;
        offset += 32;
        let pub_inputs_offset = read_metadata(&buf[offset..offset + 32])?;
        offset += 32;

        let mut commitments = PrecomputedEntities::default();

        let basefield_modulus: BigUint = C::BaseField::MODULUS.into();
        let read_coordinate = |bytes: &[u8]| -> HonkProofResult<C::BaseField> {
            // v6 U256Codec checks raw fq integers before point reconstruction.
            // Modular reduction would otherwise accept x + q (or q as zero),
            // producing the same key and VK hash from bytes BB rejects.
            if BigUint::from_bytes_be(bytes) >= basefield_modulus {
                return Err(HonkProofError::NonCanonicalFieldEncoding);
            }
            Ok(C::BaseField::from_be_bytes_mod_order(bytes))
        };
        for el in commitments.iter_mut() {
            let x = read_coordinate(&buf[offset..offset + 32])?;
            offset += 32;
            let y = read_coordinate(&buf[offset..offset + 32])?;
            offset += 32;
            // Untrusted input: reject off-curve VK commitments cleanly.
            *el = C::g1_affine_from_xy_checked(x, y)?;
        }

        debug_assert!(offset == Self::SER_FULL_SIZE_KECCAK);

        Ok(Self {
            log_circuit_size,
            num_public_inputs,
            pub_inputs_offset,
            commitments,
        })
    }

    pub fn hash_with_origin_tagging<H>(
        &self,
        domain_separator: &str,
        transcript: &mut Transcript<TranscriptFieldType, H>,
    ) -> C::ScalarField
    where
        H: TranscriptHasher<TranscriptFieldType>,
    {
        transcript.add_u64_to_independent_hash_buffer(
            domain_separator.to_string() + "vk_log_circuit_size",
            self.log_circuit_size,
        );
        transcript.add_u64_to_independent_hash_buffer(
            domain_separator.to_string() + "vk_num_public_inputs",
            self.num_public_inputs,
        );
        transcript.add_u64_to_independent_hash_buffer(
            domain_separator.to_string() + "vk_pub_inputs_offset",
            self.pub_inputs_offset,
        );

        for commitment in self.commitments.iter() {
            transcript.add_point_to_independent_hash_buffer::<C>(
                domain_separator.to_string() + "vk_commitment",
                *commitment,
            );
        }

        transcript.hash_independent_buffer::<C>()
    }
}

#[cfg(test)]
mod encoding_tests {
    use super::*;
    use ark_bn254::G1Projective;

    #[test]
    fn infinity_commitments_round_trip() {
        let vk = VerifyingKeyBarretenberg::<G1Projective> {
            log_circuit_size: 4,
            num_public_inputs: 8,
            pub_inputs_offset: 1,
            commitments: PrecomputedEntities::default(),
        };
        let bytes = vk.to_buffer();
        let parsed = VerifyingKeyBarretenberg::<G1Projective>::from_buffer(&bytes)
            .expect("serialized infinity commitments must parse");
        assert_eq!(parsed.to_buffer(), bytes);
    }

    #[test]
    fn infinity_commitments_round_trip_keccak() {
        let vk = VerifyingKeyBarretenberg::<G1Projective> {
            log_circuit_size: 4,
            num_public_inputs: 8,
            pub_inputs_offset: 1,
            commitments: PrecomputedEntities::default(),
        };
        let bytes = vk.to_buffer_keccak();
        let parsed = VerifyingKeyBarretenberg::<G1Projective>::from_buffer_keccak(&bytes)
            .expect("serialized infinity commitments must parse");
        assert_eq!(parsed.to_buffer_keccak(), bytes);
    }

    #[test]
    fn vk_metadata_rejects_high_integer_bits() {
        let vk = VerifyingKeyBarretenberg::<G1Projective> {
            log_circuit_size: 4,
            num_public_inputs: 8,
            pub_inputs_offset: 1,
            commitments: PrecomputedEntities::default(),
        };
        for keccak in [false, true] {
            let canonical = if keccak {
                vk.to_buffer_keccak()
            } else {
                vk.to_buffer()
            };
            for header in 0..3 {
                let mut alias = canonical.clone();
                let word = &mut alias[header * 32..(header + 1) * 32];
                let value = BigUint::from_bytes_be(word) + (BigUint::from(1u8) << 64usize);
                let bytes = value.to_bytes_be();
                word.fill(0);
                word[32 - bytes.len()..].copy_from_slice(&bytes);
                let parsed = if keccak {
                    VerifyingKeyBarretenberg::<G1Projective>::from_buffer_keccak(&alias)
                } else {
                    VerifyingKeyBarretenberg::<G1Projective>::from_buffer(&alias)
                };
                assert!(
                    parsed.is_err(),
                    "accepted high integer bits in header {header}, keccak={keccak}"
                );
            }
        }
    }

    #[test]
    fn poseidon_vk_rejects_outer_field_modulus_aliases() {
        let mut vk = VerifyingKeyBarretenberg::<G1Projective> {
            log_circuit_size: 4,
            num_public_inputs: 8,
            pub_inputs_offset: 1,
            commitments: PrecomputedEntities::default(),
        };
        vk.commitments.elements[0] = ark_bn254::G1Affine::generator();
        let canonical = vk.to_buffer();
        let modulus: BigUint = ark_bn254::Fr::MODULUS.into();
        for word in 0..canonical.len() / 32 {
            let mut alias = canonical.clone();
            let output = &mut alias[word * 32..(word + 1) * 32];
            let value = BigUint::from_bytes_be(output) + &modulus;
            let bytes = value.to_bytes_be();
            output.fill(0);
            output[32 - bytes.len()..].copy_from_slice(&bytes);
            assert!(
                matches!(
                    VerifyingKeyBarretenberg::<G1Projective>::from_buffer(&alias),
                    Err(HonkProofError::NonCanonicalFieldEncoding)
                ),
                "accepted outer field modulus alias at word {word}"
            );
        }
    }

    #[test]
    fn exact_v6_vk_fixtures_round_trip() {
        let fixtures =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test_vectors/noir");
        for (path, keccak) in [
            ("poseidon/kat/pos_vk_with_pos", false),
            ("poseidon/kat/pos_vk_with_kec", true),
            ("add3u64/kat/add3u64_vk_with_pos", false),
            ("add3u64/kat/add3u64_vk_with_kec", true),
            ("rom_shared/kat/rom_shared_vk_with_pos", false),
            ("rom_shared/kat/rom_shared_vk_with_kec", true),
            ("recursion/kat/recursion_vk_with_pos", false),
            ("recursion_zk/kat/recursion_zk_vk_with_pos", false),
        ] {
            let bytes = std::fs::read(fixtures.join(path)).unwrap();
            let parsed = if keccak {
                VerifyingKeyBarretenberg::<G1Projective>::from_buffer_keccak(&bytes)
            } else {
                VerifyingKeyBarretenberg::<G1Projective>::from_buffer(&bytes)
            }
            .unwrap_or_else(|error| panic!("{path}: {error}"));
            let normalized = if keccak {
                parsed.to_buffer_keccak()
            } else {
                parsed.to_buffer()
            };
            assert_eq!(normalized, bytes, "{path}");
        }
    }
}

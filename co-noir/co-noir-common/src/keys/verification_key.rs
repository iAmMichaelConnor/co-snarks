use crate::constants::CONST_PROOF_SIZE_LOG_N;
use crate::polynomials::entities::PRECOMPUTED_ENTITIES_SIZE;
use ark_ec::AffineRepr;
use ark_ec::{CurveGroup, pairing::Pairing};
use ark_ff::Zero;
use ark_ff::{BigInteger, PrimeField};
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

    /// Checks that the metadata describes a circuit the verifier can handle:
    /// `1 <= log_circuit_size <= CONST_PROOF_SIZE_LOG_N`, and the public inputs
    /// `[pub_inputs_offset, pub_inputs_offset + num_public_inputs)` lie within the
    /// `2^log_circuit_size` rows of the circuit.
    pub fn validate_metadata(&self) -> HonkProofResult<()> {
        if self.log_circuit_size == 0 || self.log_circuit_size > CONST_PROOF_SIZE_LOG_N as u64 {
            return Err(HonkProofError::CorruptedKey);
        }
        let circuit_size = 1u64 << self.log_circuit_size;
        if self.pub_inputs_offset > circuit_size
            || self.num_public_inputs > circuit_size - self.pub_inputs_offset
        {
            return Err(HonkProofError::CorruptedKey);
        }
        Ok(())
    }

    /// Decodes a commitment from its two (two-limb) coordinates, like barretenberg's `FrCodec`:
    /// the limbs must be canonical and the point must be on the curve ((0, 0) is the point at
    /// infinity).
    fn commitment_from_limbs(limbs: &[TranscriptFieldType]) -> HonkProofResult<C::Affine> {
        let (x, y) = limbs.split_at(limbs.len() / 2);
        C::validate_basefield(x)?;
        C::validate_basefield(y)?;
        C::g1_affine_from_xy(C::convert_basefield_back(x), C::convert_basefield_back(y))
    }

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

    pub fn from_buffer(buf: &[u8]) -> HonkProofResult<Self> {
        let size = buf.len();
        let mut offset = 0;
        if size != Self::SER_FULL_SIZE {
            return Err(HonkProofError::InvalidKeyLength);
        }

        // Every word must be a canonical field element (barretenberg rejects the others).
        SerializeF::<TranscriptFieldType>::from_buffer(buf, false)
            .map_err(|_| HonkProofError::NonCanonicalFieldEncoding)?;

        // Read data
        let mut read_u64 = || {
            let fe: BigUint =
                SerializeF::<TranscriptFieldType>::read_field_element(buf, &mut offset).into();
            u64::try_from(fe).map_err(|_| HonkProofError::CorruptedKey)
        };
        let log_circuit_size = read_u64()?;
        let num_public_inputs = read_u64()?;
        let pub_inputs_offset = read_u64()?;

        let mut commitments = PrecomputedEntities::default();

        for el in commitments.iter_mut() {
            let x0 = SerializeF::<TranscriptFieldType>::read_field_element(buf, &mut offset);
            let x1 = SerializeF::<TranscriptFieldType>::read_field_element(buf, &mut offset);
            let y0 = SerializeF::<TranscriptFieldType>::read_field_element(buf, &mut offset);
            let y1 = SerializeF::<TranscriptFieldType>::read_field_element(buf, &mut offset);
            *el = Self::commitment_from_limbs(&[x0, x1, y0, y1])?;
        }

        debug_assert!(offset == Self::SER_FULL_SIZE);

        let vk = Self {
            log_circuit_size,
            num_public_inputs,
            pub_inputs_offset,
            commitments,
        };
        vk.validate_metadata()?;
        Ok(vk)
    }

    pub fn from_buffer_keccak(buf: &[u8]) -> HonkProofResult<Self> {
        let size = buf.len();
        let mut offset = 0;
        if size != Self::SER_FULL_SIZE_KECCAK {
            return Err(HonkProofError::InvalidKeyLength);
        }

        let words = U256::from_buffer(buf);
        let read_u64 =
            |word: &U256| u64::try_from(word.0).map_err(|_| HonkProofError::CorruptedKey);
        let log_circuit_size = read_u64(&words[0])?;
        let num_public_inputs = read_u64(&words[1])?;
        let pub_inputs_offset = read_u64(&words[2])?;
        offset += 3 * 32;

        // Coordinates must be canonical base-field elements (barretenberg's `U256Codec`).
        let modulus = C::BaseField::MODULUS.to_bytes_be();
        let mut read_coordinate = || {
            let bytes = &buf[offset..offset + 32];
            offset += 32;
            if bytes >= modulus.as_slice() {
                return Err(HonkProofError::NonCanonicalFieldEncoding);
            }
            Ok(C::BaseField::from_be_bytes_mod_order(bytes))
        };

        let mut commitments = PrecomputedEntities::default();

        for el in commitments.iter_mut() {
            let x = read_coordinate()?;
            let y = read_coordinate()?;
            *el = C::g1_affine_from_xy(x, y)?;
        }

        debug_assert!(offset == Self::SER_FULL_SIZE_KECCAK);

        let vk = Self {
            log_circuit_size,
            num_public_inputs,
            pub_inputs_offset,
            commitments,
        };
        vk.validate_metadata()?;
        Ok(vk)
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
mod tests {
    use super::*;
    use ark_bn254::{Fq, Fr, G1Affine, G1Projective};
    use ark_ff::Field;

    type Vk = VerifyingKeyBarretenberg<G1Projective>;

    fn sample_vk() -> Vk {
        let mut commitments = PrecomputedEntities::default();
        for (i, c) in commitments.iter_mut().enumerate() {
            *c = (G1Affine::generator() * Fr::from(i as u64 + 1)).into();
        }
        VerifyingKeyBarretenberg {
            log_circuit_size: 4,
            num_public_inputs: 8,
            pub_inputs_offset: 1,
            commitments,
        }
    }

    fn word(buf: &[u8], index: usize) -> BigUint {
        BigUint::from_bytes_be(&buf[index * 32..(index + 1) * 32])
    }

    fn set_word(buf: &mut [u8], index: usize, value: &BigUint) {
        let raw = value.to_bytes_be();
        let word = &mut buf[index * 32..(index + 1) * 32];
        word.fill(0);
        word[32 - raw.len()..].copy_from_slice(&raw);
    }

    fn decode(buf: &[u8], keccak: bool) -> HonkProofResult<Vk> {
        if keccak {
            Vk::from_buffer_keccak(buf)
        } else {
            Vk::from_buffer(buf)
        }
    }

    fn encode(vk: &Vk, keccak: bool) -> Vec<u8> {
        if keccak {
            vk.to_buffer_keccak()
        } else {
            vk.to_buffer()
        }
    }

    #[test]
    fn round_trip_including_points_at_infinity() {
        let mut vk = sample_vk();
        vk.commitments.elements[0] = G1Affine::zero();
        for keccak in [false, true] {
            let buf = encode(&vk, keccak);
            assert_eq!(encode(&decode(&buf, keccak).unwrap(), keccak), buf);
        }
    }

    #[test]
    fn header_words_must_fit_in_64_bits() {
        for keccak in [false, true] {
            let buf = encode(&sample_vk(), keccak);
            for header in 0..3 {
                let mut tampered = buf.clone();
                set_word(
                    &mut tampered,
                    header,
                    &(word(&buf, header) + (BigUint::from(1u8) << 64)),
                );
                assert!(matches!(
                    decode(&tampered, keccak),
                    Err(HonkProofError::CorruptedKey)
                ));
            }
        }
    }

    #[test]
    fn metadata_is_bounded() {
        for (log_circuit_size, num_public_inputs, pub_inputs_offset, valid) in [
            (4, 0, 0, true),
            (4, 16, 0, true),
            (4, 15, 1, true),
            (4, 0, 16, true),
            (25, 8, 1, true),
            (0, 0, 0, false),
            (26, 8, 1, false),
            (u64::MAX, 8, 1, false),
            (4, 17, 0, false),
            (4, 16, 1, false),
            (4, 0, 17, false),
            (4, u64::MAX, 1, false),
            (4, 1, u64::MAX, false),
        ] {
            let mut vk = sample_vk();
            vk.log_circuit_size = log_circuit_size;
            vk.num_public_inputs = num_public_inputs;
            vk.pub_inputs_offset = pub_inputs_offset;
            assert_eq!(vk.validate_metadata().is_ok(), valid, "{log_circuit_size}");
            for keccak in [false, true] {
                assert_eq!(
                    decode(&encode(&vk, keccak), keccak).is_ok(),
                    valid,
                    "{log_circuit_size} {num_public_inputs} {pub_inputs_offset} {keccak}"
                );
            }
        }
    }

    #[test]
    fn field_words_above_the_modulus_are_rejected() {
        let buf = sample_vk().to_buffer();
        let modulus: BigUint = Fr::MODULUS.into();
        for index in 0..buf.len() / 32 {
            let mut tampered = buf.clone();
            set_word(&mut tampered, index, &(word(&buf, index) + &modulus));
            assert!(
                matches!(
                    Vk::from_buffer(&tampered),
                    Err(HonkProofError::NonCanonicalFieldEncoding)
                ),
                "word {index}"
            );
        }
    }

    #[test]
    fn coordinate_limbs_must_be_canonical() {
        let buf = sample_vk().to_buffer();
        // The x-coordinate of the second commitment (2 * G): low limb at word 7, high limb at word 8.
        let (lo, hi) = (word(&buf, 7), word(&buf, 8));
        assert!(hi > BigUint::zero());
        let q: BigUint = Fq::MODULUS.into();
        let low_mask = (BigUint::from(1u8) << 136) - 1u8;
        let aliased = &lo + (&hi << 136) + &q;
        for (new_lo, new_hi) in [
            // Same value, low limb above 2^136.
            (&lo + (BigUint::from(1u8) << 136), &hi - 1u8),
            // Value plus q.
            (&aliased & &low_mask, &aliased >> 136),
        ] {
            let mut tampered = buf.clone();
            set_word(&mut tampered, 7, &new_lo);
            set_word(&mut tampered, 8, &new_hi);
            assert!(matches!(
                Vk::from_buffer(&tampered),
                Err(HonkProofError::NonCanonicalFieldEncoding)
            ));
        }
    }

    #[test]
    fn keccak_coordinates_must_be_canonical() {
        // x = q - 1 lies on the curve (x^3 + 3 = 2), so x + q still fits in 256 bits.
        let boundary = G1Affine::new_unchecked(-Fq::ONE, Fq::from(2u64).sqrt().unwrap());
        assert!(boundary.is_on_curve());
        let q: BigUint = Fq::MODULUS.into();
        for point in [G1Affine::zero(), G1Affine::generator(), boundary] {
            let mut vk = sample_vk();
            vk.commitments.elements[0] = point;
            let buf = vk.to_buffer_keccak();
            assert_eq!(
                Vk::from_buffer_keccak(&buf).unwrap().to_buffer_keccak(),
                buf
            );
            for index in [3, 4] {
                let mut tampered = buf.clone();
                set_word(&mut tampered, index, &(word(&buf, index) + &q));
                assert!(matches!(
                    Vk::from_buffer_keccak(&tampered),
                    Err(HonkProofError::NonCanonicalFieldEncoding)
                ));
            }
        }
    }

    #[test]
    fn off_curve_commitments_are_errors() {
        for keccak in [false, true] {
            let mut buf = encode(&sample_vk(), keccak);
            // Low limb (or word) of the first commitment's y-coordinate.
            let index = if keccak { 4 } else { 5 };
            let value = word(&buf, index) + 1u8;
            set_word(&mut buf, index, &value);
            assert!(matches!(
                decode(&buf, keccak),
                Err(HonkProofError::PointNotOnCurve)
            ));
        }
    }
}

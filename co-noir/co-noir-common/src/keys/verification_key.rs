use crate::constants::CONST_PROOF_SIZE_LOG_N;
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

    /// Validate an untrusted VK's `log_circuit_size`. It must be at least 1 (no circuit has zero
    /// rows) and at most `CONST_PROOF_SIZE_LOG_N` (the max the constant-size proof format supports).
    /// A zero would drive the verifier's sumcheck round count to 0 and underflow the Gemini
    /// fold-commitment loop; an over-large value would mis-size the transcript reads. Mirrors bb
    /// `1391c49546`, which added the equivalent reject in the UltraKeccak verifier.
    fn check_log_circuit_size(log_circuit_size: u64) -> HonkProofResult<()> {
        if log_circuit_size == 0 || log_circuit_size > CONST_PROOF_SIZE_LOG_N as u64 {
            return Err(HonkProofError::CorruptedKey);
        }
        Ok(())
    }

    /// Validate an untrusted VK's `num_public_inputs` and `pub_inputs_offset`
    /// against the circuit size implied by the (already-validated)
    /// `log_circuit_size`. The entire public-input interval must fit within
    /// the circuit's `2^log_circuit_size` physical rows.
    /// Left unchecked, a huge `num_public_inputs` drives the oink verifier's
    /// `Vec::with_capacity(num_public_inputs)` preamble allocation past the
    /// allocator's capacity-overflow abort, and a huge `pub_inputs_offset`
    /// overflows the `1 + pub_inputs_offset` addition in
    /// `compute_public_input_delta` (debug-panics, wraps in release). Call only
    /// after `check_log_circuit_size` has bounded `log_circuit_size` to
    /// `[1, CONST_PROOF_SIZE_LOG_N]`, so the shift below cannot overflow.
    fn check_public_input_bounds(
        log_circuit_size: u64,
        num_public_inputs: u64,
        pub_inputs_offset: u64,
    ) -> HonkProofResult<()> {
        let circuit_size = 1u64 << log_circuit_size;
        // Public inputs occupy [offset, offset + count) in the physical trace.
        // The disabled rows are already included in both the trace offset and
        // dyadic size (BB ProverInstance_::compute_dyadic_size). Subtract after
        // checking the offset, so malformed metadata cannot overflow addition.
        if pub_inputs_offset > circuit_size || num_public_inputs > circuit_size - pub_inputs_offset
        {
            return Err(HonkProofError::CorruptedKey);
        }
        Ok(())
    }

    /// Validate circuit and public-input bounds, including for keys constructed
    /// directly through the public fields rather than a byte decoder.
    pub fn validate_metadata(&self) -> HonkProofResult<()> {
        Self::check_log_circuit_size(self.log_circuit_size)?;
        Self::check_public_input_bounds(
            self.log_circuit_size,
            self.num_public_inputs,
            self.pub_inputs_offset,
        )
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

        // Untrusted input: a VK with log_circuit_size = 0 (or out of range) is invalid for any
        // circuit and, if accepted, drives the verifier's round count to 0 — reject it cleanly
        // rather than letting a zero round count underflow downstream (mirrors bb `1391c49546`).
        Self::check_log_circuit_size(log_circuit_size)?;
        // Untrusted input: bound num_public_inputs / pub_inputs_offset against the
        // circuit size before they can reach the oink verifier's preamble
        // allocation or its public-input-delta offset arithmetic.
        Self::check_public_input_bounds(log_circuit_size, num_public_inputs, pub_inputs_offset)?;

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

        // Untrusted input: reject log_circuit_size = 0 / out of range (mirrors bb `1391c49546`).
        // The Keccak path did not panic like the field path, but silently accepting a zero round
        // count is the same soundness/robustness gap.
        Self::check_log_circuit_size(log_circuit_size)?;
        // Untrusted input: bound num_public_inputs / pub_inputs_offset against the
        // circuit size before they can reach the oink verifier's preamble
        // allocation or its public-input-delta offset arithmetic.
        Self::check_public_input_bounds(log_circuit_size, num_public_inputs, pub_inputs_offset)?;

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
    use ark_ff::Field;

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
    fn sample_vk() -> VerifyingKeyBarretenberg<G1Projective> {
        VerifyingKeyBarretenberg {
            log_circuit_size: 4,
            num_public_inputs: 8,
            pub_inputs_offset: 1,
            commitments: PrecomputedEntities::default(),
        }
    }

    fn write_word(bytes: &mut [u8], word: usize, value: &BigUint) {
        let encoded = value.to_bytes_be();
        assert!(encoded.len() <= 32);
        bytes[word * 32..(word + 1) * 32].fill(0);
        bytes[(word + 1) * 32 - encoded.len()..(word + 1) * 32].copy_from_slice(&encoded);
    }

    #[test]
    fn keccak_vk_rejects_noncanonical_coordinate_aliases() {
        let modulus: BigUint = ark_bn254::Fq::MODULUS.into();
        // x = q - 1 is a valid boundary coordinate: x^3 + 3 = 2.
        let boundary = ark_bn254::G1Affine::new_unchecked(
            -ark_bn254::Fq::from(1u64),
            ark_bn254::Fq::from(2u64).sqrt().unwrap(),
        );
        assert!(boundary.is_on_curve());
        for point in [
            ark_bn254::G1Affine::zero(),
            ark_bn254::G1Affine::generator(),
            boundary,
        ] {
            let mut vk = sample_vk();
            vk.commitments.elements[0] = point;
            let canonical = vk.to_buffer_keccak();
            assert_eq!(
                VerifyingKeyBarretenberg::<G1Projective>::from_buffer_keccak(&canonical)
                    .unwrap()
                    .to_buffer_keccak(),
                canonical,
            );
            for coordinate in 0..2 {
                let mut alias = canonical.clone();
                let word = 3 + coordinate;
                let value = BigUint::from_bytes_be(&alias[word * 32..(word + 1) * 32]);
                write_word(&mut alias, word, &(value + &modulus));
                assert!(
                    matches!(
                        VerifyingKeyBarretenberg::<G1Projective>::from_buffer_keccak(&alias),
                        Err(HonkProofError::NonCanonicalFieldEncoding)
                    ),
                    "accepted coordinate {coordinate} + fq for point {point:?}",
                );
            }
        }
    }

    #[test]
    fn vk_public_input_interval_fits_circuit_rows() {
        // Metadata addresses a contiguous physical block in the trace. The
        // disabled rows are already included in its offset and dyadic size.
        for (count, offset, valid) in [
            (0, 0, true),
            (0, 16, true),
            (16, 0, true),
            (15, 1, true),
            (1, 15, true),
            (1, 16, false),
            (16, 1, false),
            (9, 8, false),
            (17, 0, false),
            (0, 17, false),
            (u64::MAX, 0, false),
            (0, u64::MAX, false),
        ] {
            let mut vk = sample_vk();
            vk.num_public_inputs = count;
            vk.pub_inputs_offset = offset;
            assert_eq!(
                vk.validate_metadata().is_ok(),
                valid,
                "direct: {count}, {offset}"
            );
            assert_eq!(
                VerifyingKeyBarretenberg::<G1Projective>::from_buffer(&vk.to_buffer()).is_ok(),
                valid,
                "Poseidon: {count}, {offset}",
            );
            assert_eq!(
                VerifyingKeyBarretenberg::<G1Projective>::from_buffer_keccak(
                    &vk.to_buffer_keccak()
                )
                .is_ok(),
                valid,
                "Keccak: {count}, {offset}",
            );
        }
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
            parsed.validate_metadata().unwrap();
            let normalized = if keccak {
                parsed.to_buffer_keccak()
            } else {
                parsed.to_buffer()
            };
            assert_eq!(normalized, bytes, "{path}");
        }
    }
}

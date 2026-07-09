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

        // Read data. Note `BigUint::to_u64_digits()` returns an EMPTY vec for zero,
        // so index `[0]` would panic on a genuinely-zero (or malformed all-zero) VK
        // header; take the low limb with a 0 default instead.
        let log_circuit_size: BigUint = {
            let fe = SerializeF::<TranscriptFieldType>::read_field_element(buf, &mut offset);
            fe.into()
        };
        let log_circuit_size: u64 = log_circuit_size.to_u64_digits().first().copied().unwrap_or(0);
        let num_public_inputs: BigUint = {
            let fe = SerializeF::<TranscriptFieldType>::read_field_element(buf, &mut offset);
            fe.into()
        };
        let num_public_inputs: u64 =
            num_public_inputs.to_u64_digits().first().copied().unwrap_or(0);
        let pub_inputs_offset: BigUint = {
            let fe = SerializeF::<TranscriptFieldType>::read_field_element(buf, &mut offset);
            fe.into()
        };
        let pub_inputs_offset: u64 =
            pub_inputs_offset.to_u64_digits().first().copied().unwrap_or(0);

        // Untrusted input: a VK with log_circuit_size = 0 (or out of range) is invalid for any
        // circuit and, if accepted, drives the verifier's round count to 0 — reject it cleanly
        // rather than letting a zero round count underflow downstream (mirrors bb `1391c49546`).
        Self::check_log_circuit_size(log_circuit_size)?;

        let mut commitments = PrecomputedEntities::default();

        for el in commitments.iter_mut() {
            let x0 = SerializeF::<TranscriptFieldType>::read_field_element(buf, &mut offset);
            let x1 = SerializeF::<TranscriptFieldType>::read_field_element(buf, &mut offset);
            let y0 = SerializeF::<TranscriptFieldType>::read_field_element(buf, &mut offset);
            let y1 = SerializeF::<TranscriptFieldType>::read_field_element(buf, &mut offset);
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

    pub fn from_buffer_keccak(buf: &[u8]) -> HonkProofResult<Self> {
        let size = buf.len();
        let mut offset = 0;
        if size != Self::SER_FULL_SIZE_KECCAK {
            return Err(HonkProofError::InvalidKeyLength);
        }

        let log_circuit_size: u64 = U256::from_buffer(&buf[offset..offset + 32])[0].0.as_limbs()[0];
        offset += 32;
        let num_public_inputs: u64 =
            U256::from_buffer(&buf[offset..offset + 32])[0].0.as_limbs()[0];
        offset += 32;
        let pub_inputs_offset: u64 =
            U256::from_buffer(&buf[offset..offset + 32])[0].0.as_limbs()[0];
        offset += 32;

        // Untrusted input: reject log_circuit_size = 0 / out of range (mirrors bb `1391c49546`).
        // The Keccak path did not panic like the field path, but silently accepting a zero round
        // count is the same soundness/robustness gap.
        Self::check_log_circuit_size(log_circuit_size)?;

        let mut commitments = PrecomputedEntities::default();

        for el in commitments.iter_mut() {
            let x = C::BaseField::from_be_bytes_mod_order(&buf[offset..offset + 32]);
            offset += 32;
            let y = C::BaseField::from_be_bytes_mod_order(&buf[offset..offset + 32]);
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

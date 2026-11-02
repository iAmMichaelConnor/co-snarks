use crate::{
    honk_curve::HonkCurve,
    honk_proof::{HonkProofError, HonkProofResult, TranscriptFieldType},
    sponge_hasher::{FieldHash, FieldSponge},
};
use ark_ec::AffineRepr;
use ark_ff::{PrimeField, Zero};
use mpc_core::gadgets::poseidon2::Poseidon2;
use noir_types::{HonkProof, SerializeF};
use std::{collections::BTreeMap, ops::Index};

pub type Poseidon2Sponge =
    FieldSponge<TranscriptFieldType, 4, 3, Poseidon2<TranscriptFieldType, 4, 5>>;

pub trait TranscriptHasher<F: PrimeField> {
    type DataType: Default
        + Copy
        + Clone
        + From<u64>
        + From<u32>
        + std::cmp::PartialEq
        + std::marker::Send
        + std::fmt::Debug
        + 'static;
    const USE_PADDING: bool = false;
    const NUM_BASEFIELD_ELEMENTS: usize;
    const NUM_SCALARFIELD_ELEMENTS: usize = 1;
    fn hash(buffer: Vec<Self::DataType>) -> Self::DataType;
    fn convert_scalarfield_into<P: HonkCurve<F>>(element: &P::ScalarField) -> Vec<Self::DataType>;
    fn convert_point<P: HonkCurve<F>>(element: &P::Affine) -> Vec<Self::DataType>;
    fn convert_scalarfield_back<P: HonkCurve<F>>(elements: &[Self::DataType]) -> P::ScalarField;
    fn convert_basefield_back<P: HonkCurve<F>>(elements: &[Self::DataType]) -> P::BaseField;
    /// Checks that `elements` canonically encode a scalar-field element. The verifier calls this
    /// on untrusted proof data before [`Self::convert_scalarfield_back`].
    fn validate_scalarfield<P: HonkCurve<F>>(elements: &[Self::DataType]) -> HonkProofResult<()>;
    /// Checks that `elements` canonically encode a base-field element. The verifier calls this
    /// on untrusted proof data before [`Self::convert_basefield_back`].
    fn validate_basefield<P: HonkCurve<F>>(elements: &[Self::DataType]) -> HonkProofResult<()>;
    fn convert_challenge_into<P: HonkCurve<F>>(challenge: &F) -> Self::DataType;
    fn convert_destinationfield_to_scalarfield<P: HonkCurve<F>>(
        element: &Self::DataType,
    ) -> P::ScalarField;
    fn to_buffer(buffer: &[Self::DataType]) -> Vec<u8>;
    fn from_buffer(buffer: &[u8]) -> Vec<Self::DataType>;
}

impl<F: PrimeField, const T: usize, const R: usize, H: FieldHash<F, T> + Default>
    TranscriptHasher<F> for FieldSponge<F, T, R, H>
{
    type DataType = F;
    const USE_PADDING: bool = true;
    const NUM_BASEFIELD_ELEMENTS: usize = 2;
    fn hash(buffer: Vec<Self::DataType>) -> F {
        Self::hash_fixed_length::<1>(&buffer)[0]
    }

    fn convert_scalarfield_into<P: HonkCurve<F>>(element: &P::ScalarField) -> Vec<Self::DataType> {
        P::convert_scalarfield_into(element)
    }

    fn convert_point<P: HonkCurve<F>>(element: &P::Affine) -> Vec<Self::DataType> {
        let (x, y) = if element.is_zero() {
            // we are at infinity
            (P::BaseField::zero(), P::BaseField::zero())
        } else {
            P::g1_affine_to_xy(element)
        };

        let mut res = P::convert_basefield_into(&x);
        res.extend(P::convert_basefield_into(&y));

        res
    }

    fn convert_scalarfield_back<P: HonkCurve<F>>(elements: &[Self::DataType]) -> P::ScalarField {
        P::convert_scalarfield_back(elements)
    }

    fn convert_basefield_back<P: HonkCurve<F>>(elements: &[Self::DataType]) -> P::BaseField {
        P::convert_basefield_back(elements)
    }

    fn validate_scalarfield<P: HonkCurve<F>>(elements: &[Self::DataType]) -> HonkProofResult<()> {
        P::validate_scalarfield(elements)
    }

    fn validate_basefield<P: HonkCurve<F>>(elements: &[Self::DataType]) -> HonkProofResult<()> {
        P::validate_basefield(elements)
    }

    fn convert_challenge_into<P: HonkCurve<F>>(challenge: &F) -> Self::DataType {
        *challenge
    }

    fn convert_destinationfield_to_scalarfield<P: HonkCurve<F>>(
        element: &Self::DataType,
    ) -> P::ScalarField {
        P::convert_destinationfield_to_scalarfield(element)
    }

    fn to_buffer(buffer: &[Self::DataType]) -> Vec<u8> {
        SerializeF::to_buffer(buffer, false)
    }

    fn from_buffer(buffer: &[u8]) -> Vec<Self::DataType> {
        SerializeF::from_buffer(buffer, false).unwrap()
    }
}

pub struct Transcript<F, H>
where
    F: PrimeField,
    H: TranscriptHasher<F>,
{
    proof_data: Vec<H::DataType>,
    manifest: TranscriptManifest,
    num_frs_written: usize, // the number of bb::frs written to proof_data by the prover or the verifier
    num_frs_read: usize,    // the number of bb::frs read from proof_data by the verifier
    round_number: usize,
    is_first_challenge: bool,
    current_round_data: Vec<H::DataType>,
    independent_hash_buffer: Vec<H::DataType>,
    previous_challenge: H::DataType,
}

impl<F, H> Default for Transcript<F, H>
where
    F: PrimeField,
    H: TranscriptHasher<F>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<F, H> Transcript<F, H>
where
    F: PrimeField,
    H: TranscriptHasher<F>,
{
    pub fn new() -> Self {
        Self {
            proof_data: Default::default(),
            manifest: Default::default(),
            num_frs_written: 0,
            num_frs_read: 0,
            round_number: 0,
            is_first_challenge: true,
            current_round_data: Default::default(),
            independent_hash_buffer: Default::default(),
            previous_challenge: Default::default(),
        }
    }

    pub fn new_verifier(proof: HonkProof<H::DataType>) -> Self {
        Self {
            proof_data: proof.inner(),
            manifest: Default::default(),
            num_frs_written: 0,
            num_frs_read: 0,
            round_number: 0,
            is_first_challenge: true,
            current_round_data: Default::default(),
            independent_hash_buffer: Default::default(),
            previous_challenge: Default::default(),
        }
    }

    pub fn get_proof(self) -> HonkProof<H::DataType> {
        HonkProof::new(self.proof_data)
    }

    /// Checks that the verifier has read the whole proof, so that a proof with trailing data is
    /// rejected (as barretenberg's `enforce_proof_fully_consumed` does).
    pub fn check_fully_consumed(&self) -> HonkProofResult<()> {
        if self.num_frs_read != self.proof_data.len() {
            return Err(HonkProofError::InvalidProofLength);
        }
        Ok(())
    }

    #[expect(dead_code)]
    pub(crate) fn print(&self) {
        self.manifest.print();
    }

    #[expect(dead_code)]
    pub(crate) fn get_manifest(&self) -> &TranscriptManifest {
        &self.manifest
    }

    fn add_element_frs_to_hash_buffer(&mut self, label: String, elements: &[H::DataType]) {
        // Add an entry to the current round of the manifest
        let len = elements.len();
        self.manifest.add_entry(self.round_number, label, len);
        self.current_round_data.extend(elements);
        self.num_frs_written += len;
    }

    fn add_element_frs_to_independent_hash_buffer(
        &mut self,
        _label: String,
        elements: &[H::DataType],
    ) {
        self.independent_hash_buffer.extend(elements);
    }

    // Adds an element to the transcript.
    // Serializes the element to frs and adds it to the current_round_data buffer. Does NOT add the element to the proof. This is used for elements which should be part of the transcript but are not in the final proof (e.g. circuit size)
    fn add_to_hash_buffer(&mut self, label: String, elements: &[H::DataType]) {
        self.add_element_frs_to_hash_buffer(label, elements);
    }

    fn send_to_verifier(&mut self, label: String, elements: &[H::DataType]) {
        self.proof_data.extend(elements);
        self.add_element_frs_to_hash_buffer(label, elements);
    }

    pub fn send_fr_to_verifier<P: HonkCurve<F>>(&mut self, label: String, element: P::ScalarField) {
        let elements = H::convert_scalarfield_into::<P>(&element);
        self.send_to_verifier(label, &elements);
    }

    pub fn send_u64_to_verifier(&mut self, label: String, element: u64) {
        let el = H::DataType::from(element);
        self.send_to_verifier(label, &[el]);
    }

    pub fn add_u64_to_hash_buffer(&mut self, label: String, element: u64) {
        let el = H::DataType::from(element);
        self.add_to_hash_buffer(label, &[el]);
    }

    pub fn add_fr_to_hash_buffer<P: HonkCurve<F>>(
        &mut self,
        label: String,
        element: P::ScalarField,
    ) {
        self.add_to_hash_buffer(label, &H::convert_scalarfield_into::<P>(&element));
    }

    pub fn send_point_to_verifier<P: HonkCurve<F>>(&mut self, label: String, element: P::Affine) {
        let elements = H::convert_point::<P>(&element);
        self.send_to_verifier(label, &elements);
    }

    pub fn add_u64_to_independent_hash_buffer(&mut self, label: String, element: u64) {
        let el = H::DataType::from(element);
        self.add_element_frs_to_independent_hash_buffer(label, &[el]);
    }

    pub fn add_point_to_independent_hash_buffer<P: HonkCurve<F>>(
        &mut self,
        label: String,
        element: P::Affine,
    ) {
        let elements = H::convert_point::<P>(&element);
        self.add_element_frs_to_independent_hash_buffer(label, &elements);
    }

    pub fn send_fr_iter_to_verifier<
        'a,
        P: HonkCurve<F>,
        I: IntoIterator<Item = &'a P::ScalarField>,
    >(
        &mut self,
        label: String,
        element: I,
    ) {
        let elements = element
            .into_iter()
            .flat_map(H::convert_scalarfield_into::<P>)
            .collect::<Vec<_>>();
        self.send_to_verifier(label, &elements);
    }

    fn receive_n_from_prover(
        &mut self,
        label: String,
        n: usize,
    ) -> HonkProofResult<Vec<H::DataType>> {
        let end = self
            .num_frs_read
            .checked_add(n)
            .filter(|end| *end <= self.proof_data.len())
            .ok_or(HonkProofError::ProofTooSmall)?;
        let elements = self.proof_data[self.num_frs_read..end].to_owned();
        self.num_frs_read = end;

        self.add_element_frs_to_hash_buffer(label, &elements);
        Ok(elements)
    }

    pub fn receive_fr_from_prover<P: HonkCurve<F>>(
        &mut self,
        label: String,
    ) -> HonkProofResult<P::ScalarField> {
        let elements = self.receive_n_from_prover(label, H::NUM_SCALARFIELD_ELEMENTS)?;

        H::validate_scalarfield::<P>(&elements)?;
        Ok(H::convert_scalarfield_back::<P>(&elements))
    }

    pub fn receive_point_from_prover<P: HonkCurve<F>>(
        &mut self,
        label: String,
    ) -> HonkProofResult<P::Affine> {
        let elements = self.receive_n_from_prover(label, H::NUM_BASEFIELD_ELEMENTS * 2)?;

        // `as_chunks` is not possible here since associated consts cannot be used as const generics on stable
        #[allow(clippy::chunks_exact_to_as_chunks)]
        let coords = elements
            .chunks_exact(H::NUM_BASEFIELD_ELEMENTS)
            .map(|coord| {
                H::validate_basefield::<P>(coord)?;
                Ok(H::convert_basefield_back::<P>(coord))
            })
            .collect::<HonkProofResult<Vec<_>>>()?;

        let x: P::BaseField = coords[0];
        let y: P::BaseField = coords[1];

        // The coordinates are canonical, so (0, 0) is the only encoding of the point at infinity.
        let res = if x.is_zero() && y.is_zero() {
            P::Affine::zero()
        } else {
            P::g1_affine_from_xy(x, y)?
        };

        Ok(res)
    }

    pub fn receive_fr_vec_from_prover<P: HonkCurve<F>>(
        &mut self,
        label: String,
        n: usize,
    ) -> HonkProofResult<Vec<P::ScalarField>> {
        let num_elements = H::NUM_SCALARFIELD_ELEMENTS
            .checked_mul(n)
            .ok_or(HonkProofError::ProofTooSmall)?;
        let elements = self.receive_n_from_prover(label, num_elements)?;

        // `as_chunks` is not possible here since associated consts cannot be used as const generics on stable
        #[allow(clippy::chunks_exact_to_as_chunks)]
        let elements = elements
            .chunks_exact(H::NUM_SCALARFIELD_ELEMENTS)
            .map(|element| {
                H::validate_scalarfield::<P>(element)?;
                Ok(H::convert_scalarfield_back::<P>(element))
            })
            .collect::<HonkProofResult<_>>()?;

        Ok(elements)
    }

    pub fn receive_fr_array_from_prover<P: HonkCurve<F>, const SIZE: usize>(
        &mut self,
        label: String,
    ) -> HonkProofResult<[P::ScalarField; SIZE]> {
        let mut res: [P::ScalarField; SIZE] = [P::ScalarField::zero(); SIZE];
        let elements = self.receive_n_from_prover(label, H::NUM_SCALARFIELD_ELEMENTS * SIZE)?;

        // `as_chunks` is not possible here since associated consts cannot be used as const generics on stable
        #[allow(clippy::chunks_exact_to_as_chunks)]
        for (src, des) in elements
            .chunks_exact(H::NUM_SCALARFIELD_ELEMENTS)
            .zip(res.iter_mut())
        {
            H::validate_scalarfield::<P>(src)?;
            let el = H::convert_scalarfield_back::<P>(src);
            *des = el;
        }
        Ok(res)
    }

    /// Computes the next challenge c_next = H(c_prev || round_buffer) and sets it as the previous challenge.
    fn get_next_challenge_hash<C: HonkCurve<F>>(&mut self) -> H::DataType {
        // Prevent challenge generation if this is the first challenge we're generating,
        // AND nothing was sent by the prover.
        if self.is_first_challenge {
            assert!(!self.current_round_data.is_empty());
        }
        // concatenate the previous challenge (if this is not the first challenge) with the current round data.
        // AZTEC TODO(Adrian): Do we want to use a domain separator as the initial challenge buffer?
        // We could be cheeky and use the hash of the manifest as domain separator, which would prevent us from having
        // to domain separate all the data. (See https://safe-hash.dev)

        let mut full_buffer = Vec::new();
        std::mem::swap(&mut full_buffer, &mut self.current_round_data);

        if self.is_first_challenge {
            // Update is_first_challenge for the future
            self.is_first_challenge = false;
        } else {
            // if not the first challenge, we can use the previous_challenge
            full_buffer.insert(0, self.previous_challenge);
        }

        // Hash the full buffer with poseidon2, which is believed to be a collision resistant hash function and a random
        // oracle, removing the need to pre-hash to compress and then hash with a random oracle, as we previously did
        // with Pedersen and Blake3s.
        let new_challenge = H::hash(full_buffer);
        // update previous challenge buffer for next time we call this function
        // We need the modulo reduction into F here
        let new_challenge_as_field =
            H::convert_destinationfield_to_scalarfield::<C>(&new_challenge);
        let new_challenge = H::convert_scalarfield_into::<C>(&new_challenge_as_field)[0];

        self.previous_challenge = new_challenge;
        new_challenge
    }

    /// Generates a single full-width challenge.
    pub fn get_challenge<P: HonkCurve<F>>(&mut self, label: String) -> P::ScalarField {
        self.manifest.add_challenge(self.round_number, &[label]);
        let challenge = self.get_next_challenge_hash::<P>();
        let res = H::convert_destinationfield_to_scalarfield::<P>(&challenge);
        self.round_number += 1;
        res
    }

    /// Generates full-width challenges, one transcript hash per challenge.
    pub fn get_challenges<P: HonkCurve<F>>(&mut self, labels: &[String]) -> Vec<P::ScalarField> {
        self.manifest.add_challenge(self.round_number, labels);
        let res = (0..labels.len())
            .map(|_| {
                let challenge = self.get_next_challenge_hash::<P>();
                H::convert_destinationfield_to_scalarfield::<P>(&challenge)
            })
            .collect();
        self.round_number += 1;
        res
    }

    pub fn hash_independent_buffer<P: HonkCurve<F>>(&mut self) -> P::ScalarField {
        let res = H::hash(std::mem::take(&mut self.independent_hash_buffer));
        H::convert_destinationfield_to_scalarfield::<P>(&res)
    }

    pub fn compute_round_challenge_pows<P: HonkCurve<F>>(
        &self,
        num_powers: usize,
        round_challenge: P::ScalarField,
    ) -> Vec<P::ScalarField> {
        let mut pows = Vec::with_capacity(num_powers);
        if num_powers > 0 {
            pows.push(round_challenge);
            for i in 1..num_powers {
                pows.push(pows[i - 1] * pows[i - 1]);
            }
        }
        pows
    }

    pub fn get_powers_of_challenge<P: HonkCurve<F>>(
        &mut self,
        label: String,
        num_challenges: usize,
    ) -> Vec<P::ScalarField> {
        let challenge = self.get_challenge::<P>(label);
        self.compute_round_challenge_pows::<P>(num_challenges, challenge)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub(crate) struct RoundData {
    challenge_label: Vec<String>,
    entries: Vec<(String, usize)>,
}

impl RoundData {
    pub(crate) fn print(&self) {
        for label in self.challenge_label.iter() {
            println!("\tchallenge: {label}");
        }
        for entry in self.entries.iter() {
            println!("\telement ({}): {}", entry.1, entry.0);
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct TranscriptManifest {
    manifest: BTreeMap<usize, RoundData>,
}

impl TranscriptManifest {
    pub(crate) fn print(&self) {
        for round in self.manifest.iter() {
            println!("Round: {}", round.0);
            round.1.print();
        }
    }

    pub(crate) fn add_challenge(&mut self, round: usize, labels: &[String]) {
        self.manifest
            .entry(round)
            .or_default()
            .challenge_label
            .extend_from_slice(labels);
    }

    pub(crate) fn add_entry(&mut self, round: usize, element_label: String, element_size: usize) {
        self.manifest
            .entry(round)
            .or_default()
            .entries
            .push((element_label, element_size));
    }

    #[expect(dead_code)]
    pub(crate) fn size(&self) -> usize {
        self.manifest.len()
    }
}

impl Index<usize> for TranscriptManifest {
    type Output = RoundData;

    fn index(&self, index: usize) -> &Self::Output {
        &self.manifest[&index]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::honk_curve::HonkCurve;
    use ark_bn254::{Fq, Fr, G1Affine, G1Projective};
    use ark_ec::AffineRepr;
    use noir_types::U256;
    use num_bigint::BigUint;
    use sha3::Keccak256;

    fn word(value: BigUint) -> U256 {
        let raw = value.to_bytes_be();
        let mut bytes = [0u8; 32];
        bytes[32 - raw.len()..].copy_from_slice(&raw);
        U256(ruint::Uint::from_be_bytes(bytes))
    }

    fn keccak_verifier(words: Vec<U256>) -> Transcript<Fr, Keccak256> {
        Transcript::new_verifier(HonkProof::new(words))
    }

    fn poseidon_verifier(frs: Vec<Fr>) -> Transcript<Fr, Poseidon2Sponge> {
        Transcript::new_verifier(HonkProof::new(frs))
    }

    /// Encodes the coordinates of a point as the four (136-bit, 118-bit) limbs of a proof.
    fn limbs(x: &BigUint, y: &BigUint) -> Vec<Fr> {
        let mask = (BigUint::from(1u8) << 136) - 1u8;
        [x, y]
            .into_iter()
            .flat_map(|c| [Fr::from(c & &mask), Fr::from(c >> 136)])
            .collect()
    }

    fn read_point(frs: Vec<Fr>) -> HonkProofResult<G1Affine> {
        poseidon_verifier(frs).receive_point_from_prover::<G1Projective>("P".to_string())
    }

    #[test]
    fn field_points_reject_noncanonical_limbs() {
        let q: BigUint = Fq::MODULUS.into();
        let (gx, gy) = G1Projective::g1_affine_to_xy(&G1Affine::generator());
        let (gx, gy): (BigUint, BigUint) = (gx.into(), gy.into());
        assert_eq!(read_point(limbs(&gx, &gy)).unwrap(), G1Affine::generator());
        assert!(read_point(vec![Fr::zero(); 4]).unwrap().is_zero());

        // Same coordinate value, but the low limb exceeds its 136-bit bound.
        let mut frs = limbs(&gx, &gy);
        frs[0] += Fr::from(BigUint::from(1u8) << 136);
        frs[1] -= Fr::from(1u64);
        assert!(matches!(
            read_point(frs),
            Err(HonkProofError::NonCanonicalFieldEncoding)
        ));
        // Coordinates that are congruent to the honest ones (or to infinity) modulo q.
        for frs in [
            limbs(&(&gx + &q), &gy),
            limbs(&gx, &(&gy + &q)),
            limbs(&q, &q),
        ] {
            assert!(matches!(
                read_point(frs),
                Err(HonkProofError::NonCanonicalFieldEncoding)
            ));
        }
    }

    #[test]
    fn off_curve_points_are_errors() {
        let off_curve = (BigUint::from(1u8), BigUint::from(3u8));
        assert!(matches!(
            read_point(limbs(&off_curve.0, &off_curve.1)),
            Err(HonkProofError::PointNotOnCurve)
        ));
        assert!(matches!(
            keccak_verifier(vec![word(off_curve.0), word(off_curve.1)])
                .receive_point_from_prover::<G1Projective>("P".to_string()),
            Err(HonkProofError::PointNotOnCurve)
        ));
    }

    #[test]
    fn keccak_scalars_reject_noncanonical_words() {
        let r: BigUint = Fr::MODULUS.into();
        for value in [BigUint::zero(), &r - 1u8] {
            assert!(
                keccak_verifier(vec![word(value)])
                    .receive_fr_from_prover::<G1Projective>("x".to_string())
                    .is_ok()
            );
        }
        for value in [r.clone(), &r + 1u8, (BigUint::from(1u8) << 256) - 1u8] {
            let w = word(value);
            assert!(matches!(
                keccak_verifier(vec![w]).receive_fr_from_prover::<G1Projective>("x".to_string()),
                Err(HonkProofError::NonCanonicalFieldEncoding)
            ));
            assert!(matches!(
                keccak_verifier(vec![w])
                    .receive_fr_vec_from_prover::<G1Projective>("x".to_string(), 1),
                Err(HonkProofError::NonCanonicalFieldEncoding)
            ));
            assert!(matches!(
                keccak_verifier(vec![w])
                    .receive_fr_array_from_prover::<G1Projective, 1>("x".to_string()),
                Err(HonkProofError::NonCanonicalFieldEncoding)
            ));
        }
    }

    #[test]
    fn oversized_reads_are_errors() {
        for n in [2, usize::MAX] {
            let mut transcript = poseidon_verifier(vec![Fr::zero()]);
            transcript
                .receive_fr_from_prover::<G1Projective>("first".to_string())
                .unwrap();
            assert!(matches!(
                transcript.receive_fr_vec_from_prover::<G1Projective>("rest".to_string(), n),
                Err(HonkProofError::ProofTooSmall)
            ));
        }
    }

    #[test]
    fn keccak_points_reject_coordinates_above_the_modulus() {
        let q: BigUint = Fq::MODULUS.into();
        // (1, 2) is the generator, (0, 0) encodes the point at infinity.
        for (x, y) in [(1u8, 2u8), (0, 0)] {
            let (x, y) = (BigUint::from(x), BigUint::from(y));
            assert!(
                keccak_verifier(vec![word(x.clone()), word(y.clone())])
                    .receive_point_from_prover::<G1Projective>("P".to_string())
                    .is_ok()
            );
            for words in [
                vec![word(&x + &q), word(y.clone())],
                vec![word(x.clone()), word(&y + &q)],
            ] {
                assert!(matches!(
                    keccak_verifier(words)
                        .receive_point_from_prover::<G1Projective>("P".to_string()),
                    Err(HonkProofError::NonCanonicalFieldEncoding)
                ));
            }
        }
    }

    /// Replays the prover messages of `tests/fixtures/transcript_challenges.cpp` and compares the challenges with
    /// the values barretenberg v6.0.0 prints for it: scalar and point encodings, several challenges from one
    /// squeeze, a challenge after a round without new data, and an element that needs the full field width.
    fn check_barretenberg_challenges<H: TranscriptHasher<TranscriptFieldType>>(name: &str) {
        let expected: Vec<_> = include_str!("../tests/fixtures/transcript_challenges.txt")
            .lines()
            .filter_map(|line| {
                let (hasher, value) = line.split_once(' ').unwrap();
                let value = BigUint::parse_bytes(value.trim_start_matches("0x").as_bytes(), 16);
                (hasher == name).then(|| Fr::from(value.unwrap()))
            })
            .collect();
        assert_eq!(expected.len(), 7);

        let mut transcript = Transcript::<TranscriptFieldType, H>::new();
        transcript.send_fr_to_verifier::<G1Projective>("data0".to_string(), Fr::from(1u64));
        transcript.send_fr_to_verifier::<G1Projective>("data1".to_string(), Fr::from(2u64));
        transcript
            .send_point_to_verifier::<G1Projective>("point".to_string(), G1Affine::generator());
        let mut actual = transcript
            .get_challenges::<G1Projective>(&["eta".to_string(), "rom_logup_gamma".to_string()]);
        actual.push(transcript.get_challenge::<G1Projective>("tail".to_string()));
        transcript
            .send_fr_to_verifier::<G1Projective>("data2".to_string(), Fr::from(0xdeadbeefu64));
        transcript.send_fr_to_verifier::<G1Projective>("large".to_string(), -Fr::from(1u64));
        actual.extend(transcript.get_challenges::<G1Projective>(&[
            "alpha".to_string(),
            "beta".to_string(),
            "gamma".to_string(),
        ]));
        actual.push(transcript.get_challenge::<G1Projective>("delta".to_string()));
        assert_eq!(actual, expected);
    }

    #[test]
    fn poseidon2_challenges_match_barretenberg() {
        check_barretenberg_challenges::<Poseidon2Sponge>("poseidon2");
    }

    #[test]
    fn keccak_challenges_match_barretenberg() {
        check_barretenberg_challenges::<Keccak256>("keccak");
    }
}

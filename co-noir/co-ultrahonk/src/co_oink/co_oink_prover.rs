// clang-format off
/*                                            )\   /|
*                                          .-/'-|_/ |
*                       __            __,-' (   / \/
*                   .-'"  "'-..__,-'""          -o.`-._
*                  /                                   '/
*          *--._ ./                                 _.--
*                |                              _.-'
*                :                           .-/
*                 \                       )_ /
*                  \                _)   / \(
*                    `.   /-.___.---'(  /   \\
*                     (  /   \\       \(     L\
*                      \(     L\       \\
*                       \\              \\
*                        L\              L\
*/
// clang-format on

use super::types::{Challenges, ProverMemory};
use ark_ff::{One, Zero};
use co_noir_common::{
    CoUtils,
    constants::{NUM_ZERO_ROWS, PERMUTATION_ARGUMENT_VALUE_SEPARATOR},
    crs::ProverCrs,
    honk_curve::HonkCurve,
    honk_proof::{HonkProofError, HonkProofResult, TranscriptFieldType},
    keys::{
        proving_key::ProvingKey, types::ActiveRegionData,
        verification_key::VerifyingKeyBarretenberg,
    },
    mpc::NoirUltraHonkProver,
    polynomials::{
        entities::Polynomials,
        polynomial::{NUM_DISABLED_ROWS_IN_SUMCHECK, NUM_MASKED_ROWS, Polynomial},
        shared_polynomial::SharedPolynomial,
    },
    transcript::{Transcript, TranscriptHasher},
    types::ZeroKnowledge,
};
use mpc_core::MpcState;
use mpc_net::Network;
use rayon::prelude::*;
use std::marker::PhantomData;
use ultrahonk::NUM_ALPHAS;

pub(crate) struct CoOink<
    'a,
    T: NoirUltraHonkProver<C>,
    C: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
    N: Network,
> {
    net: &'a N,
    state: &'a mut T::State,
    memory: ProverMemory<T, C>,
    phantom_data: PhantomData<C>,
    phantom_hasher: PhantomData<H>,
    has_zk: ZeroKnowledge,
}

impl<
    'a,
    T: NoirUltraHonkProver<C>,
    C: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
    N: Network,
> CoOink<'a, T, C, H, N>
{
    pub(crate) fn new(net: &'a N, state: &'a mut T::State, has_zk: ZeroKnowledge) -> Self {
        Self {
            net,
            state,
            memory: ProverMemory::default(),
            phantom_data: PhantomData,
            phantom_hasher: PhantomData,
            has_zk,
        }
    }

    fn mask_polynomial(
        &mut self,
        polynomial: &mut Polynomial<T::ArithmeticShare>,
    ) -> HonkProofResult<()> {
        tracing::trace!("mask polynomial");

        // Masked rows sit right after the zero row (row 0): [NUM_ZERO_ROWS, NUM_ZERO_ROWS + NUM_MASKED_ROWS).
        let virtual_size = polynomial.coefficients.len();
        assert!(
            virtual_size >= NUM_ZERO_ROWS + NUM_MASKED_ROWS as usize,
            "Insufficient space for masking"
        );
        for i in (NUM_ZERO_ROWS..NUM_ZERO_ROWS + NUM_MASKED_ROWS as usize).rev() {
            polynomial.coefficients[i] = T::rand(self.net, self.state)?;
        }

        Ok(())
    }

    fn compute_w4_inner(&mut self, proving_key: &ProvingKey<T, C>, gate_idx: usize) {
        let target = &mut self.memory.w_4[gate_idx];

        let mul1 = T::mul_with_public(
            self.memory.challenges.eta_1,
            proving_key.polynomials.witness.w_l()[gate_idx],
        );
        let mul2 = T::mul_with_public(
            self.memory.challenges.eta_2,
            proving_key.polynomials.witness.w_r()[gate_idx],
        );
        let mul3 = T::mul_with_public(
            self.memory.challenges.eta_3,
            proving_key.polynomials.witness.w_o()[gate_idx],
        );
        // TACEO TODO add_assign?
        *target = T::add(*target, mul1);
        *target = T::add(*target, mul2);
        *target = T::add(*target, mul3);
    }

    fn add_ram_rom_memory_records_to_wire_4(&mut self, proving_key: &ProvingKey<T, C>) {
        tracing::trace!("add_ram_rom_memory_records_to_wire_4");
        // The memory record values are computed at the indicated indices as
        // w4 = w3 * eta^3 + w2 * eta^2 + w1 * eta + read_write_flag;

        debug_assert_eq!(
            proving_key.polynomials.witness.w_l().len(),
            proving_key.polynomials.witness.w_r().len()
        );
        debug_assert_eq!(
            proving_key.polynomials.witness.w_l().len(),
            proving_key.polynomials.witness.w_o().len()
        );

        self.memory.w_4 = proving_key.polynomials.witness.w_4().clone();
        self.memory.w_4.resize(
            proving_key.polynomials.witness.w_l().len(),
            T::ArithmeticShare::default(),
        );

        // Compute read record values
        for gate_idx in proving_key.memory_read_records.iter() {
            let gate_idx = *gate_idx as usize;
            self.compute_w4_inner(proving_key, gate_idx);
        }

        // Compute write record values
        for gate_idx in proving_key.memory_write_records.iter() {
            let gate_idx = *gate_idx as usize;
            self.compute_w4_inner(proving_key, gate_idx);
            let target = &mut self.memory.w_4[gate_idx];
            *target = T::add_with_public(C::ScalarField::one(), *target, self.state.id());
        }

        // This computes the values for cases where the type (r/w) of the record is a secret share of 0/1 and adds this share
        for (gate_idx, type_share) in proving_key.memory_records_shared.iter() {
            let gate_idx = *gate_idx as usize;
            self.compute_w4_inner(proving_key, gate_idx);
            let target = &mut self.memory.w_4[gate_idx];
            *target = T::add(*type_share, *target);
        }
    }

    /// Populates the inverse helper w4 = 1 / (rom_logup_gamma + w1 + eta * w2 + eta^2 * q_c) at every ROM-LogUp row,
    /// where q_c holds the ROM array id.
    fn add_rom_logup_inverses_to_wire_4(
        &mut self,
        proving_key: &ProvingKey<T, C>,
    ) -> HonkProofResult<()> {
        tracing::trace!("add_rom_logup_inverses_to_wire_4");
        if proving_key.rom_logup_records.is_empty() {
            return Ok(());
        }
        let id = self.state.id();
        let challenges = &self.memory.challenges;
        let mut denominators = proving_key
            .rom_logup_records
            .iter()
            .map(|&gate_idx| {
                let gate_idx = gate_idx as usize;
                let public = challenges.rom_logup_gamma
                    + proving_key.polynomials.precomputed.q_c()[gate_idx] * challenges.eta_2;
                let value = T::mul_with_public(
                    challenges.eta_1,
                    proving_key.polynomials.witness.w_r()[gate_idx],
                );
                let denom = T::add(proving_key.polynomials.witness.w_l()[gate_idx], value);
                T::add_with_public(public, denom, id)
            })
            .collect::<Vec<_>>();
        // The denominators are nonzero with overwhelming probability over the choice of rom_logup_gamma
        T::inv_many_in_place(&mut denominators, self.net, self.state)?;
        for (&gate_idx, inverse) in proving_key.rom_logup_records.iter().zip(denominators) {
            self.memory.w_4[gate_idx as usize] = inverse;
        }
        Ok(())
    }

    fn compute_lookup_term(
        challenges: &Challenges<C::ScalarField>,
        id: <T::State as MpcState>::PartyID,
        polynomials: &Polynomials<T::ArithmeticShare, C::ScalarField>,
        i: usize,
    ) -> T::ArithmeticShare {
        let gamma = challenges.gamma;
        let beta = challenges.beta;
        let beta_sqr = challenges.beta_sqr;
        let beta_cube = challenges.beta_cube;

        let w_1 = polynomials.witness.w_l()[i];
        let w_2 = polynomials.witness.w_r()[i];
        let w_3 = polynomials.witness.w_o()[i];

        let w_1_shift = polynomials.witness.w_l().shifted()[i];
        let w_2_shift = polynomials.witness.w_r().shifted()[i];
        let w_3_shift = polynomials.witness.w_o().shifted()[i];

        let table_index = polynomials.precomputed.q_o()[i];
        let negative_column_1_step_size = polynomials.precomputed.q_r()[i];
        let negative_column_2_step_size = polynomials.precomputed.q_m()[i];
        let negative_column_3_step_size = polynomials.precomputed.q_c()[i];

        // The wire values for lookup gates are accumulators structured in such a way that the differences w_i -
        // step_size*w_i_shift result in values present in column i of a corresponding table. See the documentation in
        // method get_lookup_accumulators() in  for a detailed explanation.
        let mul = T::mul_with_public(negative_column_1_step_size, w_1_shift);
        let add = T::add_with_public(gamma, mul, id);
        let derived_table_entry_1 = T::add(w_1, add);

        let mul = T::mul_with_public(negative_column_2_step_size, w_2_shift);
        let derived_table_entry_2 = T::add(w_2, mul);

        let mul = T::mul_with_public(negative_column_3_step_size, w_3_shift);
        let derived_table_entry_3 = T::add(w_3, mul);

        let table_index_entry = beta_cube * table_index;

        // (w_1 + \gamma + q_2*w_1_shift) + β(w_2 + q_m*w_2_shift) + β²(w_3 + q_c*w_3_shift) + β³q_index.
        // deg 2 or 3
        let mul = T::mul_with_public(beta, derived_table_entry_2);
        let res = T::add(derived_table_entry_1, mul);
        let mul = T::mul_with_public(beta_sqr, derived_table_entry_3);
        let res = T::add(res, mul);
        T::add_with_public(table_index_entry, res, id)
    }

    // Compute table_1 + gamma + table_2 * beta + table_3 * beta^2 + table_4 * beta^3
    fn compute_table_term(
        challenges: &Challenges<C::ScalarField>,
        polynomials: &Polynomials<T::ArithmeticShare, C::ScalarField>,
        i: usize,
    ) -> C::ScalarField {
        let gamma = &challenges.gamma;
        let beta = challenges.beta;
        let beta_sqr = challenges.beta_sqr;
        let beta_cube = challenges.beta_cube;
        let table_1 = &polynomials.precomputed.table_1()[i];
        let table_2 = &polynomials.precomputed.table_2()[i];
        let table_3 = &polynomials.precomputed.table_3()[i];
        let table_4 = &polynomials.precomputed.table_4()[i];

        *table_1 + gamma + *table_2 * beta + *table_3 * beta_sqr + *table_4 * beta_cube
    }

    fn compute_logderivative_inverses(
        &mut self,
        proving_key: &ProvingKey<T, C>,
    ) -> HonkProofResult<()> {
        tracing::trace!("compute logderivative inverse");

        debug_assert_eq!(
            proving_key.polynomials.precomputed.q_lookup().len(),
            proving_key.circuit_size as usize
        );
        debug_assert_eq!(
            proving_key.polynomials.witness.lookup_read_tags().len(),
            proving_key.circuit_size as usize
        );

        // const READ_TERMS: usize = 1;
        // const WRITE_TERMS: usize = 1;
        // // 1 + polynomial degree of this relation
        // const LENGTH: usize = 5; // both subrelations are degree 4

        // Every row is a local computation, so the rows run on rayon.
        let id = self.state.id();
        let challenges = &self.memory.challenges;
        let polynomials = &proving_key.polynomials;
        let q_lookup: &[C::ScalarField] = polynomials.precomputed.q_lookup().as_ref();
        let lookup_read_tags: &[T::ArithmeticShare] =
            polynomials.witness.lookup_read_tags().as_ref();
        let (lookup_inverses, q_lookup_mul_read_tag): (Vec<_>, Vec<_>) = q_lookup
            .par_iter()
            .zip(lookup_read_tags.par_iter())
            .enumerate()
            .map(|(i, (q_lookup, lookup_read_tag))| {
                // The following check cannot easily be done since lookup_read_tag is shared. We prepare q_lookup_mul_read_tag instead and multiply it later to self.memory.lookup_inverses.
                // if !(q_lookup.is_one() || lookup_read_tag.is_one()) {
                //     continue;
                // }
                debug_assert!(q_lookup.is_one() || q_lookup.is_zero());
                let mul = T::mul_with_public(
                    C::ScalarField::one() - q_lookup,
                    lookup_read_tag.to_owned(),
                );
                let q_lookup_mul_read_tag = T::add_with_public(q_lookup.to_owned(), mul, id);

                // READ_TERMS and WRITE_TERMS are 1, so we skip the loop
                let read_term = Self::compute_lookup_term(challenges, id, polynomials, i);
                let write_term = Self::compute_table_term(challenges, polynomials, i);
                (
                    T::mul_with_public(write_term, read_term),
                    q_lookup_mul_read_tag,
                )
            })
            .unzip();
        self.memory.lookup_inverses = Polynomial::new(lookup_inverses);

        // Invert the denominators before multiplying by the secret activity bit
        // q_lookup + (1 - q_lookup) * read_tag. The inversion opens each denominator
        // multiplied by a random value and therefore reveals which rows are zero. If
        // the activity bit were applied first, those zeros would reveal, for every
        // table row (q_lookup = 0), whether the private read tag is set, i.e. which
        // table entries the witness used. The denominators contain gamma and are
        // nonzero except for challenge collisions, and for a boolean activity bit s
        // the result s * inv(d) equals inv(d * s), with zeroes kept as zero.
        CoUtils::batch_invert_leaking_zeros::<T, C, N>(
            self.memory.lookup_inverses.as_mut(),
            self.net,
            self.state,
        )?;
        self.memory.lookup_inverses = Polynomial::new(T::mul_many(
            self.memory.lookup_inverses.as_ref(),
            &q_lookup_mul_read_tag,
            self.net,
            self.state,
        )?);
        Ok(())
    }

    fn compute_public_input_delta(&self, proving_key: &ProvingKey<T, C>) -> C::ScalarField {
        tracing::trace!("compute public input delta");

        // Let m be the number of public inputs x₀,…, xₘ₋₁.
        // Recall that we broke the permutation σ⁰ by changing the mapping
        //  (i) -> (n+i)   to   (i) -> (-(i+1))   i.e. σ⁰ᵢ = −(i+1)
        //
        // Therefore, the term in the numerator with ID¹ᵢ = n+i does not cancel out with any term in the denominator.
        // Similarly, the denominator contains an extra σ⁰ᵢ = −(i+1) term that does not appear in the numerator.
        // We expect the values of W⁰ᵢ and W¹ᵢ to be equal to xᵢ.
        // The expected accumulated product would therefore be equal to

        //   ∏ᵢ (γ + W¹ᵢ + β⋅ID¹ᵢ)        ∏ᵢ (γ + xᵢ + β⋅(n+i) )
        //  -----------------------  =  ------------------------
        //   ∏ᵢ (γ + W⁰ᵢ + β⋅σ⁰ᵢ )        ∏ᵢ (γ + xᵢ - β⋅(i+1) )

        // At the start of the loop for each xᵢ where i = 0, 1, …, m-1,
        // we have
        //      numerator_acc   = γ + β⋅(n+i) = γ + β⋅n + β⋅i
        //      denominator_acc = γ - β⋅(1+i) = γ - β   - β⋅i
        // at the end of the loop, add and subtract β to each term respectively to
        // set the expected value for the start of iteration i+1.
        // Note: The public inputs may be offset from the 0th index of the wires, for example due to the inclusion of an
        // initial zero row or Goblin-style ECC op gates. Accordingly, the indices i in the above formulas are given by i =
        // [0, m-1] + offset, i.e. i = offset, 1 + offset, …, m - 1 + offset.

        let mut num = C::ScalarField::one();
        let mut denom = C::ScalarField::one();
        let separator = PERMUTATION_ARGUMENT_VALUE_SEPARATOR;
        let mut num_acc = self.memory.challenges.gamma
            + self.memory.challenges.beta
                * C::ScalarField::from((separator + proving_key.pub_inputs_offset) as u64);
        let mut denom_acc = self.memory.challenges.gamma
            - self.memory.challenges.beta
                * C::ScalarField::from((1 + proving_key.pub_inputs_offset) as u64);

        for (i, x_i) in proving_key.public_inputs.iter().enumerate() {
            num *= num_acc + x_i;
            denom *= denom_acc + x_i;

            if i + 1 < proving_key.public_inputs.len() {
                num_acc += self.memory.challenges.beta;
                denom_acc -= self.memory.challenges.beta;
            }
        }
        num / denom
    }

    /// Appends the two factors (`pub1 * beta + gamma + shared1` and `pub2 * beta + gamma +
    /// shared2`) of the first `output_len` active rows of a grand-product numerator or
    /// denominator term to `lhs` and `rhs`.
    #[expect(clippy::too_many_arguments)]
    fn grand_product_num_denom_factors(
        id: <T::State as MpcState>::PartyID,
        shared1: &Polynomial<T::ArithmeticShare>,
        shared2: &Polynomial<T::ArithmeticShare>,
        pub1: &Polynomial<C::ScalarField>,
        pub2: &Polynomial<C::ScalarField>,
        beta: &C::ScalarField,
        gamma: &C::ScalarField,
        output_len: usize,
        active_region_data: &ActiveRegionData,
        lhs: &mut Vec<T::ArithmeticShare>,
        rhs: &mut Vec<T::ArithmeticShare>,
    ) {
        debug_assert!(shared1.len() >= output_len);
        debug_assert!(shared2.len() >= output_len);
        debug_assert!(pub1.len() >= output_len);
        debug_assert!(pub2.len() >= output_len);
        let has_active_ranges = active_region_data.size() > 0;

        // We drop the last element since it is not needed for the grand product
        // Every row is a local computation, so the rows run on rayon.
        let (mul1, mul2): (Vec<_>, Vec<_>) = (0..output_len)
            .into_par_iter()
            .map(|i| {
                let idx = if has_active_ranges {
                    active_region_data.get_idx(i)
                } else {
                    i
                };
                let m1 = T::add_with_public(pub1[idx] * beta + gamma, shared1[idx], id);
                let m2 = T::add_with_public(pub2[idx] * beta + gamma, shared2[idx], id);
                (m1, m2)
            })
            .unzip();
        lhs.extend(mul1);
        rhs.extend(mul2);
    }

    fn compute_grand_product(&mut self, proving_key: &ProvingKey<T, C>) -> HonkProofResult<()> {
        tracing::trace!("compute grand product");

        let has_active_ranges = proving_key.active_region_data.size() > 0;

        // Barretenberg uses multithreading here

        // Set the domain over which the grand product must be computed. This may be less than the dyadic circuit size, e.g
        // the permutation grand product does not need to be computed beyond the index of the last active wire
        let domain_size = proving_key.final_active_wire_idx + 1;

        let active_domain_size = if has_active_ranges {
            proving_key.active_region_data.size()
        } else {
            domain_size
        };

        // In Barretenberg circuit size is taken from the q_c polynomial
        // Step (1)
        // Populate `numerator` and `denominator` with the algebra described by Relation

        // The four factor products (denom1, denom2, num1, num2) are independent, so they are
        // multiplied in one batch.
        let output_len = active_domain_size - 1;
        let id = self.state.id();
        let witness = &proving_key.polynomials.witness;
        let precomputed = &proving_key.polynomials.precomputed;
        let (beta, gamma) = (&self.memory.challenges.beta, &self.memory.challenges.gamma);
        let mut lhs = Vec::with_capacity(4 * output_len);
        let mut rhs = Vec::with_capacity(4 * output_len);
        for (shared1, shared2, pub1, pub2) in [
            (
                witness.w_l(),
                witness.w_r(),
                precomputed.sigma_1(),
                precomputed.sigma_2(),
            ),
            (
                witness.w_o(),
                &self.memory.w_4,
                precomputed.sigma_3(),
                precomputed.sigma_4(),
            ),
            (
                witness.w_l(),
                witness.w_r(),
                precomputed.id_1(),
                precomputed.id_2(),
            ),
            (
                witness.w_o(),
                &self.memory.w_4,
                precomputed.id_3(),
                precomputed.id_4(),
            ),
        ] {
            Self::grand_product_num_denom_factors(
                id,
                shared1,
                shared2,
                pub1,
                pub2,
                beta,
                gamma,
                output_len,
                &proving_key.active_region_data,
                &mut lhs,
                &mut rhs,
            );
        }
        let mut factors = CoUtils::mul_many_bounded::<T, C, N>(&lhs, &rhs, self.net, self.state)?;
        let num2 = factors.split_off(3 * output_len);
        let num1 = factors.split_off(2 * output_len);
        let denom2 = factors.split_off(output_len);
        let denom1 = factors;

        // numerator = num1 * num2 and denominator = denom1 * denom2 share one batch as well.
        let mut lhs = num1;
        lhs.extend(denom1);
        let mut rhs = num2;
        rhs.extend(denom2);
        let mut numerator = CoUtils::mul_many_bounded::<T, C, N>(&lhs, &rhs, self.net, self.state)?;
        let denominator = numerator.split_off(output_len);

        // Step (2)
        // Compute the accumulating product of the numerator and denominator terms.

        // Do the multiplications of num[i] * num[i-1] and den[i] * den[i-1] in constant rounds.
        // Both prefix products share the rounds of one batched call, unless the masks of both
        // (2 * (output_len + 1) values) would exceed a single message in the inversion.
        let (numerator, mut denominator) =
            if 2 * (output_len + 1) <= CoUtils::max_mul_many_len::<C::ScalarField>() {
                let mut products = CoUtils::array_prod_inner_mul_many::<T, C, N>(
                    self.net,
                    self.state,
                    &[numerator, denominator],
                )?;
                let denominator = products.pop().expect("two prefix products");
                let numerator = products.pop().expect("two prefix products");
                (numerator, denominator)
            } else {
                (
                    CoUtils::array_prod_mul::<T, C, N>(self.net, self.state, &numerator)?,
                    CoUtils::array_prod_mul::<T, C, N>(self.net, self.state, &denominator)?,
                )
            };

        // invert denominator
        CoUtils::batch_invert::<T, C, N>(&mut denominator, self.net, self.state)?;

        // Step (3) Compute z_perm[i] = numerator[i] / denominator[i]
        let mul = T::mul_many(&numerator, &denominator, self.net, self.state)?;

        self.memory.z_perm.resize(
            proving_key.circuit_size as usize,
            T::ArithmeticShare::default(),
        );
        // The grand product's boundary value of 1 sits at the trace's start row (the first row
        // after the disabled/reserved head rows), i.e. NUM_DISABLED_ROWS_IN_SUMCHECK + NUM_ZERO_ROWS.
        self.memory.z_perm[NUM_DISABLED_ROWS_IN_SUMCHECK as usize + NUM_ZERO_ROWS] =
            T::promote_to_trivial_share(self.state.id(), C::ScalarField::one());

        // Compute grand product values corresponding only to the active regions of the trace
        for (i, mul) in mul.into_iter().enumerate() {
            let idx = if has_active_ranges {
                proving_key.active_region_data.get_idx(i + 1)
            } else {
                i + 1
            };
            self.memory.z_perm[idx] = mul
        }

        // Final step: If active/inactive regions have been specified, the value of the grand product in the inactive
        // regions have not yet been set. The polynomial takes an already computed constant value across each inactive
        // region (since no copy constraints are present there) equal to the value of the grand product at the first index
        // of the subsequent active region.
        if has_active_ranges {
            for i in 0..domain_size {
                for j in 0..proving_key.active_region_data.num_ranges() - 1 {
                    let previous_range_end = proving_key.active_region_data.get_range(j).1;
                    let next_range_start = proving_key.active_region_data.get_range(j + 1).0;
                    // Set the value of the polynomial if the index falls in an inactive region
                    if i >= previous_range_end && i < next_range_start {
                        self.memory.z_perm[i] = self.memory.z_perm[next_range_start];
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    // Generate relation separators alphas for sumcheck/combiner computation
    fn generate_alphas_round(&mut self, transcript: &mut Transcript<TranscriptFieldType, H>) {
        tracing::trace!("generate alpha round");

        let alpha = transcript.get_challenge::<C>("alpha".to_string());
        let mut alpha_powers = [C::ScalarField::one(); NUM_ALPHAS];
        alpha_powers[0] = alpha;
        for i in 1..NUM_ALPHAS {
            alpha_powers[i] = alpha_powers[i - 1] * alpha;
        }
        self.memory.challenges.alphas.copy_from_slice(&alpha_powers);
    }

    // Add circuit size public input size and public inputs to transcript
    fn send_vk_hash_and_public_inputs(
        transcript: &mut Transcript<TranscriptFieldType, H>,
        proving_key: &ProvingKey<T, C>,
        verifying_key: &VerifyingKeyBarretenberg<C>,
    ) -> HonkProofResult<()> {
        tracing::trace!("executing preamble round");

        let vk_hash = verifying_key.hash_with_origin_tagging::<H>("", transcript);
        transcript.add_fr_to_hash_buffer::<C>("VK_HASH".to_string(), vk_hash);

        if proving_key.num_public_inputs as usize != proving_key.public_inputs.len() {
            return Err(HonkProofError::CorruptedWitness(
                proving_key.public_inputs.len(),
            ));
        }

        for (i, public_input) in proving_key.public_inputs.iter().enumerate() {
            // transcript.add_scalar(*public_input);
            transcript.send_fr_to_verifier::<C>(format!("PUBLIC_INPUT_{i}"), *public_input);
        }
        Ok(())
    }

    // Compute first three wire commitments
    fn commit_to_wires(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        proving_key: &mut ProvingKey<T, C>,
        crs: &ProverCrs<C>,
    ) -> HonkProofResult<()> {
        tracing::trace!("executing wire commitments round");

        // Commit to the first three wire polynomials of the instance
        // We only commit to the fourth wire polynomial after adding memory records

        // Mask the polynomial when proving in zero-knowledge
        if self.has_zk == ZeroKnowledge::Yes {
            self.mask_polynomial(proving_key.polynomials.witness.w_l_mut())?;
            self.mask_polynomial(proving_key.polynomials.witness.w_r_mut())?;
            self.mask_polynomial(proving_key.polynomials.witness.w_o_mut())?;
        };

        let w_l = CoUtils::commit::<T, C>(proving_key.polynomials.witness.w_l().as_ref(), crs);
        let w_r = CoUtils::commit::<T, C>(proving_key.polynomials.witness.w_r().as_ref(), crs);
        let w_o = CoUtils::commit::<T, C>(proving_key.polynomials.witness.w_o().as_ref(), crs);
        let open = T::open_point_many(&[w_l, w_r, w_o], self.net, self.state)?;

        let w_l: C::Affine = open[0].into();
        let w_r: C::Affine = open[1].into();
        let w_o: C::Affine = open[2].into();
        transcript.send_point_to_verifier::<C>("W_L".to_string(), w_l);
        transcript.send_point_to_verifier::<C>("W_R".to_string(), w_r);
        transcript.send_point_to_verifier::<C>("W_O".to_string(), w_o);

        // Round is done since ultra_honk is no goblin flavor
        Ok(())
    }

    fn commit_to_masking_poly(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        proving_key: &ProvingKey<T, C>,
        crs: &ProverCrs<C>,
    ) -> HonkProofResult<()> {
        if self.has_zk == ZeroKnowledge::No {
            return Ok(());
        }

        let polynomial_size = proving_key.polynomials.witness.w_l().len();
        let masking_poly = SharedPolynomial::<T, C>::random(polynomial_size, self.net, self.state)?;
        let masking_poly_commitment_shared = CoUtils::commit::<T, C>(masking_poly.as_ref(), crs);
        let masking_poly_commitment =
            T::open_point(masking_poly_commitment_shared, self.net, self.state)?;
        transcript.send_point_to_verifier::<C>(
            "Gemini:masking_poly_comm".to_string(),
            masking_poly_commitment.into(),
        );
        self.memory.gemini_masking_poly = Some(masking_poly);

        Ok(())
    }

    // Compute sorted witness-table accumulator and commit to the resulting polynomials.
    fn commit_to_lookup_counts_and_w4(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        proving_key: &mut ProvingKey<T, C>,
        crs: &ProverCrs<C>,
    ) -> HonkProofResult<()> {
        tracing::trace!("executing sorted list accumulator round");

        let challs =
            transcript.get_challenges::<C>(&["eta".to_string(), "rom_logup_gamma".to_string()]);
        let eta = challs[0];
        self.memory.challenges.eta_1 = eta;
        self.memory.challenges.eta_2 = eta * eta;
        self.memory.challenges.eta_3 = eta * eta * eta;
        self.memory.challenges.rom_logup_gamma = challs[1];

        self.add_ram_rom_memory_records_to_wire_4(proving_key);
        self.add_rom_logup_inverses_to_wire_4(proving_key)?;

        // Mask the polynomial when proving in zero-knowledge
        if self.has_zk == ZeroKnowledge::Yes {
            self.mask_polynomial(proving_key.polynomials.witness.lookup_read_counts_mut())?;
            self.mask_polynomial(proving_key.polynomials.witness.lookup_read_tags_mut())?;
            // we do std::mem::take here to avoid borrowing issues with self
            let mut w_4_tmp = std::mem::take(&mut self.memory.w_4);
            self.mask_polynomial(&mut w_4_tmp)?;
            std::mem::swap(&mut self.memory.w_4, &mut w_4_tmp);
        };

        // Commit to lookup argument polynomials and the finalized (i.e. with memory records) fourth wire polynomial
        let lookup_read_counts = CoUtils::commit::<T, C>(
            proving_key
                .polynomials
                .witness
                .lookup_read_counts()
                .as_ref(),
            crs,
        );
        let lookup_read_tags = CoUtils::commit::<T, C>(
            proving_key.polynomials.witness.lookup_read_tags().as_ref(),
            crs,
        );
        let w_4 = CoUtils::commit::<T, C>(self.memory.w_4.as_ref(), crs);

        let opened = T::open_point_many(
            &[lookup_read_counts, lookup_read_tags, w_4],
            self.net,
            self.state,
        )?;

        let lookup_read_counts: C::Affine = opened[0].into();
        let lookup_read_tags: C::Affine = opened[1].into();
        let w_4: C::Affine = opened[2].into();

        transcript
            .send_point_to_verifier::<C>("LOOKUP_READ_COUNTS".to_string(), lookup_read_counts);
        transcript.send_point_to_verifier::<C>("LOOKUP_READ_TAGS".to_string(), lookup_read_tags);
        transcript.send_point_to_verifier::<C>("W_4".to_string(), w_4);

        Ok(())
    }

    // Compute log derivative inverse polynomial and its commitment, if required
    fn commit_to_logderiv_inverses(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        proving_key: &ProvingKey<T, C>,
    ) -> HonkProofResult<()> {
        tracing::trace!("commit_to_logderiv_inverses");

        let [beta, gamma] = transcript
            .get_challenges::<C>(&["beta".to_string(), "gamma".to_string()])
            .try_into()
            .unwrap();
        self.memory.challenges.beta = beta;
        self.memory.challenges.beta_sqr = beta * beta;
        self.memory.challenges.beta_cube = beta * beta * beta;
        self.memory.challenges.gamma = gamma;

        // Compute the inverses used in log-derivative lookup relations
        self.compute_logderivative_inverses(proving_key)?;

        // We moved the committing and opening of the lookup inverses to be at the same time as z_perm

        // Round is done since ultra_honk is no goblin flavor
        Ok(())
    }

    // Compute the permutation grand product polynomial and commit to it.
    fn commit_to_z_perm(
        &mut self,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        proving_key: &ProvingKey<T, C>,
        crs: &ProverCrs<C>,
    ) -> HonkProofResult<()> {
        tracing::trace!("executing grand product computation round");

        self.memory.public_input_delta = self.compute_public_input_delta(proving_key);
        self.compute_grand_product(proving_key)?;

        // Mask the polynomial when proving in zero-knowledge
        if self.has_zk == ZeroKnowledge::Yes {
            // we do std::mem::take here to avoid borrowing issues with self
            let mut lookup_inverses_mut = std::mem::take(&mut self.memory.lookup_inverses);
            self.mask_polynomial(&mut lookup_inverses_mut)?;
            std::mem::swap(&mut self.memory.lookup_inverses, &mut lookup_inverses_mut);
            let mut z_perm_mut = std::mem::take(&mut self.memory.z_perm);
            self.mask_polynomial(&mut z_perm_mut)?;
            std::mem::swap(&mut self.memory.z_perm, &mut z_perm_mut);
        };

        // This is from the previous round, but we open it here with z_perm
        let lookup_inverses = CoUtils::commit::<T, C>(self.memory.lookup_inverses.as_ref(), crs);

        let z_perm = CoUtils::commit::<T, C>(self.memory.z_perm.as_ref(), crs);

        let open = T::open_point_many(&[lookup_inverses, z_perm], self.net, self.state)?;

        let lookup_inverses: C::Affine = open[0].into();
        let z_perm: C::Affine = open[1].into();
        transcript.send_point_to_verifier::<C>("LOOKUP_INVERSES".to_string(), lookup_inverses);
        transcript.send_point_to_verifier::<C>("Z_PERM".to_string(), z_perm);
        Ok(())
    }

    pub(crate) fn prove(
        mut self,
        proving_key: &mut ProvingKey<T, C>,
        transcript: &mut Transcript<TranscriptFieldType, H>,
        crs: &ProverCrs<C>,
        verifying_key: &VerifyingKeyBarretenberg<C>,
    ) -> HonkProofResult<ProverMemory<T, C>> {
        tracing::trace!("Oink prove");

        // Add circuit size public input size and public inputs to transcript
        Self::send_vk_hash_and_public_inputs(transcript, proving_key, verifying_key)?;
        self.commit_to_masking_poly(transcript, proving_key, crs)?;
        // Compute first three wire commitments
        self.commit_to_wires(transcript, proving_key, crs)?;
        // Compute sorted list accumulator and commitment
        self.commit_to_lookup_counts_and_w4(transcript, proving_key, crs)?;

        // Fiat-Shamir: beta & gamma
        self.commit_to_logderiv_inverses(transcript, proving_key)?;
        // Compute grand product(s) and commitments.
        self.commit_to_z_perm(transcript, proving_key, crs)?;

        // Generate relation separators alphas for sumcheck/combiner computation
        self.generate_alphas_round(transcript);

        Ok(self.memory)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Fr, G1Projective};
    use ark_ff::{Field, UniformRand};
    use ark_serialize::CanonicalDeserialize;
    use bytes::Bytes;
    use co_noir_common::{
        keys::proving_key::ProvingKey,
        mpc::{plain::PlainUltraHonkDriver, rep3::Rep3UltraHonkDriver},
        polynomials::entities::Polynomials,
        transcript::Poseidon2Sponge,
    };
    use mpc_core::protocols::rep3::{
        Rep3State, conversion::A2BType, share_field_element, share_field_elements,
    };
    use mpc_net::{ConnectionStats, local::LocalNetwork};
    use std::sync::Mutex;

    /// Records every message a party sends and receives.
    struct RecordingNetwork {
        inner: LocalNetwork,
        events: Mutex<Vec<(bool, Bytes)>>,
    }

    impl Network for RecordingNetwork {
        fn id(&self) -> usize {
            self.inner.id()
        }

        fn send(&self, to: usize, data: Bytes) -> eyre::Result<()> {
            self.events.lock().unwrap().push((true, data.clone()));
            self.inner.send(to, data)
        }

        fn recv(&self, from: usize) -> eyre::Result<Bytes> {
            let data = self.inner.recv(from)?;
            self.events.lock().unwrap().push((false, data.clone()));
            Ok(data)
        }

        fn get_connection_stats(&self) -> ConnectionStats {
            self.inner.get_connection_stats()
        }
    }

    /// One party's view of the opened values: in an opening, a party sends the same share
    /// to both other parties and then receives one share from each of them, so the
    /// opened value is the sum of its own share and the two received ones.
    fn opened_values(events: &[(bool, Bytes)]) -> Vec<Vec<Fr>> {
        events
            .windows(4)
            .filter(|w| w[0].0 && w[1].0 && !w[2].0 && !w[3].0 && w[0].1 == w[1].1)
            .map(|w| {
                let mut opened = Vec::<Fr>::deserialize_uncompressed(w[0].1.as_ref()).unwrap();
                for frame in &w[2..] {
                    let received = Vec::<Fr>::deserialize_uncompressed(frame.1.as_ref()).unwrap();
                    assert_eq!(received.len(), opened.len());
                    for (value, share) in opened.iter_mut().zip(received) {
                        *value += share;
                    }
                }
                opened
            })
            .collect()
    }

    #[test]
    fn lookup_inverse_openings_do_not_reveal_read_tags() {
        const N: usize = 8;
        // All rows are table rows (q_lookup = 0); a set read tag marks a table entry
        // that the private witness used.
        let tags = [0u64, 1, 0, 1, 1, 0, 0, 1].map(Fr::from);
        let mut rng = rand::thread_rng();
        let shared_tags = tags.map(|tag| share_field_element(tag, &mut rng));
        let threads: Vec<_> = LocalNetwork::new_3_parties()
            .into_iter()
            .enumerate()
            .map(|(id, inner)| {
                std::thread::spawn(move || {
                    let net = RecordingNetwork {
                        inner,
                        events: Mutex::new(Vec::new()),
                    };
                    let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                    let mut pk = ProvingKey::<Rep3UltraHonkDriver, G1Projective> {
                        circuit_size: N as u32,
                        polynomials: Polynomials::new(N),
                        ..Default::default()
                    };
                    for (tag, shares) in pk
                        .polynomials
                        .witness
                        .lookup_read_tags_mut()
                        .iter_mut()
                        .zip(shared_tags)
                    {
                        *tag = shares[id];
                    }
                    let mut oink = CoOink::<_, _, Poseidon2Sponge, _>::new(
                        &net,
                        &mut state,
                        ZeroKnowledge::No,
                    );
                    // With all wires and tables zero, both the lookup and the table
                    // term equal gamma, so every denominator is 49.
                    oink.memory.challenges.gamma = Fr::from(7u64);
                    net.events.lock().unwrap().clear();
                    oink.compute_logderivative_inverses(&pk).unwrap();
                    (
                        oink.memory.lookup_inverses.coefficients,
                        net.events.into_inner().unwrap(),
                    )
                })
            })
            .collect();
        let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();

        let inv_49 = Fr::from(49u64).inverse().unwrap();
        for (row, tag) in tags.iter().enumerate() {
            let inverse: Fr = results.iter().map(|(values, _)| values[row].a).sum();
            assert_eq!(inverse, *tag * inv_49, "wrong lookup inverse at row {row}");
        }

        // Everything a single party sees opened during the computation must be
        // independent of the read tags.
        let opened = opened_values(&results[0].1);
        assert!(!opened.is_empty(), "expected a masked inversion opening");
        for values in opened {
            let revealed: Vec<bool> = values.iter().map(|v| !v.is_zero()).collect();
            assert!(
                values.iter().all(|v| !v.is_zero()),
                "an opening reveals the private read tags: {revealed:?}"
            );
        }
    }

    #[test]
    fn lookup_inverses_are_zero_on_inactive_rows() {
        // Rows START..START + 8 enumerate q_lookup, read_tag and a zero or nonzero
        // denominator: the inverse must be 1/d on active rows with d != 0 and zero
        // everywhere else.
        const N: usize = 16;
        const START: usize = 4;
        let mut pk = ProvingKey::<PlainUltraHonkDriver, G1Projective> {
            circuit_size: N as u32,
            polynomials: Polynomials::new(N),
            ..Default::default()
        };
        let gamma = Fr::from(7u64);
        for case in 0..8 {
            let row = START + case;
            pk.polynomials.precomputed.q_lookup_mut()[row] = Fr::from((case & 1) as u64);
            pk.polynomials.witness.lookup_read_tags_mut()[row] = Fr::from(((case >> 1) & 1) as u64);
            if case & 4 != 0 {
                // A zero table term.
                pk.polynomials.precomputed.table_1_mut()[row] = -gamma;
            }
        }
        let mut state = Default::default();
        let mut oink = CoOink::<_, _, Poseidon2Sponge, _>::new(&(), &mut state, ZeroKnowledge::No);
        oink.memory.challenges.gamma = gamma;
        oink.compute_logderivative_inverses(&pk).unwrap();
        for row in 0..N {
            let active = (START..START + 8).contains(&row) && (row - START) & 3 != 0;
            let nonzero_denominator = !(START..START + 8).contains(&row) || (row - START) & 4 == 0;
            let expected = if active && nonzero_denominator {
                (gamma * gamma).inverse().unwrap()
            } else {
                Fr::zero()
            };
            assert_eq!(oink.memory.lookup_inverses[row], expected, "row {row}");
        }
    }

    #[test]
    fn grand_product_batches_independent_multiplications() {
        const N: usize = 32;
        const OUTPUT_LEN: usize = N - 2;
        let mut rng = rand::thread_rng();
        let wires: [Vec<Fr>; 4] =
            std::array::from_fn(|_| (0..N).map(|_| Fr::rand(&mut rng)).collect());
        let sigmas: [Vec<Fr>; 4] =
            std::array::from_fn(|_| (0..N).map(|_| Fr::rand(&mut rng)).collect());
        let ids: [Vec<Fr>; 4] =
            std::array::from_fn(|_| (0..N).map(|_| Fr::rand(&mut rng)).collect());
        let (beta, gamma) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
        let shared_wires = wires.clone().map(|w| share_field_elements(&w, &mut rng));

        let threads: Vec<_> = LocalNetwork::new_3_parties()
            .into_iter()
            .enumerate()
            .map(|(id, inner)| {
                let wires = shared_wires
                    .clone()
                    .map(|[s0, s1, s2]| [s0, s1, s2][id].clone());
                let (sigmas, ids) = (sigmas.clone(), ids.clone());
                std::thread::spawn(move || {
                    let net = RecordingNetwork {
                        inner,
                        events: Mutex::new(Vec::new()),
                    };
                    let sent = |net: &RecordingNetwork| {
                        net.events
                            .lock()
                            .unwrap()
                            .iter()
                            .filter(|(send, _)| *send)
                            .count()
                    };
                    let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                    let mut pk = ProvingKey::<Rep3UltraHonkDriver, G1Projective> {
                        circuit_size: N as u32,
                        polynomials: Polynomials::new(N),
                        final_active_wire_idx: OUTPUT_LEN,
                        ..Default::default()
                    };
                    let [w_l, w_r, w_o, w_4] = wires;
                    let witness = &mut pk.polynomials.witness;
                    witness.w_l_mut().coefficients = w_l;
                    witness.w_r_mut().coefficients = w_r;
                    witness.w_o_mut().coefficients = w_o;
                    let precomputed = &mut pk.polynomials.precomputed;
                    let [s1, s2, s3, s4] = sigmas;
                    precomputed.sigma_1_mut().coefficients = s1;
                    precomputed.sigma_2_mut().coefficients = s2;
                    precomputed.sigma_3_mut().coefficients = s3;
                    precomputed.sigma_4_mut().coefficients = s4;
                    let [i1, i2, i3, i4] = ids;
                    precomputed.id_1_mut().coefficients = i1;
                    precomputed.id_2_mut().coefficients = i2;
                    precomputed.id_3_mut().coefficients = i3;
                    precomputed.id_4_mut().coefficients = i4;

                    // The messages of one multiplication, inversion and opening of the same length.
                    let x = pk.polynomials.witness.w_l().coefficients[..OUTPUT_LEN].to_vec();
                    let before = sent(&net);
                    <Rep3UltraHonkDriver as NoirUltraHonkProver<G1Projective>>::mul_many(
                        &x, &x, &net, &mut state,
                    )
                    .unwrap();
                    let mul = sent(&net) - before;
                    let before = sent(&net);
                    <Rep3UltraHonkDriver as NoirUltraHonkProver<G1Projective>>::inv_many(
                        &x, &net, &mut state,
                    )
                    .unwrap();
                    let inv = sent(&net) - before;
                    let before = sent(&net);
                    <Rep3UltraHonkDriver as NoirUltraHonkProver<G1Projective>>::mul_open_many(
                        &x, &x, &net, &mut state,
                    )
                    .unwrap();
                    let open = sent(&net) - before;

                    let mut oink = CoOink::<_, _, Poseidon2Sponge, _>::new(
                        &net,
                        &mut state,
                        ZeroKnowledge::No,
                    );
                    oink.memory.w_4 = Polynomial::new(w_4);
                    oink.memory.challenges.beta = beta;
                    oink.memory.challenges.gamma = gamma;
                    let before = sent(&net);
                    oink.compute_grand_product(&pk).unwrap();
                    let grand_product = sent(&net) - before;
                    (
                        oink.memory.z_perm.coefficients,
                        [grand_product, mul, inv, open],
                    )
                })
            })
            .collect();
        let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();

        let mut acc = Fr::one();
        for row in 0..OUTPUT_LEN {
            let term = |a: &[Vec<Fr>; 4]| {
                (wires[0][row] + a[0][row] * beta + gamma)
                    * (wires[1][row] + a[1][row] * beta + gamma)
                    * (wires[2][row] + a[2][row] * beta + gamma)
                    * (wires[3][row] + a[3][row] * beta + gamma)
            };
            acc *= term(&ids) / term(&sigmas);
            let z_perm: Fr = results.iter().map(|(z, _)| z[row + 1].a).sum();
            assert_eq!(z_perm, acc, "wrong grand product at row {}", row + 1);
        }

        // The factor products, the numerator and denominator products and the multiplication
        // of both prefix products take one round each, plus the prefix products' inversion and
        // opening, the inversion of the denominator and the final multiplication.
        for (_, [grand_product, mul, inv, open]) in &results {
            assert!(*mul > 0);
            assert_eq!(*grand_product, 4 * mul + 2 * inv + open);
        }
    }
}

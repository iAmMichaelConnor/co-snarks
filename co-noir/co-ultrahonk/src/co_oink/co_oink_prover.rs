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
    constants::{NUM_ZERO_ROWS, PERMUTATION_ARGUMENT_VALUE_SEPARATOR, TRACE_OFFSET},
    crs::ProverCrs,
    honk_curve::HonkCurve,
    honk_proof::{HonkProofError, HonkProofResult, TranscriptFieldType},
    keys::{proving_key::ProvingKey, verification_key::VerifyingKeyBarretenberg},
    mpc::NoirUltraHonkProver,
    polynomials::{
        entities::Polynomials,
        polynomial::{NUM_MASKED_ROWS, Polynomial},
        shared_polynomial::SharedPolynomial,
    },
    transcript::{Transcript, TranscriptHasher},
    types::ZeroKnowledge,
    zk_masking::{SeededZkBlinding, site as zk_site},
};
use mpc_core::MpcState as _;
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
    /// TESTING ONLY (cross-driver determinism tests): when `Some`, all ZK masking values are
    /// drawn deterministically from this source instead of the driver's secure randomness.
    /// `None` (the production path) leaves behavior exactly as before.
    zk_blinding: Option<&'a SeededZkBlinding>,
}

impl<
    'a,
    T: NoirUltraHonkProver<C>,
    C: HonkCurve<TranscriptFieldType>,
    H: TranscriptHasher<TranscriptFieldType>,
    N: Network,
> CoOink<'a, T, C, H, N>
{
    pub(crate) fn new(
        net: &'a N,
        state: &'a mut T::State,
        has_zk: ZeroKnowledge,
        zk_blinding: Option<&'a SeededZkBlinding>,
    ) -> Self {
        Self {
            net,
            state,
            memory: ProverMemory::default(),
            phantom_data: PhantomData,
            phantom_hasher: PhantomData,
            has_zk,
            zk_blinding,
        }
    }

    fn mask_polynomial(
        &mut self,
        polynomial: &mut Polynomial<T::ArithmeticShare>,
        zk_site: &str,
    ) -> HonkProofResult<()> {
        tracing::trace!("mask polynomial");

        // Write random ZK masking values at positions {1, 2, 3} (the disabled head region after
        // the zero row).
        assert!(
            polynomial.coefficients.len() >= NUM_ZERO_ROWS + NUM_MASKED_ROWS as usize,
            "Insufficient space for masking"
        );
        if let Some(blinding) = self.zk_blinding {
            // TESTING ONLY: deterministic masking values, promoted to trivial shares (proof
            // bytes depend on the underlying values, not the share representation).
            let values = blinding.site_fields::<C::ScalarField>(zk_site, NUM_MASKED_ROWS as usize);
            let id = self.state.id();
            for (i, value) in (NUM_ZERO_ROWS..NUM_ZERO_ROWS + NUM_MASKED_ROWS as usize).zip(values)
            {
                polynomial.coefficients[i] = T::promote_to_trivial_share(id, value);
            }
        } else {
            for i in NUM_ZERO_ROWS..NUM_ZERO_ROWS + NUM_MASKED_ROWS as usize {
                polynomial.coefficients[i] = T::rand(self.net, self.state)?;
            }
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

    fn compute_lookup_term(
        challenges: &Challenges<C::ScalarField>,
        id: <T::State as mpc_core::MpcState>::PartyID,
        polynomials: &Polynomials<T::ArithmeticShare, C::ScalarField>,
        i: usize,
    ) -> T::ArithmeticShare {
        tracing::trace!("compute lookup term");

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
        tracing::trace!("compute table term");

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

        let timer = std::time::Instant::now();
        // Every row is a pure, local (communication-free) computation for all drivers, so the
        // rows are computed in parallel and collected in row order; the per-row values are
        // exactly the ones the serial loop computed.
        let id = self.state.id();
        let challenges = &self.memory.challenges;
        let polynomials = &proving_key.polynomials;
        let q_lookup_poly = proving_key.polynomials.precomputed.q_lookup();
        let lookup_read_tags = proving_key.polynomials.witness.lookup_read_tags();
        let (lookup_inverses, q_lookup_mul_read_tag): (Vec<_>, Vec<_>) =
            (0..proving_key.circuit_size as usize)
                .into_par_iter()
                .map(|i| {
                    // Skip the disabled head region: for ZK, the read tags there hold masking
                    // randomness, which must not contribute to the inverses (the head rows of
                    // lookup_inverses receive their own masking when the polynomial is committed).
                    if i < TRACE_OFFSET {
                        return (T::ArithmeticShare::default(), T::ArithmeticShare::default());
                    }
                    let q_lookup = &q_lookup_poly[i];
                    let lookup_read_tag = &lookup_read_tags[i];
                    // The following check cannot easily be done since lookup_read_tag is shared. We prepare q_lookup_mul_read_tag instead and multiply it later to self.memory.lookup_inverses.
                    // if !(q_lookup.is_one() || lookup_read_tag.is_one()) {
                    //     continue;
                    // }
                    debug_assert!(q_lookup.is_one() || q_lookup.is_zero());
                    let mul = T::mul_with_public(
                        C::ScalarField::one() - q_lookup,
                        lookup_read_tag.to_owned(),
                    );
                    let q_mul_read_tag = T::add_with_public(q_lookup.to_owned(), mul, id);

                    // READ_TERMS and WRITE_TERMS are 1, so we skip the loop
                    let read_term = Self::compute_lookup_term(challenges, id, polynomials, i);
                    let write_term = Self::compute_table_term(challenges, polynomials, i);
                    (T::mul_with_public(write_term, read_term), q_mul_read_tag)
                })
                .unzip();
        crate::phase_timing("oink/logderiv/row_loop", timer);
        let timer = std::time::Instant::now();
        self.memory.lookup_inverses = Polynomial::new(T::mul_many(
            &lookup_inverses,
            &q_lookup_mul_read_tag,
            self.net,
            self.state,
        )?);
        crate::phase_timing("oink/logderiv/mul_many", timer);

        // Compute inverse polynomial I in place by inverting the product at each row
        // Note: zeroes are ignored as they are not used anyway
        let timer = std::time::Instant::now();
        CoUtils::batch_invert_leaking_zeros::<T, C, N>(
            self.memory.lookup_inverses.as_mut(),
            self.net,
            self.state,
        )?;
        crate::phase_timing("oink/logderiv/batch_invert", timer);
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

    /// Computes the (local, communication-free) linear terms
    /// `(shared1[i] + beta*pub1[i] + gamma, shared2[i] + beta*pub2[i] + gamma)`
    /// of one grand-product numerator/denominator factor pair and appends them
    /// to `lhs`/`rhs`. The element-wise products `lhs[i] * rhs[i]` of several
    /// such pairs are then computed by the caller in a single batched
    /// `mul_many` round.
    #[expect(clippy::too_many_arguments)]
    fn grand_product_num_denom_operands(
        state: &T::State,
        shared1: &Polynomial<T::ArithmeticShare>,
        shared2: &Polynomial<T::ArithmeticShare>,
        pub1: &Polynomial<C::ScalarField>,
        pub2: &Polynomial<C::ScalarField>,
        beta: &C::ScalarField,
        gamma: &C::ScalarField,
        start_idx: usize,
        output_len: usize,
        lhs: &mut Vec<T::ArithmeticShare>,
        rhs: &mut Vec<T::ArithmeticShare>,
    ) {
        debug_assert!(shared1.len() >= start_idx + output_len);
        debug_assert!(shared2.len() >= start_idx + output_len);
        debug_assert!(pub1.len() >= start_idx + output_len);
        debug_assert!(pub2.len() >= start_idx + output_len);

        // We drop the last element since it is not needed for the grand product
        lhs.reserve(output_len);
        rhs.reserve(output_len);

        // Every row is a pure, local (communication-free) computation for all drivers, so the
        // rows are computed in parallel; the indexed unzip collects them in row order, so
        // lhs/rhs receive exactly the values (and order) the serial loop pushed.
        let id = state.id();
        let (m1s, m2s): (Vec<_>, Vec<_>) = (0..output_len)
            .into_par_iter()
            .map(|i| {
                let idx = i + start_idx;
                let m1 = T::add_with_public(pub1[idx] * beta + gamma, shared1[idx], id);
                let m2 = T::add_with_public(pub2[idx] * beta + gamma, shared2[idx], id);
                (m1, m2)
            })
            .unzip();
        lhs.extend(m1s);
        rhs.extend(m2s);
    }

    fn compute_grand_product(&mut self, proving_key: &ProvingKey<T, C>) -> HonkProofResult<()> {
        tracing::trace!("compute grand product");

        // Barretenberg uses multithreading here

        // Set the domain over which the grand product must be computed. This may be less than the dyadic circuit size, e.g
        // the permutation grand product does not need to be computed beyond the index of the last active wire
        let domain_size = proving_key.final_active_wire_idx + 1;

        // The grand product starts after the disabled/reserved head rows (where lagrange_first
        // lives), preserving the ZK masking values at rows {1, 2, 3}.
        let gp_start = TRACE_OFFSET;
        let active_size = domain_size - gp_start;

        // In Barretenberg circuit size is taken from the q_c polynomial
        // Step (1)
        // Populate `numerator` and `denominator` with the algebra described by Relation

        // The four num/denom factor pairs (denom1, denom2, num1, num2) are
        // independent of each other, so their element-wise multiplications are
        // batched into a single mul_many round: the operands are concatenated,
        // multiplied in one round and the result is split up again. This only
        // changes the communication schedule (4 rounds -> 1); the computed
        // values are identical.
        let out_len = active_size - 1;
        let timer = std::time::Instant::now();
        let mut lhs = Vec::with_capacity(4 * out_len);
        let mut rhs = Vec::with_capacity(4 * out_len);
        Self::grand_product_num_denom_operands(
            self.state,
            proving_key.polynomials.witness.w_l(),
            proving_key.polynomials.witness.w_r(),
            proving_key.polynomials.precomputed.sigma_1(),
            proving_key.polynomials.precomputed.sigma_2(),
            &self.memory.challenges.beta,
            &self.memory.challenges.gamma,
            gp_start,
            out_len,
            &mut lhs,
            &mut rhs,
        );
        Self::grand_product_num_denom_operands(
            self.state,
            proving_key.polynomials.witness.w_o(),
            &self.memory.w_4,
            proving_key.polynomials.precomputed.sigma_3(),
            proving_key.polynomials.precomputed.sigma_4(),
            &self.memory.challenges.beta,
            &self.memory.challenges.gamma,
            gp_start,
            out_len,
            &mut lhs,
            &mut rhs,
        );
        Self::grand_product_num_denom_operands(
            self.state,
            proving_key.polynomials.witness.w_l(),
            proving_key.polynomials.witness.w_r(),
            proving_key.polynomials.precomputed.id_1(),
            proving_key.polynomials.precomputed.id_2(),
            &self.memory.challenges.beta,
            &self.memory.challenges.gamma,
            gp_start,
            out_len,
            &mut lhs,
            &mut rhs,
        );
        Self::grand_product_num_denom_operands(
            self.state,
            proving_key.polynomials.witness.w_o(),
            &self.memory.w_4,
            proving_key.polynomials.precomputed.id_3(),
            proving_key.polynomials.precomputed.id_4(),
            &self.memory.challenges.beta,
            &self.memory.challenges.gamma,
            gp_start,
            out_len,
            &mut lhs,
            &mut rhs,
        );

        crate::phase_timing("oink/gp/operands", timer);

        let timer = std::time::Instant::now();
        let mut products = T::mul_many(&lhs, &rhs, self.net, self.state)?;
        crate::phase_timing("oink/gp/mul_many_pairs", timer);
        debug_assert_eq!(products.len(), 4 * out_len);
        let num2 = products.split_off(3 * out_len);
        let num1 = products.split_off(2 * out_len);
        let denom2 = products.split_off(out_len);
        let denom1 = products;

        // numerator = num1 * num2 and denominator = denom1 * denom2 are
        // independent, so they are batched into a single mul_many round as well
        // (2 rounds -> 1).
        let timer = std::time::Instant::now();
        let mut lhs = num1;
        lhs.extend(denom1);
        let mut rhs = num2;
        rhs.extend(denom2);
        let mut products = T::mul_many(&lhs, &rhs, self.net, self.state)?;
        let denominator = products.split_off(out_len);
        let numerator = products;
        crate::phase_timing("oink/gp/mul_many_numden", timer);

        // Step (2)
        // Compute the accumulating product of the numerator and denominator terms.

        // Do the multiplications of num[i] * num[i-1] and den[i] * den[i-1] in constant rounds.
        // The two prefix products are independent, so they share the rounds of a
        // single batched invocation instead of running sequentially.
        let timer = std::time::Instant::now();
        let mut prefix_products = CoUtils::array_prod_inner_mul_many::<T, C, N>(
            self.net,
            self.state,
            &[numerator, denominator],
        )?
        .into_iter();
        let numerator = prefix_products
            .next()
            .expect("two prefix products were requested");
        let mut denominator = prefix_products
            .next()
            .expect("two prefix products were requested");
        crate::phase_timing("oink/gp/array_prod", timer);

        // invert denominator
        let timer = std::time::Instant::now();
        CoUtils::batch_invert::<T, C, N>(&mut denominator, self.net, self.state)?;
        crate::phase_timing("oink/gp/batch_invert", timer);

        // Step (3) Compute z_perm[i] = numerator[i] / denominator[i]
        let timer = std::time::Instant::now();
        let mul = T::mul_many(&numerator, &denominator, self.net, self.state)?;
        crate::phase_timing("oink/gp/final_mul", timer);

        // z_perm remains 0 at rows 0..=gp_start (row gp_start hosts lagrange_first, where the
        // permutation relation reads z_perm + lagrange_first); for ZK, the masking values at rows
        // {1, 2, 3} are added later when committing.
        let timer = std::time::Instant::now();
        self.memory.z_perm.resize(
            proving_key.circuit_size as usize,
            T::ArithmeticShare::default(),
        );

        for (i, mul) in mul.into_iter().enumerate() {
            self.memory.z_perm[gp_start + i + 1] = mul
        }
        crate::phase_timing("oink/gp/z_perm_writeback", timer);

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
            self.mask_polynomial(
                proving_key.polynomials.witness.w_l_mut(),
                zk_site::OINK_MASK_W_L,
            )?;
            self.mask_polynomial(
                proving_key.polynomials.witness.w_r_mut(),
                zk_site::OINK_MASK_W_R,
            )?;
            self.mask_polynomial(
                proving_key.polynomials.witness.w_o_mut(),
                zk_site::OINK_MASK_W_O,
            )?;
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
        let masking_poly = if let Some(blinding) = self.zk_blinding {
            // TESTING ONLY: deterministic Gemini masking polynomial, promoted to trivial
            // shares (coefficient-index draw order, matching SharedPolynomial::random).
            let values = blinding
                .site_fields::<C::ScalarField>(zk_site::OINK_GEMINI_MASKING_POLY, polynomial_size);
            SharedPolynomial::new(T::promote_to_trivial_shares(self.state.id(), &values))
        } else {
            SharedPolynomial::<T, C>::random(polynomial_size, self.net, self.state)?
        };
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

        let eta = transcript.get_challenge::<C>("eta".to_string());
        self.memory.challenges.eta_1 = eta;
        self.memory.challenges.eta_2 = eta * eta;
        self.memory.challenges.eta_3 = eta * eta * eta;

        self.add_ram_rom_memory_records_to_wire_4(proving_key);

        // Mask the polynomial when proving in zero-knowledge
        if self.has_zk == ZeroKnowledge::Yes {
            self.mask_polynomial(
                proving_key.polynomials.witness.lookup_read_counts_mut(),
                zk_site::OINK_MASK_LOOKUP_READ_COUNTS,
            )?;
            self.mask_polynomial(
                proving_key.polynomials.witness.lookup_read_tags_mut(),
                zk_site::OINK_MASK_LOOKUP_READ_TAGS,
            )?;
            // we do std::mem::take here to avoid borrowing issues with self
            let mut w_4_tmp = std::mem::take(&mut self.memory.w_4);
            self.mask_polynomial(&mut w_4_tmp, zk_site::OINK_MASK_W_4)?;
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
            self.mask_polynomial(&mut lookup_inverses_mut, zk_site::OINK_MASK_LOOKUP_INVERSES)?;
            std::mem::swap(&mut self.memory.lookup_inverses, &mut lookup_inverses_mut);
            let mut z_perm_mut = std::mem::take(&mut self.memory.z_perm);
            self.mask_polynomial(&mut z_perm_mut, zk_site::OINK_MASK_Z_PERM)?;
            std::mem::swap(&mut self.memory.z_perm, &mut z_perm_mut);
        };

        // This is from the previous round, but we open it here with z_perm
        let timer = std::time::Instant::now();
        let lookup_inverses = CoUtils::commit::<T, C>(self.memory.lookup_inverses.as_ref(), crs);

        let z_perm = CoUtils::commit::<T, C>(self.memory.z_perm.as_ref(), crs);

        let open = T::open_point_many(&[lookup_inverses, z_perm], self.net, self.state)?;
        crate::phase_timing("oink/z_perm/commit_open", timer);

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
        let timer = std::time::Instant::now();
        Self::send_vk_hash_and_public_inputs(transcript, proving_key, verifying_key)?;
        crate::phase_timing("oink/vk_and_public_inputs", timer);
        let timer = std::time::Instant::now();
        self.commit_to_masking_poly(transcript, proving_key, crs)?;
        crate::phase_timing("oink/masking_poly", timer);
        // Compute first three wire commitments
        let timer = std::time::Instant::now();
        self.commit_to_wires(transcript, proving_key, crs)?;
        crate::phase_timing("oink/wires_commit", timer);
        // Compute sorted list accumulator and commitment
        let timer = std::time::Instant::now();
        self.commit_to_lookup_counts_and_w4(transcript, proving_key, crs)?;
        crate::phase_timing("oink/lookup_w4_commit", timer);

        // Fiat-Shamir: beta & gamma
        let timer = std::time::Instant::now();
        self.commit_to_logderiv_inverses(transcript, proving_key)?;
        crate::phase_timing("oink/logderiv_round_total", timer);
        // Compute grand product(s) and commitments.
        let timer = std::time::Instant::now();
        self.commit_to_z_perm(transcript, proving_key, crs)?;
        crate::phase_timing("oink/z_perm_round_total", timer);

        // Generate relation separators alphas for sumcheck/combiner computation
        self.generate_alphas_round(transcript);

        Ok(self.memory)
    }
}

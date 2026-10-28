use crate::{
    prelude::{GenericUltraCircuitBuilder, UltraCircuitBuilder},
    types::types::{CycleNode, CyclicPermutation, Mapping, PermutationMapping},
};
use ark_ec::CurveGroup;
use ark_ff::One;
use co_acvm::{PlainAcvmSolver, mpc::NoirWitnessExtensionProtocol};
use co_noir_common::{
    constants::{NUM_WIRES, NUM_ZERO_ROWS, PERMUTATION_ARGUMENT_VALUE_SEPARATOR, TRACE_OFFSET},
    crs::ProverCrs,
    honk_proof::HonkProofResult,
    keys::{plain_proving_key::PlainProvingKey, types::ActiveRegionData},
    polynomials::{
        entities::PrecomputedEntities,
        polynomial::{Polynomial, Polynomials},
    },
};
use num_bigint::BigUint;
use rayon::prelude::*;
use std::sync::Arc;

pub fn create_prover_instance<P: CurveGroup>(
    circuit: &mut UltraCircuitBuilder<P>,
    crs: Arc<ProverCrs<P>>,
    driver: &mut PlainAcvmSolver<P::ScalarField>,
) -> HonkProofResult<PlainProvingKey<P>> {
    tracing::trace!("ProverInstance create");

    assert!(
        circuit.circuit_finalized,
        "the circuit must be finalized before creating the proving key"
    );

    let dyadic_circuit_size = circuit.compute_dyadic_size();

    // Find index of last non-trivial wire value in the trace
    circuit.blocks.compute_offsets(); // compute offset of each block within the trace

    let mut final_active_wire_idx = 0;
    for block in circuit.blocks.get() {
        if !block.is_empty() {
            final_active_wire_idx = block.trace_offset as usize + block.len() - 1;
        }
    }

    tracing::debug!("allocating polynomials object in prover instance...");

    let mut proving_key = PlainProvingKey {
        crs,
        polynomials: Polynomials::new(dyadic_circuit_size),
        public_inputs: Vec::with_capacity(circuit.public_inputs.len()),
        proof_privacy: if circuit.recursion_public_output_indices.is_empty() {
            co_noir_common::keys::proof_privacy::ProofPrivacy::Standard
        } else {
            co_noir_common::keys::proof_privacy::ProofPrivacy::PrivateRecursion
        },
        circuit_size: dyadic_circuit_size as u32,
        final_active_wire_idx,
        ..Default::default()
    };

    populate_memory_records(&mut proving_key, circuit);

    // Construct and add to proving key the wire, selector and copy constraint polynomials
    populate_trace(&mut proving_key, circuit, dyadic_circuit_size);

    // Set the lagrange polynomials (lagrange_first at the first active row after the disabled region)
    proving_key.polynomials.precomputed.lagrange_first_mut()[TRACE_OFFSET] = P::ScalarField::one();
    proving_key.polynomials.precomputed.lagrange_last_mut()[final_active_wire_idx] =
        P::ScalarField::one();

    construct_lookup_polynomials(&mut proving_key, driver, circuit, dyadic_circuit_size)?;

    // Public inputs
    proving_key.num_public_inputs = circuit.blocks.get_pub_inputs().len() as u32;
    proving_key.pub_inputs_offset = circuit.blocks.get_pub_inputs().trace_offset;
    for i in 0..proving_key.num_public_inputs as usize {
        let idx = i + proving_key.pub_inputs_offset as usize;
        proving_key
            .public_inputs
            .push(proving_key.polynomials.witness.w_r()[idx]);
    }

    Ok(proving_key)
}

fn populate_memory_records<P: CurveGroup, T: NoirWitnessExtensionProtocol<P::ScalarField>>(
    proving_key: &mut PlainProvingKey<P>,
    builder: &mut GenericUltraCircuitBuilder<P, T>,
) {
    tracing::trace!("Adding memory records to proving key");

    let ram_rom_offset = builder.blocks.memory.trace_offset;

    proving_key.rom_logup_records.extend(
        builder
            .rom_logup_records
            .iter()
            .map(|index| index + ram_rom_offset),
    );

    for &index in builder.memory_read_records.iter() {
        proving_key.memory_read_records.push(index + ram_rom_offset);
    }

    for &index in builder.memory_write_records.iter() {
        proving_key
            .memory_write_records
            .push(index + ram_rom_offset);
    }
}

fn populate_trace<P: CurveGroup>(
    proving_key: &mut PlainProvingKey<P>,
    builder: &mut UltraCircuitBuilder<P>,
    circuit_size: usize,
) {
    tracing::trace!("Populating trace");

    let mut active_region_data = ActiveRegionData::new();
    let copy_cycles = populate_wires_and_selectors_and_compute_copy_cycles(
        builder,
        &mut proving_key.polynomials,
        &mut active_region_data,
    );
    proving_key.active_region_data = active_region_data;

    compute_permutation_argument_polynomials(
        &mut proving_key.polynomials.precomputed,
        builder,
        copy_cycles,
        circuit_size,
        proving_key.final_active_wire_idx,
    );
}

fn populate_wires_and_selectors_and_compute_copy_cycles<P: CurveGroup>(
    builder: &mut UltraCircuitBuilder<P>,
    polynomials: &mut Polynomials<P::ScalarField>,
    active_region_data: &mut ActiveRegionData,
) -> Vec<CyclicPermutation> {
    // At most one copy cycle per variable.
    let mut copy_cycles = vec![vec![]; builder.variables.len()];

    let wires: &mut [Polynomial<P::ScalarField>; NUM_WIRES] =
        polynomials.witness.get_wires_mut().try_into().unwrap();
    let mut selectors = polynomials.precomputed.get_selectors_mut();

    // For each block in the trace, populate wire polys, copy cycles and selector polys.
    for block in builder.blocks.get() {
        let offset = block.trace_offset as usize;
        let block_size = block.len();
        if block_size > 0 {
            active_region_data.add_range(offset, offset + block_size);
        }

        // Update wire polynomials and copy cycles.
        // NB: The order of row/column loops is arbitrary but needs to be row/column
        // to match old copy_cycle code.
        for block_row_idx in 0..block_size {
            for (wire_idx, wire) in wires.iter_mut().enumerate() {
                // an index into the variables array
                let var_idx = block.wires[wire_idx][block_row_idx] as usize;
                let real_var_idx = *builder
                    .real_variable_index
                    .get(var_idx)
                    .expect("real_variable_index must contain var_idx")
                    as usize;
                let trace_row_idx = block_row_idx + offset;
                // Insert the real witness values from this block into the wire polys
                // at the correct offset.
                wire[trace_row_idx] = builder.get_variable(var_idx);
                // Add the address of the witness value to its corresponding copy cycle.
                // Note that the copy_cycles are indexed by real_variable_indices.
                copy_cycles[real_var_idx].push(CycleNode {
                    wire_index: wire_idx as u32,
                    gate_index: trace_row_idx as u32,
                });
            }
        }

        // Insert the selector values for this block into the selector polynomials at the
        // correct offset.
        // AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/398):
        // implicit arithmetization/flavor consistency.

        for (selector_poly, selector) in selectors.iter_mut().zip(block.selectors.iter()) {
            debug_assert_eq!(selector.len(), block_size);

            for (src, des) in selector.iter().zip(selector_poly.iter_mut().skip(offset)) {
                *des = *src;
            }
        }
    }

    copy_cycles
}

pub fn compute_permutation_argument_polynomials<
    T: NoirWitnessExtensionProtocol<P::ScalarField>,
    P: CurveGroup,
>(
    polys: &mut PrecomputedEntities<Polynomial<P::ScalarField>>,
    circuit: &GenericUltraCircuitBuilder<P, T>,
    copy_cycles: Vec<CyclicPermutation>,
    circuit_size: usize,
    final_active_wire_idx: usize,
) {
    tracing::trace!("Computing permutation argument polynomials");
    let mapping = compute_permutation_mapping(circuit_size, circuit, copy_cycles);

    // Rows [NUM_ZERO_ROWS, first_active_row) are disabled-in-Sumcheck header rows that precede
    // the first circuit block; bb still fills them in the sigma/id polynomials with the identity
    // mapping (see `permutation_lib.hpp`'s full-range init pass), so we must too.

    // Compute Honk-style sigma and ID polynomials from the corresponding mappings
    compute_honk_style_permutation_lagrange_polynomials_from_mapping::<P>(
        polys.get_sigmas_mut(),
        mapping.sigmas,
        final_active_wire_idx,
    );
    compute_honk_style_permutation_lagrange_polynomials_from_mapping::<P>(
        polys.get_ids_mut(),
        mapping.ids,
        final_active_wire_idx,
    );
}

pub(crate) fn compute_permutation_mapping<
    T: NoirWitnessExtensionProtocol<P::ScalarField>,
    P: CurveGroup,
>(
    dyadic_size: usize,
    circuit_constructor: &GenericUltraCircuitBuilder<P, T>,
    wire_copy_cycles: Vec<CyclicPermutation>,
) -> PermutationMapping {
    // Initialize the table of permutations so that every element points to itself
    let mut mapping = PermutationMapping::new(dyadic_size);

    // Represents the idx of a variable in circuit_constructor.variables
    let real_variable_tags = &circuit_constructor.real_variable_tags;

    // Go through each cycle
    for (cycle_idx, cycle) in wire_copy_cycles.iter().enumerate() {
        // We go through the cycle and fill-out/modify `mapping`. Following the generalized permutation algorithm, we
        // take separate care of first/last node handling.
        let cycle_size = cycle.len();
        if cycle_size == 0 {
            continue;
        }

        let first_node = &cycle[0];
        let last_node = &cycle[cycle_size - 1];

        let first_row = first_node.gate_index as usize;
        let first_col = first_node.wire_index as usize;
        let last_row = last_node.gate_index as usize;
        let last_col = last_node.wire_index as usize;

        // First node: id gets tagged with the cycle's variable tag
        let cycle_tag = real_variable_tags[cycle_idx];
        mapping.ids[first_col][first_row].is_tag = true;
        mapping.ids[first_col][first_row].row_index = cycle_tag;

        // Last node: sigma gets tagged and points to tau(tag) instead of wrapping to first node
        mapping.sigmas[last_col][last_row].is_tag = true;
        mapping.sigmas[last_col][last_row].row_index = *circuit_constructor
            .tau
            .get(&cycle_tag)
            .expect("tau must be present  ");

        // All nodes except the last: sigma points to the next node in the cycle
        for node_idx in 0..(cycle_size - 1) {
            let current_node = &cycle[node_idx];
            let next_node = &cycle[node_idx + 1];

            let current_row = current_node.gate_index as usize;
            let current_col = current_node.wire_index as usize;
            // Point current node to next node.
            mapping.sigmas[current_col][current_row].row_index = next_node.gate_index;
            mapping.sigmas[current_col][current_row].column_index = next_node.wire_index;
        }
    }

    // Add information about public inputs so that the cycles can be altered later; See the construction of the
    // permutation polynomials for details. This _only_ effects sigma_0, the 0th sigma polynomial, as the structure of
    // the algorithm only requires modifying sigma_0(i) where i is a public input row. (Note that at such a row, the
    // non-zero wire values are in w_l and w_r, and both of them contain the public input.)
    let num_public_inputs = circuit_constructor.public_inputs.len();
    let pub_inputs_offset = circuit_constructor.blocks.pub_inputs.trace_offset as usize;

    for i in 0..num_public_inputs {
        let idx = i + pub_inputs_offset;
        mapping.sigmas[0][idx].row_index = idx as u32;
        mapping.sigmas[0][idx].column_index = 0;
        mapping.sigmas[0][idx].is_public_input = true;
        if mapping.sigmas[0][idx].is_tag {
            tracing::warn!("MAPPING IS BOTH A TAG AND A PUBLIC INPUT");
        }
    }

    mapping
}

fn compute_honk_style_permutation_lagrange_polynomials_from_mapping<P: CurveGroup>(
    permutation_polynomials: &mut [Polynomial<P::ScalarField>],
    permutation_mappings: Mapping,
    final_active_wire_idx: usize,
) {
    // SEPARATOR ensures that the evaluations of `id_i` (`sigma_i`) and `id_j`(`sigma_j`) polynomials on the boolean
    // hypercube do not intersect for i != j.
    assert!(permutation_polynomials[0].len() < PERMUTATION_ARGUMENT_VALUE_SEPARATOR as usize);

    // The sigma/id polynomials carry the identity permutation on every row of the active trace range
    // [NUM_ZERO_ROWS, final_active_wire_idx] (this includes the disabled head rows and the zero row at
    // TRACE_OFFSET, which do not belong to any trace block), overridden by cycle linkages/tags and the
    // public input marks recorded in the mapping. They are zero outside the active range.
    // Each row's value depends only on that row's mapping entry, so the wires and the
    // rows within a wire parallelize freely (bb multithreads here too).
    permutation_polynomials
        .par_iter_mut()
        .zip(permutation_mappings.par_iter())
        .for_each(|(current_permutation_poly, mapping)| {
            current_permutation_poly.coefficients[NUM_ZERO_ROWS..=final_active_wire_idx]
                .par_iter_mut()
                .zip(mapping[NUM_ZERO_ROWS..=final_active_wire_idx].par_iter())
                .with_min_len(1 << 12)
                .for_each(|(eval, entry)| {
                    let current_row_idx = entry.row_index;
                    let current_col_idx = entry.column_index;
                    *eval = if entry.is_public_input {
                        // We intentionally want to break the cycles of the public input variables as an optimization.
                        // During the witness generation, both the left and right wire polynomials (w_l and w_r
                        // respectively) at row idx i contain the i-th public input. Let n = SEPARATOR. The initial
                        // CyclicPermutation created for these variables copy-constrained to the ith public input therefore
                        // always starts with (i) -> (n+i), followed by the indices of the variables in the "real" gates
                        // (i.e., the gates not merely present to set-up inputs).
                        //
                        // We change this and make i point to -(i+1). This choice "unbalances" the grand product argument,
                        // so that the final result of the grand product is _not_ 1. These indices are chosen so they can
                        // easily be computed by the verifier (just knowing the public inputs), and this algorithm
                        // constitutes a specification of the "permutation argument with public inputs" optimization due to
                        // Gabizon and Williamson. The verifier can expect the final product to be equal to the "public
                        // input delta" that is computed in <honk/library/grand_product_delta.hpp>.
                        -P::ScalarField::from(
                            current_row_idx
                                + 1
                                + PERMUTATION_ARGUMENT_VALUE_SEPARATOR * current_col_idx,
                        )
                    } else if entry.is_tag {
                        // Set evaluations to (arbitrary) values disjoint from non-tag values
                        P::ScalarField::from(
                            PERMUTATION_ARGUMENT_VALUE_SEPARATOR * NUM_WIRES as u32
                                + current_row_idx,
                        )
                    } else {
                        // For the regular permutation we simply point to the next location by setting the
                        // evaluation to its idx
                        P::ScalarField::from(
                            current_row_idx
                                + PERMUTATION_ARGUMENT_VALUE_SEPARATOR * current_col_idx,
                        )
                    };
                });
        });
}

pub fn construct_lookup_table_polynomials<
    T: NoirWitnessExtensionProtocol<P::ScalarField>,
    P: CurveGroup,
>(
    table_polynomials: &mut [Polynomial<P::ScalarField>],
    circuit: &GenericUltraCircuitBuilder<P, T>,
    dyadic_circuit_size: usize,
) {
    // Create lookup table polynomials which interpolate each table column. The table data is placed
    // at the lookup block's trace offset (which is always past the disabled head region), aligned
    // with the lookup read counts/tags.
    let mut offset = circuit.blocks.lookup.trace_offset as usize;
    assert!(dyadic_circuit_size >= offset + circuit.get_tables_size());

    for table in circuit.lookup_tables.iter() {
        let table_index = table.table_index;

        for i in 0..table.len() {
            table_polynomials[0][offset] = table.column_1[i];
            table_polynomials[1][offset] = table.column_2[i];
            table_polynomials[2][offset] = table.column_3[i];
            table_polynomials[3][offset] = P::ScalarField::from(table_index as u64);
            offset += 1;
        }
    }
}

pub fn construct_lookup_read_counts<
    T: NoirWitnessExtensionProtocol<P::ScalarField>,
    P: CurveGroup,
>(
    driver: &mut T,
    witness: &mut [Polynomial<T::ArithmeticShare>; 2],
    circuit: &mut GenericUltraCircuitBuilder<P, T>,
) -> eyre::Result<()> {
    // Read counts/tags track which table entries have been read; they are aligned with the
    // table data at the lookup block's trace offset.
    //
    // L2 batching (CHUNKED): the expensive step is converting each shared gate's secret table
    // index into a one-hot vector (a2b bit-decompose + level-doubling — communication). Doing
    // every gate at once is the fewest rounds but materialises ALL one-hot vectors
    // simultaneously (peak memory ∝ Σ_gates table_size — which OOMs the host on lookup-dense
    // circuits, e.g. sha256 ≥ 2^18 needs hundreds of GB). Instead we process the shared-index
    // gates in chunks of `driver.lookup_read_count_batch_size()`: each chunk converts ≤ K
    // indices, adds their read counts (local sums), and folds their read-tag contributions
    // (1 − ohv) into a per-table running product carried across chunks. Peak memory is thus
    // bounded by the chunk (∝ K) at the cost of ~gates/K× more rounds. `None` => a single
    // chunk (the original unbounded behaviour). The reconstructed read counts and read tags
    // are identical for every chunk size — only the per-reshare masking (hence the individual
    // share splits) differs, not the values, so the proof/VK are byte-identical.

    let one = T::AcvmType::from(P::ScalarField::one());

    // Local descriptor of one shared-index read: its secret index, the table length (= the
    // one-hot vector length), the read-count polynomial offset, and the owning table.
    struct SharedRead<S> {
        index: S,
        len: usize,
        offset: usize,
        table: usize,
    }

    // --- Pass 1: resolve every gate's table index. Public-index reads accumulate now
    // (local, comms-free); shared-index reads are queued with routing info for the chunked
    // one-hot pass below (exactly the indices the previous implementation batched). ---
    let n_tables = circuit.lookup_tables.len();
    let mut shared: Vec<SharedRead<T::ArithmeticShare>> = Vec::new();
    let mut public_reads: Vec<Vec<usize>> = vec![Vec::new(); n_tables];
    let mut table_offsets: Vec<usize> = Vec::with_capacity(n_tables);

    let mut table_offset = circuit.blocks.lookup.trace_offset as usize;
    for (t, table) in circuit.lookup_tables.iter_mut().enumerate() {
        // we need the index_map hash table in this case
        if table.requires_index_map() {
            table.initialize_index_map();
        }
        let len = table.len();
        table_offsets.push(table_offset);

        for gate_data in table.lookup_gates.iter() {
            // find the index of the entry in the table (local: a public-coefficient
            // linear map of the gate's keys)
            let index_in_table = gate_data.calculate_table_index(
                driver,
                table.use_twin_keys,
                table.column_2_step_size,
            );

            if T::is_shared(&index_in_table) {
                let index_in_table = if table.requires_index_map() {
                    let column = &table.column_1;
                    let mut index = T::public_zero();
                    let index_vec = vec![index_in_table; column.len()];
                    let table_vec: Vec<T::AcvmType> =
                        column.iter().map(|v| T::AcvmType::from(*v)).collect();
                    let cmp = T::equal_many(driver, &index_vec, &table_vec)?;
                    for (i, val) in cmp.into_iter().enumerate() {
                        let mul = T::mul_with_public(driver, P::ScalarField::from(i as u64), val);
                        index = T::add(driver, index, mul);
                    }
                    T::get_shared(&index).expect("Already checked it is shared")
                } else {
                    T::get_shared(&index_in_table).expect("Already checked it is shared")
                };
                shared.push(SharedRead {
                    index: index_in_table,
                    len,
                    offset: table_offset,
                    table: t,
                });
            } else {
                // Index is public
                let index_in_table: BigUint = T::get_public(&index_in_table)
                    .expect("Already checked it is public")
                    .into();
                let index_in_table = if table.requires_index_map() {
                    table.index_map[index_in_table.into()]
                } else {
                    usize::try_from(index_in_table).expect("index is too large for usize?")
                };

                let index_in_poly = table_offset + index_in_table;

                // increment the read count at the corresponding index in the full polynomial
                let mut wit0 = T::AcvmType::from(witness[0][index_in_poly].to_owned());
                driver.add_assign_with_public(P::ScalarField::one(), &mut wit0);
                witness[0][index_in_poly] = driver.get_as_shared(&wit0); // Read count

                // Public read => read tag is 1 at this entry; applied (idempotently, as an
                // OR term) after the per-table tag products below.
                public_reads[t].push(index_in_poly);
            }
        }
        table_offset += len; // set the offset of the next table within the polynomials
    }

    // --- Chunked one-hot pass: convert shared indices to OHVs in batches of ≤ K, adding read
    // counts and folding a per-table running product of (1 − ohv) for the read tags. ---
    // tag_carry[t] = Π (1 − ohv) over the shared gates of table `t` processed so far
    // (empty = none yet), length = table length.
    let mut tag_carry: Vec<Vec<T::AcvmType>> = vec![Vec::new(); n_tables];

    let mut remaining = shared.as_slice();
    while !remaining.is_empty() {
        let chunk_len = co_acvm::mpc::lookup_read_count_batch_len::<P::ScalarField>(
            driver.lookup_read_count_batch_size(),
            remaining.iter().map(|s| s.len),
        );
        let (chunk, rest) = remaining.split_at(chunk_len);
        remaining = rest;
        let idxs: Vec<T::ArithmeticShare> = chunk.iter().map(|s| s.index.to_owned()).collect();
        let lens: Vec<usize> = chunk.iter().map(|s| s.len).collect();
        // ONE batched index -> OHV conversion for this chunk. (Empty batch => no driver call:
        // circuits without shared lookup indices stay comms-free.)
        let ohvs = driver.one_hot_vector_from_shared_index_many(&idxs, &lens)?;

        // Per-table operand lists for this chunk's tag reduction, seeded with the running
        // carry so the product spans every chunk.
        let mut operands: Vec<Vec<Vec<T::AcvmType>>> = Vec::with_capacity(n_tables);
        for carry in tag_carry.iter_mut() {
            let mut ops: Vec<Vec<T::AcvmType>> = Vec::new();
            if !carry.is_empty() {
                ops.push(std::mem::take(carry));
            }
            operands.push(ops);
        }

        for (s, ohv) in chunk.iter().zip(ohvs.into_iter()) {
            // Read count: increment the count at the read index across the table's range
            // (local commutative sum, comms-free).
            for (src, des) in ohv
                .iter()
                .zip(witness[0].iter_mut().skip(s.offset).take(s.len))
            {
                let wit = T::AcvmType::from(des.to_owned());
                let src = T::AcvmType::from(src.to_owned());
                let added = driver.add(wit, src);
                *des = driver.get_as_shared(&added);
                // Read count
            }
            // Read-tag operand: the complement 1 − ohv (truncated to the table length,
            // matching the read-count range), a local `public − share`.
            let comp: Vec<T::AcvmType> = ohv
                .iter()
                .take(s.len)
                .map(|x| driver.sub(one.clone(), T::AcvmType::from(x.to_owned())))
                .collect();
            operands[s.table].push(comp);
        }

        // Reduce each table's [carry?] + this chunk's complements into the new carry, batching
        // all tables' pairwise products into one mul_many per tree level.
        let reduced = batched_elementwise_product::<T, P>(driver, operands)?;
        for (carry, prod) in tag_carry.iter_mut().zip(reduced) {
            *carry = prod;
        }
    }

    // --- Emit read tags: 1 − Π(1 − ohv) for tables with shared reads, then OR in the public
    // reads (idempotent set-to-1). ---
    for (t, carry) in tag_carry.into_iter().enumerate() {
        let offset = table_offsets[t];
        for (j, p) in carry.into_iter().enumerate() {
            let tag = driver.sub(one.clone(), p);
            witness[1][offset + j] = driver.get_as_shared(&tag);
        }
        for &idx in &public_reads[t] {
            witness[1][idx] = driver.promote_to_trivial_share(P::ScalarField::one());
        }
    }
    Ok(())
}

/// Reduces each table's list of equal-length operand vectors to their elementwise product,
/// batching every table's pairwise multiplications into ONE `mul_many` per tree level (so the
/// whole reduction costs `max_t ⌈log2 n_t⌉` rounds rather than `Σ_t (n_t − 1)`). A table with
/// no operands yields an empty vector; with one operand, that operand unchanged. All operands
/// within a table must share a length. This is the batched OR-tree that
/// [`construct_lookup_read_counts`] uses to turn per-gate `1 − ohv` complements into the
/// `Π(1 − ohv)` whose complement is the read tag (`OR` is associative/commutative/idempotent
/// on `{0,1}`, so the value is independent of the pairing/chunking).
fn batched_elementwise_product<T, P>(
    driver: &mut T,
    mut operands: Vec<Vec<Vec<T::AcvmType>>>,
) -> eyre::Result<Vec<Vec<T::AcvmType>>>
where
    T: NoirWitnessExtensionProtocol<P::ScalarField>,
    P: CurveGroup,
{
    loop {
        let mut lhs: Vec<T::AcvmType> = Vec::new();
        let mut rhs: Vec<T::AcvmType> = Vec::new();
        let mut layout: Vec<(usize, bool)> = Vec::with_capacity(operands.len());
        let mut any = false;
        for ops in &operands {
            let m = ops.len();
            if m <= 1 {
                layout.push((0, m == 1));
                continue;
            }
            any = true;
            let n_pairs = m / 2;
            for p in 0..n_pairs {
                lhs.extend_from_slice(&ops[2 * p]);
                rhs.extend_from_slice(&ops[2 * p + 1]);
            }
            layout.push((n_pairs, m % 2 == 1));
        }
        if !any {
            break;
        }
        let products = driver.mul_many(&lhs, &rhs)?;
        let mut pit = products.into_iter();
        for (ops, (n_pairs, leftover)) in operands.iter_mut().zip(layout) {
            if n_pairs == 0 {
                continue;
            }
            let len = ops[0].len();
            let mut new_ops = Vec::with_capacity(n_pairs + usize::from(leftover));
            for _ in 0..n_pairs {
                new_ops.push(pit.by_ref().take(len).collect::<Vec<_>>());
            }
            if leftover {
                new_ops.push(ops.last().expect("leftover exists").clone());
            }
            *ops = new_ops;
        }
    }
    Ok(operands
        .into_iter()
        .map(|mut ops| {
            if ops.is_empty() {
                Vec::new()
            } else {
                ops.swap_remove(0)
            }
        })
        .collect())
}

pub fn construct_lookup_polynomials<P: CurveGroup>(
    proving_key: &mut PlainProvingKey<P>,
    driver: &mut PlainAcvmSolver<P::ScalarField>,
    circuit: &mut UltraCircuitBuilder<P>,
    dyadic_circuit_size: usize,
) -> eyre::Result<()> {
    construct_lookup_table_polynomials(
        proving_key
            .polynomials
            .precomputed
            .get_table_polynomials_mut(),
        circuit,
        dyadic_circuit_size,
    );
    construct_lookup_read_counts(
        driver,
        proving_key
            .polynomials
            .witness
            .lookup_read_counts_and_tags_mut()
            .try_into()
            .unwrap(),
        circuit,
    )?;
    Ok(())
}

use crate::{
    prelude::{GenericUltraCircuitBuilder, UltraCircuitBuilder},
    types::types::{CycleNode, CyclicPermutation, Mapping, PermutationMapping},
};
use ark_ec::CurveGroup;
use ark_ff::One;
use co_acvm::{PlainAcvmSolver, mpc::NoirWitnessExtensionProtocol};
use co_noir_common::{
    constants::{NUM_WIRES, NUM_ZERO_ROWS, PERMUTATION_ARGUMENT_VALUE_SEPARATOR},
    crs::ProverCrs,
    honk_proof::HonkProofResult,
    keys::{plain_proving_key::PlainProvingKey, types::ActiveRegionData},
    polynomials::{
        entities::PrecomputedEntities,
        polynomial::{NUM_DISABLED_ROWS_IN_SUMCHECK, Polynomial, Polynomials},
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
        circuit_size: dyadic_circuit_size as u32,
        final_active_wire_idx,
        proof_privacy: circuit.proof_privacy(),
        ..Default::default()
    };

    populate_memory_records(&mut proving_key, circuit);

    // Construct and add to proving key the wire, selector and copy constraint polynomials
    populate_trace(&mut proving_key, circuit, dyadic_circuit_size);

    // Set the lagrange polynomials. lagrange_first marks row NUM_DISABLED_ROWS_IN_SUMCHECK, the
    // row immediately preceding the first real trace content (rows before it are disabled in
    // Sumcheck for ZK masking/shift compatibility).
    proving_key.polynomials.precomputed.lagrange_first_mut()
        [NUM_DISABLED_ROWS_IN_SUMCHECK as usize] = P::ScalarField::one();
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

    for &index in builder.memory_read_records.iter() {
        proving_key.memory_read_records.push(index + ram_rom_offset);
    }

    for &index in builder.memory_write_records.iter() {
        proving_key
            .memory_write_records
            .push(index + ram_rom_offset);
    }

    for &index in builder.rom_logup_records.iter() {
        proving_key.rom_logup_records.push(index + ram_rom_offset);
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
        &proving_key.active_region_data,
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
    active_region_data: &ActiveRegionData,
) {
    tracing::trace!("Computing permutation argument polynomials");
    let mapping = compute_permutation_mapping(circuit_size, circuit, copy_cycles);

    // Rows [NUM_ZERO_ROWS, first_active_row) are disabled-in-Sumcheck header rows that precede
    // the first circuit block; bb still fills them in the sigma/id polynomials with the identity
    // mapping (see `permutation_lib.hpp`'s full-range init pass), so we must too.
    let first_active_row = circuit.blocks.pub_inputs.trace_offset as usize;

    // Compute Honk-style sigma and ID polynomials from the corresponding mappings
    compute_honk_style_permutation_lagrange_polynomials_from_mapping::<P>(
        polys.get_sigmas_mut(),
        mapping.sigmas,
        active_region_data,
        first_active_row,
    );
    compute_honk_style_permutation_lagrange_polynomials_from_mapping::<P>(
        polys.get_ids_mut(),
        mapping.ids,
        active_region_data,
        first_active_row,
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
    active_region_data: &ActiveRegionData,
    first_active_row: usize,
) {
    // SEPARATOR ensures that the evaluations of `id_i` (`sigma_i`) and `id_j`(`sigma_j`) polynomials on the boolean
    // hypercube do not intersect for i != j.
    assert!(permutation_polynomials[0].len() < PERMUTATION_ARGUMENT_VALUE_SEPARATOR as usize);

    // The wires are independent, and each row's value depends only on that row's mapping entry, so the
    // wires and the rows of each active range are filled in parallel. The active ranges cover exactly the
    // rows `active_region_data.get_idx(i)` for `i < active_region_data.size()`.
    permutation_polynomials
        .par_iter_mut()
        .zip(permutation_mappings.par_iter())
        .enumerate()
        .for_each(|(wire_idx, (current_permutation_poly, mapping))| {
            // The disabled-in-Sumcheck header rows before the first circuit block are outside any
            // copy cycle, so the mapping there is still the untouched self-referencing identity from
            // `PermutationMapping::new`; write that identity value explicitly to match bb.
            for poly_idx in NUM_ZERO_ROWS..first_active_row {
                current_permutation_poly[poly_idx] = P::ScalarField::from(
                    poly_idx as u32 + PERMUTATION_ARGUMENT_VALUE_SEPARATOR * wire_idx as u32,
                );
            }
            for &(start, end) in active_region_data.get_ranges() {
                current_permutation_poly.coefficients[start..end]
                    .par_iter_mut()
                    .zip(mapping[start..end].par_iter())
                    .with_min_len(1 << 12)
                    .for_each(|(eval, entry)| {
                        let current_row_idx = entry.row_index;
                        let current_col_idx = entry.column_index;
                        let current_is_tag = entry.is_tag;
                        let current_is_public_input = entry.is_public_input;
                        if current_is_public_input {
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
                            *eval = -P::ScalarField::from(
                                current_row_idx
                                    + 1
                                    + PERMUTATION_ARGUMENT_VALUE_SEPARATOR * current_col_idx,
                            );
                        } else if current_is_tag {
                            // Set evaluations to (arbitrary) values disjoint from non-tag values
                            *eval = P::ScalarField::from(
                                PERMUTATION_ARGUMENT_VALUE_SEPARATOR * NUM_WIRES as u32
                                    + current_row_idx,
                            );
                        } else {
                            // For the regular permutation we simply point to the next location by setting the
                            // evaluation to its idx
                            *eval = P::ScalarField::from(
                                current_row_idx
                                    + PERMUTATION_ARGUMENT_VALUE_SEPARATOR * current_col_idx,
                            );
                        }
                    });
            }
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
    // Create lookup selector polynomials which interpolate each table column, starting at the row
    // where the `lookup` gate block actually begins in the execution trace (matching bb's
    // `construct_lookup_table_polynomials`, which starts at `circuit.blocks.lookup.trace_offset()`).
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
    // A shared-index read: the shared index, the table length, the table's offset in the
    // polynomials and the table.
    struct SharedRead<S> {
        index: S,
        len: usize,
        offset: usize,
        table: usize,
    }

    // Starts at the row where the `lookup` gate block begins in the trace, matching bb's
    // `construct_lookup_read_counts` (`circuit.blocks.lookup.trace_offset()`), and consistent with
    // `construct_lookup_table_polynomials` above.
    let mut table_offset = circuit.blocks.lookup.trace_offset as usize;
    assert!(witness[0].len() >= table_offset + circuit.get_tables_size());

    // First pass: compute the index of every gate. Reads at public indices are counted right
    // away; reads at shared indices are collected, so that their one-hot vectors can be built in
    // batches.
    let num_tables = circuit.lookup_tables.len();
    let mut shared_reads = Vec::new();
    let mut public_reads = vec![Vec::new(); num_tables];
    let mut table_offsets = Vec::with_capacity(num_tables);
    for (table_idx, table) in circuit.lookup_tables.iter_mut().enumerate() {
        // we need the index_map hash table in this case
        if table.requires_index_map() {
            table.initialize_index_map();
        }
        table_offsets.push(table_offset);

        for gate_data in table.lookup_gates.iter() {
            // convert lookup gate data to an array of three field elements, one for each of the 3 columns
            // let table_entry = gate_data.to_table_components(table.use_twin_keys); // We calculate indices from keys

            // find the index of the entry in the table
            // let index_in_table = table.index_map[table_entry]; // We calculate indices from keys
            let index_in_table = gate_data.calculate_table_index(
                driver,
                table.use_twin_keys,
                table.column_2_step_size,
            );

            if T::is_shared(&index_in_table) {
                let index_in_table = if table.requires_index_map() {
                    let table = &table.column_1;
                    let mut index = T::public_zero();
                    let index_vec = vec![index_in_table; table.len()];
                    let table_vec: Vec<T::AcvmType> =
                        table.iter().map(|v| T::AcvmType::from(*v)).collect();
                    let cmp = T::equal_many(driver, &index_vec, &table_vec)?;
                    for (i, val) in cmp.into_iter().enumerate() {
                        let mul = T::mul_with_public(driver, P::ScalarField::from(i as u64), val);
                        index = T::add(driver, index, mul);
                    }
                    T::get_shared(&index).expect("Already checked it is shared")
                } else {
                    T::get_shared(&index_in_table).expect("Already checked it is shared")
                };
                shared_reads.push(SharedRead {
                    index: index_in_table,
                    len: table.len(),
                    offset: table_offset,
                    table: table_idx,
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

                // The read tag is set to 1 below
                public_reads[table_idx].push(index_in_poly);
            }
        }
        table_offset += table.len(); // set the offset of the next table within the polynomials
    }

    // Second pass: build the one-hot vectors of the shared-index reads in batches. The read
    // counts are sums of the one-hot vectors. The read tag of an entry is 1 if it has been read
    // at least once, i.e., 1 - prod(1 - ohv) over the table's reads, where each table's running
    // product is carried from batch to batch.
    let one = T::AcvmType::from(P::ScalarField::one());
    let mut not_read: Vec<Vec<T::AcvmType>> = vec![Vec::new(); num_tables];
    let mut remaining = shared_reads.as_slice();
    while !remaining.is_empty() {
        let batch_len = co_acvm::mpc::lookup_read_count_batch_len::<P::ScalarField>(
            driver.lookup_read_count_batch_size(),
            remaining.iter().map(|read| read.len),
        );
        let (batch, rest) = remaining.split_at(batch_len);
        remaining = rest;

        let indices = batch
            .iter()
            .map(|read| read.index.to_owned())
            .collect::<Vec<_>>();
        let lens = batch.iter().map(|read| read.len).collect::<Vec<_>>();
        let ohvs = driver.one_hot_vector_from_shared_index_many(&indices, &lens)?;

        // The factors of each table's product: its running product and 1 - ohv of its reads
        let mut factors = not_read
            .iter_mut()
            .map(|carry| {
                if carry.is_empty() {
                    Vec::new()
                } else {
                    vec![std::mem::take(carry)]
                }
            })
            .collect::<Vec<_>>();
        for (read, ohv) in batch.iter().zip(ohvs) {
            // increment the read count at the corresponding index in the full polynomial
            for (src, des) in ohv
                .iter()
                .zip(witness[0].iter_mut().skip(read.offset).take(read.len))
            {
                let wit = T::AcvmType::from(des.to_owned());
                let src = T::AcvmType::from(src.to_owned());
                let added = driver.add(wit, src);
                *des = driver.get_as_shared(&added);
            }
            factors[read.table].push(
                ohv.into_iter()
                    .take(read.len)
                    .map(|x| driver.sub(one.clone(), T::AcvmType::from(x)))
                    .collect(),
            );
        }
        not_read = elementwise_products::<T, P>(driver, factors)?;
    }

    for ((offset, not_read), public_reads) in
        table_offsets.into_iter().zip(not_read).zip(public_reads)
    {
        // Read tag is 1 if entry has been read 1 or more times
        for (j, not_read) in not_read.into_iter().enumerate() {
            let tag = driver.sub(one.clone(), not_read);
            witness[1][offset + j] = driver.get_as_shared(&tag);
        }
        for index_in_poly in public_reads {
            witness[1][index_in_poly] = driver.promote_to_trivial_share(P::ScalarField::one());
        }
    }
    Ok(())
}

/// Computes the elementwise product of each list of equally long vectors (an empty list gives an
/// empty vector), as a product tree in which each level of all lists is one `mul_many`.
fn elementwise_products<T: NoirWitnessExtensionProtocol<P::ScalarField>, P: CurveGroup>(
    driver: &mut T,
    mut lists: Vec<Vec<Vec<T::AcvmType>>>,
) -> eyre::Result<Vec<Vec<T::AcvmType>>> {
    while lists.iter().any(|list| list.len() > 1) {
        let mut lhs = Vec::new();
        let mut rhs = Vec::new();
        for list in lists.iter() {
            for [left, right] in list.as_chunks::<2>().0 {
                lhs.extend_from_slice(left);
                rhs.extend_from_slice(right);
            }
        }
        let mut products = driver.mul_many(&lhs, &rhs)?.into_iter();
        for list in lists.iter_mut() {
            let odd = (list.len() % 2 == 1).then(|| list.pop()).flatten();
            let mut next = list
                .as_chunks::<2>()
                .0
                .iter()
                .map(|[left, _]| products.by_ref().take(left.len()).collect())
                .collect::<Vec<_>>();
            next.extend(odd);
            *list = next;
        }
    }
    Ok(lists
        .into_iter()
        .map(|list| list.into_iter().next().unwrap_or_default())
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

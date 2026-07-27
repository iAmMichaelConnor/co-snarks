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
    // Read counts/tags track which table entries have been read; they are aligned with the table
    // data at the lookup block's trace offset.
    //
    // Two-pass shape (L2 batching): pass 1 computes every gate's table index (a local
    // linear map of the gate's keys) and collects all SHARED indices, in gate order, so
    // that the expensive index -> one-hot-vector conversion runs as ONE batched driver
    // call for ALL gates of ALL tables (one a2b_many bit-decomposition + one bit
    // injection instead of one Yao conversion + one injection round PER gate). Pass 2
    // then replays the gates in exactly the original order, consuming the precomputed
    // OHVs: every witness write (count sums, tag assigns/cmuxes) happens with the same
    // values in the same order as the previous per-gate implementation.

    // Pass 1: collect shared indices (+ their table sizes) in gate order.
    let mut shared_indices: Vec<T::ArithmeticShare> = Vec::new();
    let mut shared_lens: Vec<usize> = Vec::new();
    for table in circuit.lookup_tables.iter_mut() {
        // we need the index_map hash table in this case
        if table.requires_index_map() {
            table.initialize_index_map();
        }

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
                shared_indices.push(index_in_table);
                shared_lens.push(table.len());
            }
        }
    }

    // ONE batched index -> OHV conversion for all gates of all tables. (Empty batch =>
    // no driver call at all: circuits without shared lookup indices stay comms-free.)
    let mut ohvs = driver
        .one_hot_vector_from_shared_index_many(&shared_indices, &shared_lens)?
        .into_iter();
    drop(shared_indices);

    // Pass 2: replay the gates in original order. Read counts are local commutative
    // sums (written inline, comms-free). Read tags are the elementwise OR over all
    // gates' read positions; the shared OHVs are collected here and OR-reduced in ONE
    // batched OR-tree afterwards (see `compute_read_tags_or_tree`), collapsing the tag
    // communication from Σ_t (g_t − 1) sequential reshares to max_t ⌈log2 g_t⌉.
    let mut tag_tables: Vec<TagReadTable<T::ArithmeticShare>> =
        Vec::with_capacity(circuit.lookup_tables.len());
    let mut table_offset = circuit.blocks.lookup.trace_offset as usize;
    for table in circuit.lookup_tables.iter_mut() {
        let len = table.len();
        let mut shared_ohvs: Vec<Vec<T::ArithmeticShare>> = Vec::new();
        let mut public_reads: Vec<usize> = Vec::new();

        for gate_data in table.lookup_gates.iter() {
            let index_in_table = gate_data.calculate_table_index(
                driver,
                table.use_twin_keys,
                table.column_2_step_size,
            );

            if T::is_shared(&index_in_table) {
                let mut ohv = ohvs
                    .next()
                    .expect("pass 1 collected an OHV for every shared-index gate");

                // increment the read count at the corresponding index in the full polynomial
                for (src, des) in ohv
                    .iter()
                    .zip(witness[0].iter_mut().skip(table_offset).take(len))
                {
                    let wit = T::AcvmType::from(des.to_owned());
                    let src = T::AcvmType::from(src.to_owned());
                    let added = driver.add(wit, src);
                    *des = driver.get_as_shared(&added);
                    // Read count
                }

                // Keep the OHV (truncated to the table length, matching the read-count
                // range) for the batched read-tag OR-tree.
                ohv.truncate(len);
                shared_ohvs.push(ohv);
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
                // OR term) after the OR-tree below.
                public_reads.push(index_in_poly);
            }
        }

        tag_tables.push(TagReadTable {
            offset: table_offset,
            shared_ohvs,
            public_reads,
        });
        table_offset += len; // set the offset of the next table within the polynomials
    }

    // Batched OR-tree over all tables' shared OHVs -> read tags.
    compute_read_tags_or_tree::<T, P>(driver, &mut witness[1], tag_tables)?;
    Ok(())
}

/// Per-table data gathered by [`construct_lookup_read_counts`] for the read-tag OR-tree:
/// the one-hot vectors of the table's shared-index gates (each truncated to the table
/// length) plus the absolute polynomial indices read by its public-index gates.
struct TagReadTable<S> {
    offset: usize,
    shared_ohvs: Vec<Vec<S>>,
    public_reads: Vec<usize>,
}

/// Computes read tags as the elementwise OR of every gate's read positions.
///
/// For 0/1 one-hot vectors the read tag equals `1 − Π_g (1 − ohv_g)`, i.e. the OR of the
/// gates' OHVs (`OR` is associative, commutative and idempotent on `{0,1}`, so this is
/// exactly the value the previous serial `t ← t + e·(1−t)` cmux chain accumulated,
/// independent of gate order). The complements `1 − ohv_g` are local; the product is a
/// balanced binary OR-tree whose pairwise multiplications are batched across ALL tables
/// into ONE `mul_many` per level, so the whole tag phase costs `max_t ⌈log2 g_t⌉` rounds
/// instead of `Σ_t (g_t − 1)`. Public-index reads then set their entry to 1 (an idempotent
/// OR term). A table with no shared gates contributes no communication (and if NO table
/// has ≥ 2 shared gates the loop makes no `mul_many` call at all).
fn compute_read_tags_or_tree<T, P>(
    driver: &mut T,
    read_tags: &mut Polynomial<T::ArithmeticShare>,
    tables: Vec<TagReadTable<T::ArithmeticShare>>,
) -> eyre::Result<()>
where
    T: NoirWitnessExtensionProtocol<P::ScalarField>,
    P: CurveGroup,
{
    let one = T::AcvmType::from(P::ScalarField::one());

    // Per-table operand lists, initialised to the complements (1 - ohv) of each shared
    // gate's OHV (local: public one minus a share).
    let mut operands: Vec<Vec<Vec<T::AcvmType>>> = Vec::with_capacity(tables.len());
    for tbl in &tables {
        let mut ops = Vec::with_capacity(tbl.shared_ohvs.len());
        for ohv in &tbl.shared_ohvs {
            let mut comp = Vec::with_capacity(ohv.len());
            for s in ohv {
                comp.push(driver.sub(one.clone(), T::AcvmType::from(s.to_owned())));
            }
            ops.push(comp);
        }
        operands.push(ops);
    }

    // Batched OR-tree reduction: while any table still has > 1 operand, pair operands
    // up within each table and multiply all pairs (across all tables) in one mul_many.
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

    // Emit tags: 1 - Π(1-ohv) for tables with shared reads, then OR in the public reads.
    for (tbl, ops) in tables.iter().zip(operands) {
        if let Some(prod) = ops.into_iter().next() {
            for (j, p) in prod.into_iter().enumerate() {
                let tag = driver.sub(one.clone(), p);
                read_tags[tbl.offset + j] = driver.get_as_shared(&tag);
            }
        }
        for &idx in &tbl.public_reads {
            read_tags[idx] = driver.promote_to_trivial_share(P::ScalarField::one());
        }
    }
    Ok(())
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

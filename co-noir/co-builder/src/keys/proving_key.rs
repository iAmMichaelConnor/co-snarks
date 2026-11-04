use crate::keys::plain_proving_key::{
    compute_permutation_argument_polynomials, construct_lookup_read_counts,
    construct_lookup_table_polynomials,
};
use crate::prelude::GenericUltraCircuitBuilder;
use crate::types::types::{CycleNode, CyclicPermutation};
use ark_ec::CurveGroup;
use ark_ff::One;
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_noir_common::constants::{NUM_WIRES, PUBLIC_INPUT_WIRE_INDEX};
use co_noir_common::crs::ProverCrs;
use co_noir_common::keys::verification_key::VerifyingKeyBarretenberg;
use co_noir_common::polynomials::entities::PrecomputedEntities;
use co_noir_common::utils::Utils;
use co_noir_common::{
    honk_curve::HonkCurve,
    honk_proof::{HonkProofError, HonkProofResult, TranscriptFieldType},
    keys::proving_key::ProvingKey,
    keys::types::ActiveRegionData,
    mpc::NoirUltraHonkProver,
    mpc::rep3::Rep3UltraHonkDriver,
    mpc::shamir::ShamirUltraHonkDriver,
    polynomials::entities::Polynomials,
    polynomials::polynomial::NUM_DISABLED_ROWS_IN_SUMCHECK,
};
use mpc_core::MpcState;
use std::collections::HashMap;

pub type Rep3ProvingKey<P> = ProvingKey<Rep3UltraHonkDriver, P>;
pub type ShamirProvingKey<P> = ProvingKey<ShamirUltraHonkDriver, P>;
pub fn create_prover_instance<
    C: CurveGroup,
    T: NoirUltraHonkProver<C>,
    U: NoirWitnessExtensionProtocol<C::ScalarField, ArithmeticShare = T::ArithmeticShare>,
>(
    id: <T::State as MpcState>::PartyID,
    mut circuit: GenericUltraCircuitBuilder<C, U>,
    driver: &mut U,
) -> HonkProofResult<ProvingKey<T, C>> {
    tracing::trace!("ProvingKey create");

    assert!(
        circuit.circuit_finalized,
        "the circuit must be finalized before creating the proving key"
    );

    let dyadic_circuit_size = circuit.compute_dyadic_size();

    // The public inputs must be public, except for the blinded accumulator of the private
    // recursion profile, which is opened here. Check this before anything is opened.
    let designated = &circuit.recursion_public_output_indices;
    if circuit.public_inputs.iter().any(|index| {
        U::is_shared(&circuit.get_variable(*index as usize)) && !designated.contains(index)
    }) {
        return Err(HonkProofError::ExpectedPublicWitness);
    }
    let (output_indices, output_shares): (Vec<_>, Vec<_>) = designated
        .iter()
        .filter_map(|index| {
            U::get_shared(&circuit.get_variable(*index as usize)).map(|share| (*index, share))
        })
        .unzip();
    let opened_outputs: HashMap<u32, C::ScalarField> = if output_shares.is_empty() {
        HashMap::new()
    } else {
        output_indices
            .into_iter()
            .zip(driver.open_many(&output_shares)?)
            .collect()
    };

    // Complete the public inputs execution trace block from builder.public_inputs
    circuit.blocks.compute_offsets();

    // Find index of last non-trivial wire value in the trace
    let mut final_active_wire_idx = 0;
    for block in circuit.blocks.get() {
        if !block.is_empty() {
            final_active_wire_idx = block.trace_offset as usize + block.len() - 1;
        }
    }

    // TACEO TODO BB allocates less memory for the different polynomials

    let mut proving_key = ProvingKey {
        polynomials: Polynomials::new(dyadic_circuit_size),
        public_inputs: Vec::with_capacity(circuit.public_inputs.len()),
        circuit_size: dyadic_circuit_size as u32,
        final_active_wire_idx,
        num_public_inputs: circuit.public_inputs.len() as u32,
        proof_privacy: circuit.proof_privacy(),
        ..Default::default()
    };

    populate_memory_records(&mut proving_key, &mut circuit, driver);

    // Construct and add to proving key the wire, selector and copy constraint polynomials
    populate_trace(id, &mut proving_key, &mut circuit, dyadic_circuit_size);

    // First and last lagrange polynomials (in the full circuit size). lagrange_first marks row
    // NUM_DISABLED_ROWS_IN_SUMCHECK, the row immediately preceding the first real trace content
    // (rows before it are disabled in Sumcheck for ZK masking/shift compatibility).
    proving_key.polynomials.precomputed.lagrange_first_mut()
        [NUM_DISABLED_ROWS_IN_SUMCHECK as usize] = C::ScalarField::one();
    proving_key.polynomials.precomputed.lagrange_last_mut()[final_active_wire_idx] =
        C::ScalarField::one();

    construct_lookup_polynomials(&mut proving_key, &mut circuit, dyadic_circuit_size, driver)?;

    // Construct the public inputs array
    let block = circuit.blocks.get_pub_inputs();
    proving_key.pub_inputs_offset = block.trace_offset;
    for var_idx in block.wires[PUBLIC_INPUT_WIRE_INDEX]
        .iter()
        .take(proving_key.num_public_inputs as usize)
        .cloned()
    {
        let var = U::get_public(&circuit.get_variable(var_idx as usize))
            .or_else(|| opened_outputs.get(&var_idx).copied())
            .ok_or(HonkProofError::ExpectedPublicWitness)?;
        proving_key.public_inputs.push(var);
    }

    Ok(proving_key)
}

fn populate_memory_records<
    C: CurveGroup,
    T: NoirUltraHonkProver<C>,
    U: NoirWitnessExtensionProtocol<C::ScalarField, ArithmeticShare = T::ArithmeticShare>,
>(
    proving_key: &mut ProvingKey<T, C>,
    builder: &mut GenericUltraCircuitBuilder<C, U>,
    driver: &mut U,
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

    // We have to add the shared memory records to the proving key as well
    for (k, el) in builder.memory_records_shared.iter() {
        let val = if U::is_shared(el) {
            U::get_shared(el).expect("Already checked it is shared")
        } else {
            U::promote_to_trivial_share(
                driver,
                U::get_public(el).expect("Already checked it is public"),
            )
        };
        proving_key
            .memory_records_shared
            .insert(k + ram_rom_offset, val);
    }
}

fn populate_trace<
    C: CurveGroup,
    T: NoirUltraHonkProver<C>,
    U: NoirWitnessExtensionProtocol<C::ScalarField, ArithmeticShare = T::ArithmeticShare>,
>(
    id: <T::State as MpcState>::PartyID,
    proving_key: &mut ProvingKey<T, C>,
    builder: &mut GenericUltraCircuitBuilder<C, U>,
    circuit_size: usize,
) {
    tracing::trace!("Populating trace");

    let mut active_region_data = ActiveRegionData::new();
    let copy_cycles = populate_wires_and_selectors_and_compute_copy_cycles::<C, T, U>(
        id,
        builder,
        &mut proving_key.polynomials,
        &mut active_region_data,
    );
    proving_key.active_region_data = active_region_data;

    // Compute the permutation argument polynomials (sigma/id) and add them to proving key
    compute_permutation_argument_polynomials(
        &mut proving_key.polynomials.precomputed,
        builder,
        copy_cycles,
        circuit_size,
        &proving_key.active_region_data,
    );
}

fn populate_wires_and_selectors_and_compute_copy_cycles<
    C: CurveGroup,
    T: NoirUltraHonkProver<C>,
    U: NoirWitnessExtensionProtocol<C::ScalarField, ArithmeticShare = T::ArithmeticShare>,
>(
    id: <T::State as MpcState>::PartyID,
    builder: &mut GenericUltraCircuitBuilder<C, U>,
    polynomials: &mut Polynomials<T::ArithmeticShare, C::ScalarField>,
    active_region_data: &mut ActiveRegionData,
) -> Vec<CyclicPermutation> {
    // At most one copy cycle per variable.
    let mut copy_cycles = vec![vec![]; builder.variables.len()];

    let wires: &mut [_; NUM_WIRES] = polynomials.witness.get_wires_mut().try_into().unwrap();

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
                let var = builder.get_variable(var_idx);
                wire[trace_row_idx] = if U::is_shared(&var) {
                    U::get_shared(&var).unwrap()
                } else {
                    T::promote_to_trivial_share(id, U::get_public(&var).unwrap())
                };
                // Add the address of the witness value to its corresponding copy cycle
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

pub fn create_keys_barretenberg<
    C: HonkCurve<TranscriptFieldType>,
    T: NoirUltraHonkProver<C>,
    U: NoirWitnessExtensionProtocol<C::ScalarField, ArithmeticShare = T::ArithmeticShare>,
>(
    id: <T::State as MpcState>::PartyID,
    circuit: GenericUltraCircuitBuilder<C, U>,
    crs: &ProverCrs<C>,
    driver: &mut U,
) -> HonkProofResult<(ProvingKey<T, C>, VerifyingKeyBarretenberg<C>)> {
    let pk = create_prover_instance(id, circuit, driver)?;
    let circuit_size = pk.circuit_size;

    let mut commitments = PrecomputedEntities::default();
    for (des, src) in commitments
        .iter_mut()
        .zip(pk.polynomials.precomputed.iter())
    {
        let comm = Utils::commit(src.as_ref(), crs)?;
        *des = C::Affine::from(comm);
    }

    // Create and return the VerifyingKey instance
    let vk = VerifyingKeyBarretenberg {
        log_circuit_size: Utils::get_msb64(circuit_size as u64) as u64,
        num_public_inputs: pk.num_public_inputs as u64,
        pub_inputs_offset: pk.pub_inputs_offset as u64,
        commitments,
    };
    Ok((pk, vk))
}

pub fn construct_lookup_polynomials<
    C: CurveGroup,
    T: NoirUltraHonkProver<C>,
    U: NoirWitnessExtensionProtocol<C::ScalarField, ArithmeticShare = T::ArithmeticShare>,
>(
    proving_key: &mut ProvingKey<T, C>,
    circuit: &mut GenericUltraCircuitBuilder<C, U>,
    dyadic_circuit_size: usize,
    driver: &mut U,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::GenericUltraCircuitBuilder;
    use ark_bn254::{Fr, G1Projective};
    use co_acvm::{PlainAcvmSolver, Rep3AcvmSolver, Rep3AcvmType};
    use co_noir_common::keys::proof_privacy::ProofPrivacy;
    use co_noir_common::mpc::plain::PlainUltraHonkDriver;
    use mpc_core::protocols::rep3::{conversion::A2BType, id::PartyID, share_field_elements};
    use mpc_net::{Network, bytes::Bytes, local::LocalNetwork};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A [`Network`] that counts the messages its party sends.
    struct CountingNetwork {
        inner: LocalNetwork,
        sent: AtomicUsize,
    }

    impl Network for CountingNetwork {
        fn id(&self) -> usize {
            self.inner.id()
        }

        fn send(&self, to: usize, data: Bytes) -> eyre::Result<()> {
            self.sent.fetch_add(1, Ordering::SeqCst);
            self.inner.send(to, data)
        }

        fn recv(&self, from: usize) -> eyre::Result<Bytes> {
            self.inner.recv(from)
        }

        fn get_connection_stats(&self) -> mpc_net::ConnectionStats {
            self.inner.get_connection_stats()
        }
    }

    /// Key generation opens the designated outputs of the private recursion profile, and rejects
    /// any other secret-shared public input before it opens anything.
    #[test]
    fn only_designated_outputs_are_opened() {
        let values: Vec<_> = (100..109u64).map(Fr::from).collect();
        let shares = share_field_elements(&values, &mut rand::thread_rng());
        let threads: Vec<_> = LocalNetwork::new_3_parties()
            .into_iter()
            .zip(shares)
            .map(|(inner, shares)| {
                let values = values.clone();
                std::thread::spawn(move || {
                    let net = CountingNetwork {
                        inner,
                        sent: AtomicUsize::new(0),
                    };
                    let mut driver =
                        Rep3AcvmSolver::<Fr, _>::new(&net, A2BType::default()).unwrap();
                    for undesignated_public in [false, true] {
                        let mut builder =
                            GenericUltraCircuitBuilder::<G1Projective, _>::new_minimal(0);
                        let indices: Vec<_> = shares
                            .iter()
                            .map(|share| builder.add_variable(Rep3AcvmType::Shared(*share)))
                            .collect();
                        // The first value is secret-shared but not a designated output.
                        builder.recursion_public_output_indices = indices[1..].to_vec();
                        builder.public_inputs = if undesignated_public {
                            indices.clone()
                        } else {
                            indices[1..].to_vec()
                        };
                        builder.finalize_circuit(&mut driver).unwrap();
                        net.sent.store(0, Ordering::SeqCst);
                        let key = create_prover_instance::<G1Projective, Rep3UltraHonkDriver, _>(
                            PartyID::try_from(net.id()).unwrap(),
                            builder,
                            &mut driver,
                        );
                        if undesignated_public {
                            assert!(matches!(key, Err(HonkProofError::ExpectedPublicWitness)));
                            assert_eq!(net.sent.load(Ordering::SeqCst), 0);
                        } else {
                            let key = key.unwrap();
                            assert_eq!(key.public_inputs, values[1..]);
                            assert_eq!(key.proof_privacy, ProofPrivacy::PrivateRecursion);
                            // One message: the opening of the designated outputs.
                            assert_eq!(net.sent.load(Ordering::SeqCst), 1);
                        }
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
    }

    #[test]
    fn both_key_constructors_set_the_proof_privacy() {
        for private in [false, true] {
            let builder = || {
                let mut builder =
                    GenericUltraCircuitBuilder::<G1Projective, PlainAcvmSolver<Fr>>::new_minimal(0);
                builder.add_default_to_public_inputs();
                if private {
                    builder.recursion_public_output_indices = builder.public_inputs.clone();
                }
                let mut driver = PlainAcvmSolver::new();
                builder.finalize_circuit(&mut driver).unwrap();
                (builder, driver)
            };
            let expected = if private {
                ProofPrivacy::PrivateRecursion
            } else {
                ProofPrivacy::Standard
            };
            let (circuit, mut driver) = builder();
            let key = create_prover_instance::<G1Projective, PlainUltraHonkDriver, _>(
                0,
                circuit,
                &mut driver,
            )
            .unwrap();
            assert_eq!(key.proof_privacy, expected);
            let (mut circuit, mut driver) = builder();
            let key = crate::keys::plain_proving_key::create_prover_instance(
                &mut circuit,
                Default::default(),
                &mut driver,
            )
            .unwrap();
            assert_eq!(key.proof_privacy, expected);
        }
    }
}

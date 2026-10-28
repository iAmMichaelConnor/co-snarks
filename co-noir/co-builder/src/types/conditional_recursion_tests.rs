//! Constraint-level negative regressions. These run the complete recursive
//! circuit with Plain witness execution. A separate real-party test checks
//! private constrained selection; full private-network execution of the false
//! recursive branch is not claimed here.
use super::*;
use crate::prelude::constraint_system_from_reader;
use crate::types::types::WitnessOrConstant;
use ark_bn254::{Bn254, Fr, G1Projective};
use ark_ec::CurveGroup;
use co_noir_common::{crs::parse::CrsParser, keys::verification_key::VerifyingKey};
use co_ultrahonk::prelude::UltraHonk;

fn crs_directory() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../co-noir-common/src/crs")
}
fn finish_and_prove(
    mut builder: GenericUltraCircuitBuilder<G1Projective, PlainAcvmSolver<Fr>>,
    driver: &mut PlainAcvmSolver<Fr>,
) -> (bool, Vec<u8>) {
    builder.finalize_circuit(driver).unwrap();
    let dir = crs_directory();
    let (crs, g2) = CrsParser::<G1Projective>::get_crs::<Bn254>(
        dir.join("bn254_g1.dat"),
        dir.join("bn254_g2.dat"),
        builder.compute_dyadic_size(),
        ZeroKnowledge::Yes,
    )
    .unwrap()
    .split();
    let (pk, vk): (_, VerifyingKey<Bn254>) = builder
        .create_keys::<Bn254>(crs.into(), g2, driver)
        .unwrap();
    let vk_bytes = vk.inner_vk.to_buffer();
    let (proof, inputs) =
        UltraHonk::<_, Poseidon2Sponge>::prove(pk, ZeroKnowledge::Yes, &vk.inner_vk).unwrap();
    (
        UltraHonk::<_, Poseidon2Sponge>::verify(proof, &inputs, &vk, ZeroKnowledge::Yes).unwrap(),
        vk_bytes,
    )
}

#[test]
fn conditional_invalid_inner_proof_rejects_only_when_enabled() {
    let vectors = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test_vectors/noir");
    for (name, zk) in [("recursion_private", false), ("recursion_private_zk", true)] {
        let fixture = vectors.join(name).join("kat");
        let constraints = constraint_system_from_reader(
            std::fs::File::open(fixture.join(format!("{name}.json"))).unwrap(),
        )
        .unwrap();
        let witness: Vec<Fr> = noir_types::witness_from_reader(
            std::fs::File::open(fixture.join(format!("{name}.gz"))).unwrap(),
        )
        .unwrap();
        assert_eq!(constraints.honk_recursion_constraints.len(), 1);
        let source = &constraints.honk_recursion_constraints[0];
        let dir = crs_directory();
        let recursion_crs = CrsParser::<G1Projective>::get_crs_g1(
            dir.join("bn254_g1.dat"),
            constraints
                .get_honk_recursion_public_inputs_size::<G1Projective>()
                .max(2),
            ZeroKnowledge::Yes,
        )
        .unwrap();
        let mut reference_keys = [None, None];
        for (enabled, corrupt, direct, expected) in [
            (false, true, false, true),
            (true, false, false, true),
            (true, false, true, true),
            (true, true, true, false),
        ] {
            let mut builder =
                GenericUltraCircuitBuilder::<G1Projective, PlainAcvmSolver<Fr>>::new_minimal(0);
            builder.is_write_vk_mode = false;
            let mut driver = PlainAcvmSolver::<Fr>::new();
            let key = source
                .key
                .iter()
                .map(|i| builder.add_variable(witness[*i as usize]))
                .collect();
            let mut proof_values: Vec<_> =
                source.proof.iter().map(|i| witness[*i as usize]).collect();
            // After Oink, the next element is a scalar; ZK first supplies a
            // four-field Libra point, followed by its scalar sum. Preserve all
            // curve encodings while making the proof transcript invalid.
            let scalar_offset = PUBLIC_INPUTS_SIZE
                + if zk {
                    OINK_PROOF_LENGTH_WITHOUT_PUB_INPUTS_ZK + 4
                } else {
                    OINK_PROOF_LENGTH_WITHOUT_PUB_INPUTS
                };
            if corrupt {
                proof_values[scalar_offset] += Fr::one();
            }
            let proof = proof_values
                .into_iter()
                .map(|v| builder.add_variable(v))
                .collect();
            let public_inputs = source
                .public_inputs
                .iter()
                .map(|i| builder.add_variable(witness[*i as usize]))
                .collect();
            let key_hash = builder.add_variable(witness[source.key_hash as usize]);
            let predicate = WitnessOrConstant::from_index(builder.add_variable(Fr::from(enabled)));
            let input = RecursionConstraint {
                key,
                proof,
                public_inputs,
                key_hash,
                predicate,
                proof_type: source.proof_type,
            };
            let mut points = if direct {
                // Invoke the real verifier directly: the outer constraint wrapper
                // replaces supplied inputs with mocks in write-VK mode. Here the
                // flag suppresses only host diagnostics along the verifier path;
                // every original proof/key witness is checked unchanged below.
                // An honest control proves that this mode does not itself cause
                // rejection. Compare its VK with the malformed direct case.
                builder.is_write_vk_mode = true;
                let vk_fields: Vec<_> = input
                    .key
                    .iter()
                    .map(|i| FieldCT::from_witness_index(*i))
                    .collect();
                let proof_indices =
                    create_indices_for_reconstructed_proof(&input.proof, &input.public_inputs);
                let proof_fields: Vec<_> = proof_indices
                    .iter()
                    .map(|i| FieldCT::from_witness_index(*i))
                    .collect();
                let original_inputs: Vec<_> = input
                    .key
                    .iter()
                    .chain(&proof_indices)
                    .map(|i| (*i, builder.get_variable(*i as usize)))
                    .collect();
                let vk =
                    RecursiveVerificationKey::new(&vk_fields, &mut builder, &mut driver).unwrap();
                let recursive_key = RecursiveDeciderVerificationKey {
                    vk_and_hash: VKAndHash {
                        vk,
                        hash: FieldCT::from_witness_index(input.key_hash),
                    },
                    _is_complete: false,
                    public_inputs: proof_fields
                        .iter()
                        .take(input.public_inputs.len())
                        .cloned()
                        .collect(),
                    relation_parameters: Default::default(),
                    target_sum: FieldCT::default(),
                    witness_commitments: Default::default(),
                    gemini_masking_commitment: None,
                    alphas: array::from_fn(|_| FieldCT::default()),
                    gate_challenges: Vec::new(),
                };
                let points = UltraRecursiveVerifier::verify_proof::<
                    G1Projective,
                    Poseidon2SpongeCT<G1Projective>,
                    PlainAcvmSolver<Fr>,
                >(
                    proof_fields,
                    recursive_key,
                    &mut builder,
                    &mut driver,
                    if zk {
                        ZeroKnowledge::Yes
                    } else {
                        ZeroKnowledge::No
                    },
                )
                .unwrap();
                for (index, value) in original_inputs {
                    assert_eq!(
                        builder.get_variable(index as usize),
                        value,
                        "direct verifier must retain the supplied proof and key witnesses"
                    );
                }
                builder.is_write_vk_mode = false;
                points
            } else {
                builder
                    .create_honk_recursion_constraints(&input, &recursion_crs, &mut driver)
                    .unwrap()
            };
            points
                .blind_for_private_recursion(&recursion_crs, &mut builder, &mut driver)
                .unwrap();
            points.set_public(&mut builder, &mut driver).unwrap();
            builder.recursion_public_output_indices = builder.public_inputs.clone();
            let (accepted, key) = finish_and_prove(builder, &mut driver);
            assert_eq!(
                accepted, expected,
                "{name}: enabled={enabled}, corrupt={corrupt}"
            );
            if let Some(reference) = &reference_keys[usize::from(direct)] {
                assert_eq!(
                    &key, reference,
                    "predicate and proof validity cannot change the circuit key"
                );
            } else {
                reference_keys[usize::from(direct)] = Some(key);
            }
            eprintln!(
                "conditional recursion {name}: enabled={enabled}, corrupt={corrupt}, direct={direct}, accepted={accepted}"
            );
        }
    }
}

#[test]
fn malicious_blinded_accumulator_outputs_cannot_replace_the_bound_points() {
    let dir = crs_directory();
    let basis =
        CrsParser::<G1Projective>::get_crs_g1(dir.join("bn254_g1.dat"), 2, ZeroKnowledge::No)
            .unwrap();
    let mut driver = PlainAcvmSolver::<Fr>::new();
    let mut builder = GenericUltraCircuitBuilder::<G1Projective, _>::new_minimal(0);
    let p0 = basis.monomials[1];
    let p1 = (-basis.monomials[0].into_group()).into_affine();
    let mut points = PairingPoints::new(
        BigGroup::from_witness::<G1Projective>(&p0, &mut driver, &mut builder).unwrap(),
        BigGroup::from_witness::<G1Projective>(&p1, &mut driver, &mut builder).unwrap(),
    );
    points
        .blind_for_private_recursion(&basis, &mut builder, &mut driver)
        .unwrap();
    points.set_public(&mut builder, &mut driver).unwrap();
    builder.recursion_public_output_indices = builder.public_inputs.clone();
    // Replace the complete output with another valid pairing-kernel pair.
    // A pairing-only check would accept it; the circuit must bind it to the
    // actual inner accumulator and the same secret blinding scalar.
    let mask = (num_bigint::BigUint::one() << 136) - 1u32;
    let mut replacement = Vec::new();
    for point in [p0, p1] {
        let (x, y) = point.xy().unwrap();
        for coordinate in [x, y] {
            let integer: num_bigint::BigUint = coordinate.into();
            replacement.push(Fr::from(&integer & &mask));
            replacement.push(Fr::from(integer >> 136));
        }
    }
    let indices = builder.public_inputs.clone();
    assert_ne!(
        indices
            .iter()
            .map(|i| builder.get_variable(*i as usize))
            .collect::<Vec<_>>(),
        replacement
    );
    for (index, value) in indices.into_iter().zip(replacement) {
        builder.set_variable(index, value);
    }
    assert!(
        !finish_and_prove(builder, &mut driver).0,
        "constraints must reject replacement even though its pairing equation holds"
    );
}

#[test]
fn private_predicate_selection_is_constrained_and_has_fixed_key() {
    use co_acvm::{Rep3AcvmSolver, Rep3AcvmType};
    use mpc_core::protocols::rep3::{conversion::A2BType, share_field_elements};
    use mpc_net::local::LocalNetwork;
    let mut reference_key = None;
    for enabled in [0u64, 1, 2] {
        for tamper in [false, true] {
            let expected = enabled * 123 + (2 - enabled) * 7 - 7;
            let values = [Fr::from(enabled), Fr::from(123u64), Fr::from(expected)];
            let shares = share_field_elements(&values, &mut rand::thread_rng());
            let workers: Vec<_> = LocalNetwork::new_3_parties()
                .into_iter()
                .zip(shares)
                .map(|(net, shares)| {
                    std::thread::spawn(move || {
                        let mut driver =
                            Rep3AcvmSolver::<Fr, _>::new(&net, A2BType::default()).unwrap();
                        let mut builder =
                            GenericUltraCircuitBuilder::<G1Projective, _>::new_minimal(0);
                        let predicate =
                            FieldCT::from_witness(Rep3AcvmType::Shared(shares[0]), &mut builder)
                                .to_bool_ct(&mut builder, &mut driver);
                        let original =
                            FieldCT::from_witness(Rep3AcvmType::Shared(shares[1]), &mut builder);
                        let dummy = FieldCT::from_witness(
                            Rep3AcvmType::Public(Fr::from(7u64)),
                            &mut builder,
                        );
                        let expected =
                            FieldCT::from_witness(Rep3AcvmType::Shared(shares[2]), &mut builder);
                        let selected = FieldCT::conditional_assign(
                            &predicate,
                            &original,
                            &dummy,
                            &mut builder,
                            &mut driver,
                        )
                        .unwrap();
                        assert!(matches!(
                            selected.get_value(&builder, &mut driver),
                            Rep3AcvmType::Shared(_)
                        ));
                        selected.assert_equal(&expected, &mut builder, &mut driver);
                        if tamper {
                            let mut value = builder.get_variable(selected.witness_index as usize);
                            driver.add_assign_with_public(Fr::one(), &mut value);
                            builder.set_variable(selected.witness_index, value);
                        }
                        crate::ultra_builder::private_range_tests::prove_shared_builder(
                            &net,
                            builder,
                            &mut driver,
                        )
                    })
                })
                .collect();
            for worker in workers {
                let (accepted, key) = worker.join().unwrap();
                assert_eq!(
                    accepted,
                    !tamper && enabled <= 1,
                    "enabled={enabled}: conditional output is bound"
                );
                if let Some(reference) = &reference_key {
                    assert_eq!(&key, reference, "secret predicate cannot change key layout");
                } else {
                    reference_key = Some(key);
                }
            }
        }
    }
}

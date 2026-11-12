use acir::native_types::{WitnessMap, WitnessStack};
use ark_ff::PrimeField;
use co_acvm::solver::{PlainCoSolver, Rep3CoSolver};
use co_acvm::{Rep3AcvmType, ShamirAcvmType};
use itertools::izip;
use mpc_net::local::LocalNetwork;
use noirc_artifacts::program::ProgramArtifact;
use std::path::PathBuf;

mod plain_solver;
mod rep3;
mod rep3_driver;
mod shamir;

macro_rules! add_plain_acvm_test {
    ($name: expr) => {
        paste::item! {
            #[test]
            fn [< test_plain_ $name >]() {
                super::plain_acvm_test($name, false);
            }

            #[test]
            fn [< test_plain_level_scheduled_ $name >]() {
                super::plain_acvm_test($name, true);
            }
        }
    };
}

/// Solves the circuit with the plain driver and compares the witness with the known answer.
fn plain_acvm_test(name: &str, level_scheduling: bool) {
    let program =
        std::fs::read_to_string(format!("../test_vectors/noir/{name}/kat/{name}.json")).unwrap();
    let program_artifact = serde_json::from_str::<ProgramArtifact>(&program)
        .expect("failed to parse program artifact");
    let should_witness =
        std::fs::read(format!("../test_vectors/noir/{name}/kat/{name}.gz")).unwrap();
    let should_witness = WitnessStack::deserialize(should_witness.as_slice()).unwrap();
    let prover_toml = format!("../test_vectors/noir/{name}/Prover.toml");
    let mut solver = PlainCoSolver::init_plain_driver(program_artifact, prover_toml).unwrap();
    solver.set_level_scheduling(level_scheduling);
    let is_witness = solver.solve().unwrap();
    let is_witness = PlainCoSolver::convert_to_plain_acvm_witness(is_witness);
    assert_eq!(is_witness, should_witness);
}

macro_rules! add_rep3_acvm_test {
    ($name: expr) => {
        paste::item! {
            #[test]
            fn [< test_rep3_ $name >]() {
                super::rep3_acvm_test($name, false);
            }

            #[test]
            fn [< test_rep3_level_scheduled_ $name >]() {
                super::rep3_acvm_test($name, true);
            }
        }
    };
}

/// Solves the circuit with the REP3 driver and compares the opened witness with the known answer.
fn rep3_acvm_test(name: &str, level_scheduling: bool) {
    let root = std::env!("CARGO_MANIFEST_DIR");
    let program = std::fs::read_to_string(format!(
        "{root}/../test_vectors/noir/{name}/kat/{name}.json"
    ))
    .unwrap();
    let program_artifact = serde_json::from_str::<ProgramArtifact>(&program)
        .expect("failed to parse program artifact");

    let should_witness =
        std::fs::read(format!("{root}/../test_vectors/noir/{name}/kat/{name}.gz")).unwrap();

    let should_witness = WitnessStack::deserialize(should_witness.as_slice()).unwrap();
    let input = PathBuf::from(format!("{root}/../test_vectors/noir/{name}/Prover.toml"));
    // read the input file
    let inputs = noir_types::partially_read_abi_bn254(
        std::fs::File::open(input).unwrap(),
        &program_artifact.abi,
        &program_artifact.bytecode.functions[0]
            .public_inputs()
            .indices(),
    )
    .expect("can share field elements for noir witness extension");

    // create input shares
    let shares = co_noir::split_input_rep3(inputs);
    let nets = LocalNetwork::new_3_parties();
    let mut threads = vec![];
    for (net, program_artifact, share) in izip!(
        nets,
        [
            program_artifact.clone(),
            program_artifact.clone(),
            program_artifact
        ],
        shares
    ) {
        threads.push(std::thread::spawn(move || {
            let input_share = co_noir::witness_map_from_string_map(share, &program_artifact.abi)
                .expect("can translate witness for noir witness extension");
            let mut solver =
                Rep3CoSolver::new_with_witness(&net, program_artifact, input_share).unwrap();
            solver.set_level_scheduling(level_scheduling);
            solver.solve().unwrap()
        }));
    }

    let result3 = threads.pop().unwrap().join().unwrap();
    let result2 = threads.pop().unwrap().join().unwrap();
    let result1 = threads.pop().unwrap().join().unwrap();
    let is_witness = combine_field_elements_for_acvm(result1, result2, result3);
    let is_witness = PlainCoSolver::convert_to_plain_acvm_witness(is_witness);
    assert_eq!(should_witness, is_witness)
}

fn combine_field_elements_for_acvm<F: PrimeField>(
    mut a: WitnessStack<Rep3AcvmType<F>>,
    mut b: WitnessStack<Rep3AcvmType<F>>,
    mut c: WitnessStack<Rep3AcvmType<F>>,
) -> WitnessStack<F> {
    let mut res = WitnessStack::default();
    assert_eq!(a.length(), b.length());
    assert_eq!(b.length(), c.length());
    while let Some(stack_item_a) = a.pop() {
        let stack_item_b = b.pop().unwrap();
        let stack_item_c = c.pop().unwrap();
        assert_eq!(stack_item_a.index, stack_item_b.index);
        assert_eq!(stack_item_b.index, stack_item_c.index);
        let mut witness_map = WitnessMap::default();
        for ((witness_a, share_a), (witness_b, share_b), (witness_c, share_c)) in izip!(
            stack_item_a.witness.into_iter(),
            stack_item_b.witness.into_iter(),
            stack_item_c.witness.into_iter()
        ) {
            assert_eq!(witness_a, witness_b);
            assert_eq!(witness_b, witness_c);
            let reconstructed = match (share_a, share_b, share_c) {
                (Rep3AcvmType::Public(a), Rep3AcvmType::Public(b), Rep3AcvmType::Public(c)) => {
                    if a == b && b == c {
                        a
                    } else {
                        panic!("must be all public")
                    }
                }
                (Rep3AcvmType::Shared(a), Rep3AcvmType::Shared(b), Rep3AcvmType::Shared(c)) => {
                    mpc_core::protocols::rep3::combine_field_element(a, b, c)
                }
                _ => unimplemented!(),
            };
            witness_map.insert(witness_a, reconstructed);
        }
        res.push(stack_item_a.index, witness_map);
    }
    res
}

macro_rules! add_shamir_acvm_test {
    ($name: expr) => {
        paste::item! {
            #[test]
            fn [< test_shamir_ $name >]() {
                let root = std::env!("CARGO_MANIFEST_DIR");
                let program = std::fs::read_to_string(format!(
                    "{root}/../test_vectors/noir/{}/kat/{}.json",
                    $name, $name
                ))
                .unwrap();
                let program_artifact = serde_json::from_str::<ProgramArtifact>(&program)
                    .expect("failed to parse program artifact");

                let should_witness =
                    std::fs::read(format!("{root}/../test_vectors/noir/{}/kat/{}.gz", $name, $name)).unwrap();
                let should_witness =
                   WitnessStack::deserialize(should_witness.as_slice()).unwrap();
                let input = PathBuf::from(format!(
                    "{root}/../test_vectors/noir/{}/Prover.toml",
                    $name
                ));
                let inputs = noir_types::partially_read_abi_bn254(
                    std::fs::File::open(input).unwrap(),
                    &program_artifact.abi,
                    &program_artifact.bytecode.functions[0].public_inputs().indices(),
                ).expect("can share field elements for noir witness extension");

                // degree=1, num_parties=3
                let shares = co_noir_types::split_input_shamir(inputs, 1, 3);
                let nets = LocalNetwork::new_3_parties();
                let mut threads = vec![];
                for (net, program_artifact, share) in izip!(
                    nets,
                    [
                        program_artifact.clone(),
                        program_artifact.clone(),
                        program_artifact
                    ],
                    shares
                ) {
                    threads.push(std::thread::spawn(move || {
                        let input_share = co_noir::witness_map_from_string_map(share, &program_artifact.abi)
                            .expect("can translate witness for noir witness extension");
                        let solver = ShamirCoSolver::new_with_witness(&net, 3, 1, program_artifact, input_share)
                            .unwrap();
                        solver.solve().unwrap()
                    }));
                }

                let result3 = threads.pop().unwrap().join().unwrap();
                let result2 = threads.pop().unwrap().join().unwrap();
                let result1 = threads.pop().unwrap().join().unwrap();
                let is_witness = super::combine_shamir_field_elements_for_acvm(result1, result2, result3);
                let is_witness = PlainCoSolver::convert_to_plain_acvm_witness(is_witness);
                assert_eq!(should_witness, is_witness)
            }
        }
    };
}

/// Solves the circuit with the Shamir driver, expecting every party to fail, and returns the
/// error of the first party.
fn shamir_acvm_error(name: &str) -> String {
    let root = std::env!("CARGO_MANIFEST_DIR");
    let program = std::fs::read_to_string(format!(
        "{root}/../test_vectors/noir/{name}/kat/{name}.json"
    ))
    .unwrap();
    let program_artifact = serde_json::from_str::<ProgramArtifact>(&program)
        .expect("failed to parse program artifact");
    let input = PathBuf::from(format!("{root}/../test_vectors/noir/{name}/Prover.toml"));
    let inputs = noir_types::partially_read_abi_bn254(
        std::fs::File::open(input).unwrap(),
        &program_artifact.abi,
        &program_artifact.bytecode.functions[0]
            .public_inputs()
            .indices(),
    )
    .expect("can share field elements for noir witness extension");

    // degree=1, num_parties=3
    let shares = co_noir_types::split_input_shamir(inputs, 1, 3);
    let nets = LocalNetwork::new_3_parties();
    let threads = izip!(nets, shares)
        .map(|(net, share)| {
            let program_artifact = program_artifact.clone();
            std::thread::spawn(move || {
                let input_share =
                    co_noir::witness_map_from_string_map(share, &program_artifact.abi)
                        .expect("can translate witness for noir witness extension");
                let solver = co_acvm::solver::ShamirCoSolver::new_with_witness(
                    &net,
                    3,
                    1,
                    program_artifact,
                    input_share,
                )
                .unwrap();
                match solver.solve() {
                    Ok(_) => panic!("solving must fail"),
                    Err(err) => format!("{err:?}"),
                }
            })
        })
        .collect::<Vec<_>>();
    let errors = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect::<Vec<_>>();
    errors[0].clone()
}

fn combine_shamir_field_elements_for_acvm<F: PrimeField>(
    mut a: WitnessStack<ShamirAcvmType<F>>,
    mut b: WitnessStack<ShamirAcvmType<F>>,
    mut c: WitnessStack<ShamirAcvmType<F>>,
) -> WitnessStack<F> {
    let mut res = WitnessStack::default();
    assert_eq!(a.length(), b.length());
    assert_eq!(b.length(), c.length());
    while let Some(stack_item_a) = a.pop() {
        let stack_item_b = b.pop().unwrap();
        let stack_item_c = c.pop().unwrap();
        assert_eq!(stack_item_a.index, stack_item_b.index);
        assert_eq!(stack_item_b.index, stack_item_c.index);
        let mut witness_map = WitnessMap::default();
        for ((witness_a, share_a), (witness_b, share_b), (witness_c, share_c)) in izip!(
            stack_item_a.witness.into_iter(),
            stack_item_b.witness.into_iter(),
            stack_item_c.witness.into_iter()
        ) {
            assert_eq!(witness_a, witness_b);
            assert_eq!(witness_b, witness_c);
            let reconstructed = match (share_a, share_b, share_c) {
                (
                    ShamirAcvmType::Public(a),
                    ShamirAcvmType::Public(b),
                    ShamirAcvmType::Public(c),
                ) => {
                    assert_eq!(a, b);
                    assert_eq!(b, c);
                    a
                }
                (
                    ShamirAcvmType::Shared(a),
                    ShamirAcvmType::Shared(b),
                    ShamirAcvmType::Shared(c),
                ) => mpc_core::protocols::shamir::combine_field_element(&[a, b, c], &[1, 2, 3], 1)
                    .expect("shamir reconstruction succeeded"),
                _ => unimplemented!(),
            };
            witness_map.insert(witness_a, reconstructed);
        }
        res.push(stack_item_a.index, witness_map);
    }
    res
}

use add_plain_acvm_test;
use add_rep3_acvm_test;
use add_shamir_acvm_test;

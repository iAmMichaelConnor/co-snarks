use acir::{
    acir_field::FieldElement,
    circuit::Opcode,
    native_types::{Expression, Witness, WitnessMap},
};
use ark_bn254::Fr;
use co_acvm::{
    Rep3AcvmType,
    solver::{
        Rep3CoSolver,
        level_schedule::{attribute_rounds, schedule_levels},
    },
};
use mpc_core::protocols::rep3::share_field_elements;
use mpc_net::{Network, local::LocalNetwork};
use noirc_artifacts::program::ProgramArtifact;
use rand::{SeedableRng, rngs::StdRng};
use std::collections::HashSet;

#[test]
fn compare_reported_rounds_with_actual_independent_inversions() {
    for n in [1usize, 2, 8] {
        let path = format!(
            "{}/../co-noir/examples/test_vectors/poseidon/poseidon.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let mut artifact: ProgramArtifact =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let function = &mut artifact.bytecode.functions[0];
        let initial: HashSet<u32> = (1..=n as u32).collect();
        function.private_parameters = initial.iter().map(|i| Witness(*i)).collect();
        function.public_parameters.0.clear();
        function.return_values.0.clear();
        function.opcodes = (0..n)
            .map(|i| {
                Opcode::AssertZero(Expression {
                    mul_terms: vec![(
                        FieldElement::from(1u128),
                        Witness((i + 1) as u32),
                        Witness((n + i + 1) as u32),
                    )],
                    linear_combinations: vec![],
                    q_c: FieldElement::from(1u128),
                })
            })
            .collect();
        let schedule = schedule_levels(&function.opcodes, &initial);
        let report = attribute_rounds(&function.opcodes, &schedule, &initial);
        assert_eq!(schedule.depth(), 1);
        assert_eq!(report.batched_rounds, n);
        assert_eq!(report.serial_rounds, n);
        let shares = share_field_elements(
            &(0..n).map(|i| Fr::from((i + 2) as u64)).collect::<Vec<_>>(),
            &mut StdRng::seed_from_u64(123),
        );
        let workers: Vec<_> = LocalNetwork::new_3_parties()
            .into_iter()
            .zip(shares)
            .map(|(net, shares)| {
                let artifact = artifact.clone();
                std::thread::spawn(move || {
                    let mut witness = WitnessMap::default();
                    for (i, value) in shares.into_iter().enumerate() {
                        witness.insert(Witness((i + 1) as u32), Rep3AcvmType::Shared(value));
                    }
                    let solver = Rep3CoSolver::new_with_witness(&net, artifact, witness).unwrap();
                    let before: usize = net
                        .get_connection_stats()
                        .iter_msgs()
                        .map(|(_, (_, r))| r)
                        .sum();
                    solver.solve().unwrap();
                    let after: usize = net
                        .get_connection_stats()
                        .iter_msgs()
                        .map(|(_, (_, r))| r)
                        .sum();
                    after - before
                })
            })
            .collect();
        let received: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
        // Each inversion opens a masked value to two peers. The solver also
        // opens its (empty) public output vector once at the end.
        assert_eq!(received, vec![2 * report.batched_rounds + 1; 3]);
    }
}

//! U1 equivalence referee + diagnostics for the witext round-collapse lever.
//!
//! These tests are comms-free: they run the plain driver only. They prove that
//! the Pass-1 level schedule is a correctness-preserving reordering of the
//! serial solve (bit-identical witness), red-validate that a wrong order is
//! actually caught, and emit the DAG-depth / width / round-attribution
//! diagnostics that size the lever's ceiling.
//!
//! Run diagnostics with output:
//!   cargo test -p co-acvm --test witext_level_referee -- --nocapture

use acir::{
    acir_field::FieldElement,
    circuit::Opcode,
    native_types::{Expression, Witness},
};
use co_acvm::solver::PlainCoSolver;
use co_acvm::solver::level_schedule::{attribute_rounds, format_report, schedule_levels};
use noirc_artifacts::program::ProgramArtifact;
use std::collections::HashSet;

const MANIFEST: &str = env!("CARGO_MANIFEST_DIR");

fn vectors_dir() -> String {
    format!("{MANIFEST}/../co-noir/examples/test_vectors")
}

fn load_artifact(name: &str) -> ProgramArtifact {
    let path = format!("{}/{name}/target/{name}.json", vectors_dir());
    let program = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read artifact {path}: {e}"));
    serde_json::from_str::<ProgramArtifact>(&program).expect("failed to parse program artifact")
}

fn prover_path(name: &str) -> String {
    format!("{}/{name}/Prover.toml", vectors_dir())
}

fn opcodes_of(artifact: &ProgramArtifact) -> Vec<Opcode<FieldElement>> {
    artifact.bytecode.functions[0].opcodes.clone()
}

fn shared_initial_of(artifact: &ProgramArtifact) -> HashSet<u32> {
    artifact.bytecode.functions[0]
        .private_parameters
        .iter()
        .map(|w| w.0)
        .collect()
}

/// All ABI witnesses (private + public) that are populated before solving.
fn initial_of(artifact: &ProgramArtifact) -> HashSet<u32> {
    let func = &artifact.bytecode.functions[0];
    let mut set: HashSet<u32> = func.private_parameters.iter().map(|w| w.0).collect();
    set.extend(func.public_parameters.0.iter().map(|w| w.0));
    set
}

/// The core referee: serial solve == level-ordered solve, bit-identical.
fn referee(name: &str) {
    let artifact = load_artifact(name);
    let opcodes = opcodes_of(&artifact);
    let initial = initial_of(&artifact);
    let schedule = schedule_levels(&opcodes, &initial);
    let order = schedule.flatten_level_order();

    // Sanity: the flattened order is a genuine permutation of all opcodes.
    assert_eq!(order.len(), opcodes.len(), "flattened order drops opcodes");
    let unique: HashSet<usize> = order.iter().copied().collect();
    assert_eq!(
        unique.len(),
        opcodes.len(),
        "flattened order has duplicates"
    );

    // Serial solve (ground truth).
    let serial_solver =
        PlainCoSolver::init_plain_driver(artifact.clone(), prover_path(name)).unwrap();
    let serial_witness = serial_solver.solve().unwrap();

    // Level-ordered solve.
    let levelled_solver =
        PlainCoSolver::init_plain_driver(artifact.clone(), prover_path(name)).unwrap();
    let levelled_witness = levelled_solver.solve_in_order(&order).unwrap();

    assert_eq!(
        serial_witness, levelled_witness,
        "level-ordered solve produced a different witness than the serial solve for {name}"
    );

    // The reorder must be non-trivial (otherwise the referee proves nothing):
    // for the chained poseidon circuits the level order differs from stream order.
    let identity: Vec<usize> = (0..opcodes.len()).collect();
    assert_ne!(
        order, identity,
        "level order equals stream order for {name}; referee would be vacuous"
    );
}

/// Red-validation: a deliberately wrong (reversed) order must NOT reproduce the
/// serial witness (it either errors on an unsolved dependency or diverges).
fn red_validate(name: &str) {
    let artifact = load_artifact(name);
    let opcodes = opcodes_of(&artifact);
    let initial = initial_of(&artifact);
    let schedule = schedule_levels(&opcodes, &initial);
    let mut wrong = schedule.flatten_level_order();
    wrong.reverse(); // consumers now precede producers

    let good_solver =
        PlainCoSolver::init_plain_driver(artifact.clone(), prover_path(name)).unwrap();
    let good_witness = good_solver.solve().unwrap();

    let bad_solver = PlainCoSolver::init_plain_driver(artifact.clone(), prover_path(name)).unwrap();
    match bad_solver.solve_in_order(&wrong) {
        Err(_) => { /* expected: unsolved dependency */ }
        Ok(bad_witness) => assert_ne!(
            good_witness, bad_witness,
            "reversed (wrong) order still reproduced the serial witness for {name}; \
             referee is not actually sensitive to order"
        ),
    }
}

#[test]
fn referee_poseidon_base() {
    referee("poseidon");
}

#[test]
fn referee_poseidon_2e17() {
    referee("poseidon_2e17");
}

#[test]
fn red_validate_poseidon_base() {
    red_validate("poseidon");
}

#[test]
fn red_validate_poseidon_2e17() {
    red_validate("poseidon_2e17");
}

/// Diagnostics for all three chain circuits (prints DAG depth, width histogram,
/// round attribution, and the round-collapse factor f). Not an assertion of
/// specific numbers (those are recorded in the U1 report); it validates the
/// analysis runs end-to-end and prints the registered predictions.
#[test]
fn diagnostics_chain_circuits() {
    for name in ["poseidon", "poseidon_2e17", "poseidon_2e20"] {
        let artifact = load_artifact(name);
        let opcodes = opcodes_of(&artifact);
        let initial = initial_of(&artifact);
        let shared_initial = shared_initial_of(&artifact);
        let report = format_report(name, &opcodes, &initial, &shared_initial);
        println!("{report}");
    }
}

/// Build a wrong coefficient of a term is not needed; we replicate the base
/// poseidon opcodes K times over disjoint witness ranges to synthesize a
/// K-independent-hash circuit, and show the DAG depth stays ~ one hash while the
/// per-level width and serial round count scale by K -> f grows ~K-fold.
fn shift_expr(e: &Expression<FieldElement>, off: u32) -> Expression<FieldElement> {
    Expression {
        mul_terms: e
            .mul_terms
            .iter()
            .map(|(c, l, r)| (*c, Witness(l.0 + off), Witness(r.0 + off)))
            .collect(),
        linear_combinations: e
            .linear_combinations
            .iter()
            .map(|(q, w)| (*q, Witness(w.0 + off)))
            .collect(),
        q_c: e.q_c,
    }
}

fn max_witness(opcodes: &[Opcode<FieldElement>]) -> u32 {
    let mut m = 0u32;
    for op in opcodes {
        if let Opcode::AssertZero(e) = op {
            for (_, l, r) in &e.mul_terms {
                m = m.max(l.0).max(r.0);
            }
            for (_, w) in &e.linear_combinations {
                m = m.max(w.0);
            }
        }
    }
    m
}

#[test]
fn diagnostics_independent_hash_synthetic() {
    let artifact = load_artifact("poseidon");
    let base = opcodes_of(&artifact);
    // base poseidon is pure AssertZero; keep only those for the synthetic build.
    let base_az: Vec<&Expression<FieldElement>> = base
        .iter()
        .filter_map(|op| match op {
            Opcode::AssertZero(e) => Some(e),
            _ => None,
        })
        .collect();
    assert_eq!(
        base_az.len(),
        base.len(),
        "base poseidon expected to be pure AssertZero"
    );

    let stride = max_witness(&base) + 1;
    let k = 8u32;
    let mut synthetic: Vec<Opcode<FieldElement>> = Vec::with_capacity(base.len() * k as usize);
    for copy in 0..k {
        let off = copy * stride;
        for e in &base_az {
            synthetic.push(Opcode::AssertZero(shift_expr(e, off)));
        }
    }

    // The ABI inputs of each copy, all private (shared).
    let base_initial = initial_of(&artifact);
    let synth_initial: HashSet<u32> = (0..k)
        .flat_map(|copy| {
            let off = copy * stride;
            base_initial.iter().map(move |w| w + off)
        })
        .collect();
    let schedule = schedule_levels(&synthetic, &synth_initial);
    let attr = attribute_rounds(&synthetic, &schedule, &synth_initial);

    // Reference single-hash numbers.
    let base_schedule = schedule_levels(&base, &base_initial);
    let base_attr = attribute_rounds(&base, &base_schedule, &base_initial);

    println!("=== synthetic K-independent poseidon (K={k}) ===");
    println!(
        "  single hash:  depth={} serial_rounds={} batched_rounds={} f={:.3}",
        base_schedule.depth(),
        base_attr.serial_rounds,
        base_attr.batched_rounds,
        base_attr.f_batched()
    );
    println!(
        "  K={k} hashes: depth={} serial_rounds={} batched_rounds={} f={:.3}",
        schedule.depth(),
        attr.serial_rounds,
        attr.batched_rounds,
        attr.f_batched()
    );

    // The independence claim: K disjoint hashes keep the same DAG depth and
    // batched round count as one hash, while serial rounds scale ~K.
    assert_eq!(
        schedule.depth(),
        base_schedule.depth(),
        "K independent hashes must have the same DAG depth as one hash"
    );
    assert_eq!(
        attr.batched_rounds, base_attr.batched_rounds,
        "K independent hashes must batch into the same round count as one hash"
    );
    assert_eq!(
        attr.serial_rounds,
        k as usize * base_attr.serial_rounds,
        "serial rounds must scale by K for K independent hashes"
    );
}

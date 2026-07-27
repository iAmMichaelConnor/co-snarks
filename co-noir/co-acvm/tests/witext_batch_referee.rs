//! U2 equivalence referee for the level-batched witness-extension solve.
//!
//! U1's referee proved the level *ordering* is a correctness-preserving
//! reordering of the serial solve. U2 additionally *batches* every level's
//! independent shared×shared products into one network round. This referee runs
//! the batched solve path (`solve_via_levels`) with the plain driver and checks
//! it produces a witness bit-identical to the serial solve — i.e. the deferral +
//! scatter of products does not change any solved value. It is comms-free
//! (plain driver only), so it carries zero protocol risk; the REP3 round-count
//! and proof-byte parity are pinned separately by the 3-party fences in the
//! `tests` crate.
//!
//! Run diagnostics with output:
//!   cargo test -p co-acvm --test witext_batch_referee -- --nocapture

use acir::{acir_field::FieldElement, circuit::Opcode};
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

fn initial_of(artifact: &ProgramArtifact) -> HashSet<u32> {
    let func = &artifact.bytecode.functions[0];
    let mut set: HashSet<u32> = func.private_parameters.iter().map(|w| w.0).collect();
    set.extend(func.public_parameters.0.iter().map(|w| w.0));
    set
}

fn shared_initial_of(artifact: &ProgramArtifact) -> HashSet<u32> {
    artifact.bytecode.functions[0]
        .private_parameters
        .iter()
        .map(|w| w.0)
        .collect()
}

/// The core U2 referee: serial solve == level-BATCHED solve, bit-identical.
fn referee(name: &str) {
    let artifact = load_artifact(name);

    let serial_solver =
        PlainCoSolver::init_plain_driver(artifact.clone(), prover_path(name)).unwrap();
    let serial_witness = serial_solver.solve().unwrap();

    let batched_solver =
        PlainCoSolver::init_plain_driver(artifact.clone(), prover_path(name)).unwrap();
    let batched_witness = batched_solver.solve_via_levels().unwrap();

    assert_eq!(
        serial_witness, batched_witness,
        "level-batched solve produced a different witness than the serial solve for {name}"
    );
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
fn referee_poseidon_indep8() {
    referee("poseidon_indep8");
}

/// Independent-hash demonstration: the K-disjoint-hash circuit collapses to a
/// single hash's DAG depth (and batched round count) while its serial round
/// count scales ~K, so the round-collapse factor f grows ~K-fold over the
/// single-hash chain. Prints the numbers and asserts the collapse identities.
#[test]
fn diagnostics_independent_hash_real_vector() {
    let indep = load_artifact("poseidon_indep8");
    let base = load_artifact("poseidon");

    let indep_ops = opcodes_of(&indep);
    let base_ops = opcodes_of(&base);

    println!(
        "{}",
        format_report(
            "poseidon (1 chained hash)",
            &base_ops,
            &initial_of(&base),
            &shared_initial_of(&base),
        )
    );
    println!(
        "{}",
        format_report(
            "poseidon_indep8 (K=8 independent hashes)",
            &indep_ops,
            &initial_of(&indep),
            &shared_initial_of(&indep),
        )
    );

    let base_sched = schedule_levels(&base_ops, &initial_of(&base));
    let base_attr = attribute_rounds(&base_ops, &base_sched, &shared_initial_of(&base));
    let indep_sched = schedule_levels(&indep_ops, &initial_of(&indep));
    let indep_attr = attribute_rounds(&indep_ops, &indep_sched, &shared_initial_of(&indep));

    // K independent hashes keep the single hash's DAG depth; serial rounds scale
    // ~K while batched rounds stay ~one hash -> f grows ~K-fold. (Depth may differ
    // by the tiny linear accumulation tail, so allow a small additive slack.)
    assert!(
        indep_attr.batched_rounds <= base_attr.batched_rounds + 2,
        "K independent hashes should batch into ~one hash's round count: base={} indep={}",
        base_attr.batched_rounds,
        indep_attr.batched_rounds
    );
    assert!(
        indep_attr.serial_rounds >= 6 * base_attr.serial_rounds,
        "serial rounds should scale ~K (=8) for K independent hashes: base={} indep={}",
        base_attr.serial_rounds,
        indep_attr.serial_rounds
    );
    assert!(
        indep_attr.f_batched() >= 4.0 * base_attr.f_batched(),
        "independent-hash f should be several-fold the single-chain f: base_f={:.3} indep_f={:.3}",
        base_attr.f_batched(),
        indep_attr.f_batched()
    );
}

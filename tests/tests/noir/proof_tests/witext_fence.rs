//! Witext (witness-extension) communication fence for the level-batched REP3
//! solve (Design A, unit U2).
//!
//! The poseidon proof-byte KATs and the pk-gen/prove comms fences in `rep3.rs`
//! do not observe the witness-extension phase's network traffic: witext runs
//! inside `Rep3CoSolver::solve`, before pk-gen. This fence isolates that phase.
//!
//! Crucially it drives witext on **secret-shared inputs** (via
//! `split_input_rep3` + `new_with_witness`), which is where the shared×shared
//! products — and hence the network rounds this lever collapses — actually
//! occur. (The `Rep3CoSolver::new(.., Prover.toml)` path used by
//! `witness_and_proof_test` gives every party the full plaintext input, so its
//! witext is pure public computation with ~no comms and would measure nothing.)
//!
//! Realness cross-check: the same shared run continues through pk-gen + prove
//! and the proof bytes are asserted equal to the plain KAT — a witext that
//! skipped the shared×shared reshares could not produce the correct shared
//! witness, so the proof would not match.
//!
//! Baseline (serial, pre-U2) vs batched (U2): the shared witness SHARES change
//! bit-for-bit under U2 (the level-batched solve draws correlated masks in
//! level-major order via `local_mul_vec`'s length-chunked squeeze, not in
//! serial stream order via per-element `masking_field_element`), but every
//! reconstructed witness VALUE — and hence the proof and VK bytes — is
//! unchanged. Only the round/message counts move. See the pinned constants.

use crate::proof_tests::{CRS_PATH_G1, CRS_PATH_G2};
use ark_bn254::Bn254;
use co_acvm::solver::Rep3CoSolver;
use co_noir::Bn254G1;
use co_noir_common::{
    crs::parse::CrsParser,
    honk_proof::TranscriptFieldType,
    keys::verification_key::VerifyingKey,
    transcript::{Poseidon2Sponge, TranscriptHasher},
    types::ZeroKnowledge,
};
use co_ultrahonk::prelude::Rep3CoUltraHonk;
use itertools::izip;
use mpc_net::{local::LocalNetwork, ConnectionStats, Network};
use std::{fs::File, sync::Arc};

fn msg_totals(stats: &ConnectionStats) -> (usize, usize) {
    stats
        .iter_msgs()
        .fold((0, 0), |(s, r), (_, (sent, recv))| (s + sent, r + recv))
}

fn byte_totals(stats: &ConnectionStats) -> (usize, usize) {
    stats
        .iter()
        .fold((0, 0), |(s, r), (_, (sent, recv))| (s + sent, r + recv))
}

/// Per-party witext-phase message and byte totals, summed across net0 + net1.
struct WitextMeasurement {
    proof: Vec<u8>,
    msgs: [(usize, usize); 3],
    bytes: [(usize, usize); 3],
}

fn measure_witext<H: TranscriptHasher<TranscriptFieldType>>(name: &str) -> WitextMeasurement {
    let circuit_file = format!("../test_vectors/noir/{name}/kat/{name}.json");
    let prover_toml = format!("../test_vectors/noir/{name}/Prover.toml");

    let program_artifact =
        co_noir::program_artifact_from_reader(File::open(&circuit_file).unwrap())
            .expect("failed to parse program artifact");
    let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
    let crs_size = co_noir::compute_circuit_size::<Bn254G1>(&constraint_system).unwrap();
    let prover_crs = Arc::new(
        CrsParser::<Bn254G1>::get_crs_g1(CRS_PATH_G1, crs_size, ZeroKnowledge::No).unwrap(),
    );
    let verifier_crs = CrsParser::<Bn254G1>::get_crs_g2::<Bn254>(CRS_PATH_G2).unwrap();

    // Secret-share the inputs across the three parties.
    let inputs = noir_types::partially_read_abi_bn254(
        File::open(&prover_toml).unwrap(),
        &program_artifact.abi,
        &program_artifact.bytecode.functions[0]
            .public_inputs()
            .indices(),
    )
    .expect("can share field elements for noir witness extension");
    let shares = co_noir::split_input_rep3(inputs);

    let nets0 = LocalNetwork::new_3_parties();
    let nets1 = LocalNetwork::new_3_parties();
    let mut threads = Vec::with_capacity(3);
    for (net0, net1, share) in izip!(nets0, nets1, shares) {
        let prover_crs = prover_crs.clone();
        let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
        let artifact = program_artifact.clone();
        threads.push(std::thread::spawn(move || {
            let input_share = co_noir::witness_map_from_string_map(share, &artifact.abi)
                .expect("can translate witness for noir witness extension");

            // --- WITEXT phase on shared inputs (measured) ---
            let solver =
                Rep3CoSolver::new_with_witness(&net0, &net1, artifact, input_share).unwrap();
            let witness = solver.solve().unwrap();
            let m0 = msg_totals(&net0.get_connection_stats());
            let m1 = msg_totals(&net1.get_connection_stats());
            let b0 = byte_totals(&net0.get_connection_stats());
            let b1 = byte_totals(&net1.get_connection_stats());
            let wit_msgs = (m0.0 + m1.0, m0.1 + m1.1);
            let wit_bytes = (b0.0 + b1.0, b0.1 + b1.1);

            // --- continue to prove for the realness cross-check ---
            let witness = co_noir::witness_stack_to_vec_rep3(witness);
            let pk = co_noir::generate_proving_key_rep3(
                &constraint_system,
                witness,
                &net0,
                &net1,
                &prover_crs,
                None,
            )
            .unwrap();
            let vk: VerifyingKey<Bn254> = pk.create_vk(&prover_crs, verifier_crs).unwrap();
            let (proof, _) = Rep3CoUltraHonk::<_, H>::prove(
                &net0,
                pk,
                &prover_crs,
                ZeroKnowledge::No,
                &vk.inner_vk,
            )
            .unwrap();
            (H::to_buffer(proof.inner_as_ref()), wit_msgs, wit_bytes)
        }));
    }
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    WitextMeasurement {
        proof: results[0].0.clone(),
        msgs: std::array::from_fn(|i| results[i].1),
        bytes: std::array::from_fn(|i| results[i].2),
    }
}

/// Witext comms fence for base poseidon (one `t_8` permutation), run on
/// secret-shared inputs.
///
/// Bump policy identical to `poseidon_prove_comms_message_fence_poseidon2sponge`:
/// counts INCREASED => regression, find and fix; counts DECREASED => an
/// optimisation landed, re-pin deliberately.
#[test]
fn poseidon_witext_comms_fence_poseidon2sponge() {
    const PROOF_FILE: &str = "../test_vectors/noir/poseidon/kat/pos_proof_with_pos";
    let m = measure_witext::<Poseidon2Sponge>("poseidon");

    eprintln!("WITEXT msgs (net0+net1) per party = {:?}", m.msgs);
    eprintln!("WITEXT bytes (net0+net1) per party = {:?}", m.bytes);

    // Realness: the shared witness must prove to the plain KAT proof.
    assert_eq!(
        m.proof,
        std::fs::read(PROOF_FILE).unwrap(),
        "witext-derived proof must match the plain KAT (proves the real MPC ran)"
    );

    // Baseline (serial, pre-U2): base poseidon witext pays one framed reshare
    // per shared×shared product = 363 messages + 3 return-value opens = 366 per
    // direction (matches the v3 bench's 366 recv_msgs), at 14648/14680 bytes.
    // U2's level scheduler collapses the 363 independent products into one
    // batched reshare per level that carries a product (195 such levels), + 3
    // opens = 198 messages, at 13304/13336 bytes. Frame count 366 -> 198 = the
    // 1.85x WAN round-collapse (each synchronous reshare is one RTT on the
    // wire). The loopback blocked-recv "rounds" metric also improved (~150 ->
    // ~95, measured; timing-sensitive, so not pinned) — the within-level batch
    // is NOT a global per-level barrier and does not regress loopback.
    assert_eq!(m.msgs, WITEXT_MSGS, "witext framed-message totals moved");
    assert_eq!(m.bytes, WITEXT_BYTES, "witext payload-byte totals moved");
}

// Measured batched (U2) run, base poseidon, secret-shared inputs.
const WITEXT_MSGS: [(usize, usize); 3] = [(198, 198), (198, 198), (198, 198)];
const WITEXT_BYTES: [(usize, usize); 3] = [(13304, 13304), (13336, 13304), (13304, 13336)];

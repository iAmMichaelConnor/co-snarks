use crate::proof_tests::{CRS_PATH_G1, CRS_PATH_G2};
use ark_bn254::{Bn254, Fr};
use co_acvm::solver::Rep3CoSolver;
use co_noir::{Bn254G1, HonkProof};
use co_noir_common::{
    crs::parse::CrsParser,
    honk_proof::TranscriptFieldType,
    keys::verification_key::VerifyingKey,
    transcript::{Poseidon2Sponge, TranscriptHasher},
    types::ZeroKnowledge,
};
use co_noir_types::Rep3Type;
use co_ultrahonk::prelude::{Rep3CoUltraHonk, UltraHonk};
use co_noir::ProgramArtifact;
use itertools::izip;
use mpc_core::protocols::rep3::share_field_element;
use mpc_net::{Network, local::LocalNetwork};
use rand::{CryptoRng, Rng, SeedableRng, rngs::StdRng};
use sha3::Keccak256;
use std::{fs::File, sync::Arc};

fn proof_test<H: TranscriptHasher<TranscriptFieldType>>(
    name: &str,
    has_zk: ZeroKnowledge,
    proof_file: &str,
) {
    let circuit_file = format!("../test_vectors/noir/{name}/kat/{name}.json");
    let witness_file = format!("../test_vectors/noir/{name}/kat/{name}.gz");

    let program_artifact =
        co_noir::program_artifact_from_reader(File::open(&circuit_file).unwrap())
            .expect("failed to parse program artifact");
    let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
    let public_inputs = &constraint_system.public_inputs;

    let witnesses = co_noir::witness_from_reader(File::open(&witness_file).unwrap())
        .unwrap()
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            if public_inputs.contains(&(index as u32)) {
                std::array::from_fn(|_| Rep3Type::from(value))
            } else {
                share_field_element(value, &mut rand::thread_rng()).map(Rep3Type::from)
            }
        });
    let witnesses: [Vec<Rep3Type<Fr>>; 3] =
        witnesses
            .into_iter()
            .fold([Vec::new(), Vec::new(), Vec::new()], |mut acc, share| {
                for (i, s) in share.into_iter().enumerate() {
                    acc[i].push(s);
                }
                acc
            });

    let nets0 = LocalNetwork::new_3_parties();
    let nets1 = LocalNetwork::new_3_parties();
    let mut threads = Vec::with_capacity(3);
    let crs_size = co_noir::compute_circuit_size::<Bn254G1>(&constraint_system).unwrap();
    let prover_crs =
        Arc::new(CrsParser::<Bn254G1>::get_crs_g1(CRS_PATH_G1, crs_size, has_zk).unwrap());
    // Get vk
    let verifier_crs = CrsParser::<Bn254G1>::get_crs_g2::<Bn254>(CRS_PATH_G2).unwrap();
    for (net0, net1, witness) in izip!(nets0, nets1, witnesses) {
        let prover_crs = prover_crs.clone();
        let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
        threads.push(std::thread::spawn(move || {
            // generate proving key and vk
            let pk = co_noir::generate_proving_key_rep3(
                &constraint_system,
                witness,
                &net0,
                &net1,
                &prover_crs,
            )
            .unwrap();
            let vk: VerifyingKey<Bn254> = pk.create_vk(&prover_crs, verifier_crs).unwrap();

            let (proof, public_input) =
                Rep3CoUltraHonk::<_, H>::prove(&net0, pk, &prover_crs, has_zk, &vk.inner_vk)
                    .unwrap();
            (proof, public_input, vk)
        }));
    }

    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();

    let mut proofs = results
        .iter()
        .map(|(proof, _, _)| proof.to_owned())
        .collect::<Vec<_>>();
    let proof = proofs.pop().unwrap();
    for p in proofs {
        assert_eq!(proof, p);
    }

    let mut public_inputs = results
        .iter()
        .map(|(_, public_input, _)| public_input.to_owned())
        .collect::<Vec<_>>();
    let public_input = public_inputs.pop().unwrap();
    for p in public_inputs {
        assert_eq!(public_input, p);
    }

    let vk = results[0].2.clone();
    if has_zk == ZeroKnowledge::No && name != "recursion" && name != "recursion_zk" {
        let proof_u8 = H::to_buffer(proof.inner_as_ref());
        let read_proof_u8 = std::fs::read(proof_file).unwrap();
        assert_eq!(proof_u8, read_proof_u8);

        let read_proof = HonkProof::new(H::from_buffer(&read_proof_u8));
        assert_eq!(proof, read_proof);
    }

    let is_valid = UltraHonk::<Bn254G1, H>::verify(proof, &public_input, &vk, has_zk).unwrap();
    assert!(is_valid);
}

/// Splits a plain witness into REP3 shares with the given RNG. Public inputs
/// stay in the clear (all parties hold the plain value); everything else is
/// additively shared. Mirrors the split done in `proof_test`, but with an
/// explicit RNG so callers can control the sharing randomness.
fn split_witness<R: Rng + CryptoRng>(
    witness: &[Fr],
    public_inputs: &[u32],
    rng: &mut R,
) -> [Vec<Rep3Type<Fr>>; 3] {
    let mut res: [Vec<Rep3Type<Fr>>; 3] =
        std::array::from_fn(|_| Vec::with_capacity(witness.len()));
    for (index, value) in witness.iter().enumerate() {
        let shares: [Rep3Type<Fr>; 3] = if public_inputs.contains(&(index as u32)) {
            std::array::from_fn(|_| Rep3Type::from(*value))
        } else {
            share_field_element(*value, rng).map(Rep3Type::from)
        };
        for (r, s) in res.iter_mut().zip(shares) {
            r.push(s);
        }
    }
    res
}

/// Runs the full 3-party REP3 proving flow on the given witness share-sets.
/// Asserts that all three parties produce identical proofs and public inputs
/// and that the proof verifies, then returns the serialized proof bytes.
fn prove_rep3_from_witness_shares<H: TranscriptHasher<TranscriptFieldType>>(
    program_artifact: &ProgramArtifact,
    witnesses: [Vec<Rep3Type<Fr>>; 3],
    has_zk: ZeroKnowledge,
) -> Vec<u8> {
    let nets0 = LocalNetwork::new_3_parties();
    let nets1 = LocalNetwork::new_3_parties();
    let mut threads = Vec::with_capacity(3);
    let constraint_system = co_noir::get_constraint_system_from_artifact(program_artifact);
    let crs_size = co_noir::compute_circuit_size::<Bn254G1>(&constraint_system).unwrap();
    let prover_crs =
        Arc::new(CrsParser::<Bn254G1>::get_crs_g1(CRS_PATH_G1, crs_size, has_zk).unwrap());
    let verifier_crs = CrsParser::<Bn254G1>::get_crs_g2::<Bn254>(CRS_PATH_G2).unwrap();
    for (net0, net1, witness) in izip!(nets0, nets1, witnesses) {
        let prover_crs = prover_crs.clone();
        let constraint_system = co_noir::get_constraint_system_from_artifact(program_artifact);
        threads.push(std::thread::spawn(move || {
            let pk = co_noir::generate_proving_key_rep3(
                &constraint_system,
                witness,
                &net0,
                &net1,
                &prover_crs,
            )
            .unwrap();
            let vk: VerifyingKey<Bn254> = pk.create_vk(&prover_crs, verifier_crs).unwrap();

            let (proof, public_input) =
                Rep3CoUltraHonk::<_, H>::prove(&net0, pk, &prover_crs, has_zk, &vk.inner_vk)
                    .unwrap();
            (proof, public_input, vk)
        }));
    }

    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();

    let mut proofs = results
        .iter()
        .map(|(proof, _, _)| proof.to_owned())
        .collect::<Vec<_>>();
    let proof = proofs.pop().unwrap();
    for p in proofs {
        assert_eq!(proof, p);
    }

    let mut public_inputs = results
        .iter()
        .map(|(_, public_input, _)| public_input.to_owned())
        .collect::<Vec<_>>();
    let public_input = public_inputs.pop().unwrap();
    for p in public_inputs {
        assert_eq!(public_input, p);
    }

    let vk = results[0].2.clone();
    let is_valid =
        UltraHonk::<Bn254G1, H>::verify(proof.clone(), &public_input, &vk, has_zk).unwrap();
    assert!(is_valid);

    H::to_buffer(proof.inner_as_ref())
}

fn witness_and_proof_test<H: TranscriptHasher<TranscriptFieldType>>(
    name: &str,
    has_zk: ZeroKnowledge,
    proof_file: &str,
) {
    let circuit_file = format!("../test_vectors/noir/{name}/kat/{name}.json");
    let prover_toml = format!("../test_vectors/noir/{name}/Prover.toml");

    let program_artifact =
        co_noir::program_artifact_from_reader(File::open(&circuit_file).unwrap())
            .expect("failed to parse program artifact");

    let nets0 = LocalNetwork::new_3_parties();
    let nets1 = LocalNetwork::new_3_parties();
    let mut threads = Vec::with_capacity(3);
    let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
    let crs_size = co_noir::compute_circuit_size::<Bn254G1>(&constraint_system).unwrap();
    let prover_crs =
        Arc::new(CrsParser::<Bn254G1>::get_crs_g1(CRS_PATH_G1, crs_size, has_zk).unwrap());
    // Get vk
    let verifier_crs = CrsParser::<Bn254G1>::get_crs_g2::<Bn254>(CRS_PATH_G2).unwrap();
    let vk = co_noir::generate_vk::<Bn254>(&constraint_system, prover_crs.clone(), verifier_crs)
        .unwrap();
    for (net0, net1) in nets0.into_iter().zip(nets1) {
        let prover_crs = prover_crs.clone();
        let vk = vk.clone();
        let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
        let artifact = program_artifact.clone();
        let prover_toml = prover_toml.clone();
        threads.push(std::thread::spawn(move || {
            let solver = Rep3CoSolver::new(&net0, &net1, artifact, prover_toml).unwrap();
            let witness = solver.solve().unwrap();
            let witness = co_noir::witness_stack_to_vec_rep3(witness);
            // generate proving key and vk
            let pk = co_noir::generate_proving_key_rep3(
                &constraint_system,
                witness,
                &net0,
                &net1,
                &prover_crs,
            )
            .unwrap();
            let (proof, public_input) =
                Rep3CoUltraHonk::<_, H>::prove(&net0, pk, &prover_crs, has_zk, &vk.inner_vk)
                    .unwrap();
            (proof, public_input)
        }));
    }

    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();

    let mut proofs = results
        .iter()
        .map(|(proof, _)| proof.to_owned())
        .collect::<Vec<_>>();
    let proof = proofs.pop().unwrap();
    for p in proofs {
        assert_eq!(proof, p);
    }

    let mut public_inputs = results
        .iter()
        .map(|(_, public_input)| public_input.to_owned())
        .collect::<Vec<_>>();
    let public_input = public_inputs.pop().unwrap();
    for p in public_inputs {
        assert_eq!(public_input, p);
    }

    if has_zk == ZeroKnowledge::No && name != "recursion" && name != "recursion_zk" {
        let proof_u8 = H::to_buffer(proof.inner_as_ref());
        let read_proof_u8 = std::fs::read(proof_file).unwrap();
        assert_eq!(proof_u8, read_proof_u8);

        let read_proof = HonkProof::new(H::from_buffer(&read_proof_u8));
        assert_eq!(proof, read_proof);
    }

    let is_valid = UltraHonk::<_, H>::verify(proof, &public_input, &vk, has_zk).unwrap();
    assert!(is_valid);
}

#[test]
fn poseidon_witness_and_proof_test_poseidon2sponge() {
    const PROOF_FILE: &str = "../test_vectors/noir/poseidon/kat/pos_proof_with_pos";
    witness_and_proof_test::<Poseidon2Sponge>("poseidon", ZeroKnowledge::No, PROOF_FILE);
    witness_and_proof_test::<Poseidon2Sponge>("poseidon", ZeroKnowledge::Yes, PROOF_FILE);
}

#[test]
fn poseidon_proof_test_poseidon2sponge() {
    const PROOF_FILE: &str = "../test_vectors/noir/poseidon/kat/pos_proof_with_pos";
    proof_test::<Poseidon2Sponge>("poseidon", ZeroKnowledge::No, PROOF_FILE);
    proof_test::<Poseidon2Sponge>("poseidon", ZeroKnowledge::Yes, PROOF_FILE);
}

#[test]
fn poseidon_witness_and_proof_test_keccak256() {
    const PROOF_FILE: &str = "../test_vectors/noir/poseidon/kat/pos_proof_with_kec";
    witness_and_proof_test::<Keccak256>("poseidon", ZeroKnowledge::No, PROOF_FILE);
    witness_and_proof_test::<Keccak256>("poseidon", ZeroKnowledge::Yes, PROOF_FILE);
}

#[test]
fn poseidon_proof_test_keccak256() {
    const PROOF_FILE: &str = "../test_vectors/noir/poseidon/kat/pos_proof_with_kec";
    proof_test::<Keccak256>("poseidon", ZeroKnowledge::No, PROOF_FILE);
    proof_test::<Keccak256>("poseidon", ZeroKnowledge::Yes, PROOF_FILE);
}

/// Share re-randomization invariance: splitting the same witness with fresh
/// sharing randomness must yield byte-identical non-ZK proofs, because the
/// transcript depends only on the reconstructed (plain) values, never on the
/// share representation. If any code path leaked sharing randomness into the
/// proof, the two runs below would produce different bytes. ZK mode is
/// excluded by design: its proof bytes legitimately vary run-to-run.
#[test]
fn poseidon_proof_share_rerandomization_invariance_poseidon2sponge() {
    const PROOF_FILE: &str = "../test_vectors/noir/poseidon/kat/pos_proof_with_pos";
    let circuit_file = "../test_vectors/noir/poseidon/kat/poseidon.json";
    let witness_file = "../test_vectors/noir/poseidon/kat/poseidon.gz";

    let program_artifact = co_noir::program_artifact_from_reader(File::open(circuit_file).unwrap())
        .expect("failed to parse program artifact");
    let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
    let witness = co_noir::witness_from_reader(File::open(witness_file).unwrap()).unwrap();

    // Split the same witness twice with different sharing randomness.
    let mut rng_a = StdRng::seed_from_u64(0xA11CE);
    let mut rng_b = StdRng::seed_from_u64(0xB0B);
    let witnesses_a = split_witness(&witness, &constraint_system.public_inputs, &mut rng_a);
    let witnesses_b = split_witness(&witness, &constraint_system.public_inputs, &mut rng_b);

    // Negative control: the two share-sets must actually differ, otherwise
    // the invariance assertion below would pass vacuously.
    assert_ne!(
        witnesses_a, witnesses_b,
        "different sharing randomness must produce different share-sets"
    );

    let proof_a = prove_rep3_from_witness_shares::<Poseidon2Sponge>(
        &program_artifact,
        witnesses_a,
        ZeroKnowledge::No,
    );
    let proof_b = prove_rep3_from_witness_shares::<Poseidon2Sponge>(
        &program_artifact,
        witnesses_b,
        ZeroKnowledge::No,
    );

    assert_eq!(
        proof_a, proof_b,
        "non-ZK proof bytes must not depend on the share representation"
    );

    // Both runs must also match the single-prover known-answer proof.
    let expected = std::fs::read(PROOF_FILE).unwrap();
    assert_eq!(proof_a, expected);
}

/// Sums a party's per-peer framed-message counters into a single
/// (total_sent_msgs, total_received_msgs) pair.
fn msg_totals(stats: &mpc_net::ConnectionStats) -> (usize, usize) {
    stats
        .iter_msgs()
        .fold((0, 0), |(s, r), (_, (sent, recv))| (s + sent, r + recv))
}

/// Communication-regression fence for the non-ZK REP3 poseidon prove.
///
/// The proof-byte KATs above pass no matter how many network round-trips the
/// protocol takes, so a comms regression (e.g. un-batching a `mul_many` back
/// into sequential opens) would sail through every other test. This test pins
/// the exact per-party (sent, received) framed-message totals instead. The
/// counts are protocol-determined and deterministic for non-ZK proving.
///
/// If this test fails:
/// - counts INCREASED: a round/message regression was introduced — find and
///   fix it before even thinking about bumping the constants;
/// - counts DECREASED: an optimisation landed — lower the constants
///   deliberately so the new, cheaper protocol becomes the fence.
#[test]
fn poseidon_prove_comms_message_fence_poseidon2sponge() {
    const PROOF_FILE: &str = "../test_vectors/noir/poseidon/kat/pos_proof_with_pos";
    let circuit_file = "../test_vectors/noir/poseidon/kat/poseidon.json";
    let witness_file = "../test_vectors/noir/poseidon/kat/poseidon.gz";

    // Per-party (total_sent_msgs, total_received_msgs), indexed by party id.
    // PKGEN_MSGS covers proving-key generation (both networks); PROVE_MSGS
    // covers Rep3CoUltraHonk::prove only. See the doc comment above for the
    // bump policy.
    const PKGEN_MSGS: [(usize, usize); 3] = [(116, 116), (116, 116), (116, 116)];
    // 199 -> 198: the two independent mul_many calls in array_prod_inner_mul_many
    // were merged into one (one fewer round per grand-product computation).
    const PROVE_MSGS: [(usize, usize); 3] = [(198, 198), (198, 198), (198, 198)];

    let program_artifact = co_noir::program_artifact_from_reader(File::open(circuit_file).unwrap())
        .expect("failed to parse program artifact");
    let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
    let witness = co_noir::witness_from_reader(File::open(witness_file).unwrap()).unwrap();
    let mut rng = StdRng::seed_from_u64(0xFE_ACE);
    let witnesses = split_witness(&witness, &constraint_system.public_inputs, &mut rng);

    let nets0 = LocalNetwork::new_3_parties();
    let nets1 = LocalNetwork::new_3_parties();
    let crs_size = co_noir::compute_circuit_size::<Bn254G1>(&constraint_system).unwrap();
    let prover_crs = Arc::new(
        CrsParser::<Bn254G1>::get_crs_g1(CRS_PATH_G1, crs_size, ZeroKnowledge::No).unwrap(),
    );
    let verifier_crs = CrsParser::<Bn254G1>::get_crs_g2::<Bn254>(CRS_PATH_G2).unwrap();

    let mut threads = Vec::with_capacity(3);
    for (net0, net1, witness) in izip!(nets0, nets1, witnesses) {
        let prover_crs = prover_crs.clone();
        let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
        threads.push(std::thread::spawn(move || {
            let pk = co_noir::generate_proving_key_rep3(
                &constraint_system,
                witness,
                &net0,
                &net1,
                &prover_crs,
            )
            .unwrap();
            let vk: VerifyingKey<Bn254> = pk.create_vk(&prover_crs, verifier_crs).unwrap();

            // Snapshot after pk-gen: everything so far is the pk-gen phase,
            // and the net0 totals double as the baseline for the prove phase.
            let pkgen0 = msg_totals(&net0.get_connection_stats());
            let pkgen1 = msg_totals(&net1.get_connection_stats());

            let (proof, _) = Rep3CoUltraHonk::<_, Poseidon2Sponge>::prove(
                &net0,
                pk,
                &prover_crs,
                ZeroKnowledge::No,
                &vk.inner_vk,
            )
            .unwrap();

            let after = msg_totals(&net0.get_connection_stats());
            let pkgen = (pkgen0.0 + pkgen1.0, pkgen0.1 + pkgen1.1);
            let prove = (after.0 - pkgen0.0, after.1 - pkgen0.1);
            (proof, pkgen, prove)
        }));
    }

    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();

    // Sanity check that we ran the real protocol: the proof must match the
    // single-prover known-answer proof bytes.
    let proof_u8 = Poseidon2Sponge::to_buffer(results[0].0.inner_as_ref());
    assert_eq!(proof_u8, std::fs::read(PROOF_FILE).unwrap());

    let measured_pkgen: [(usize, usize); 3] = std::array::from_fn(|i| results[i].1);
    let measured_prove: [(usize, usize); 3] = std::array::from_fn(|i| results[i].2);
    assert_eq!(
        measured_pkgen, PKGEN_MSGS,
        "pk-gen per-party (sent, recv) message totals changed"
    );
    assert_eq!(
        measured_prove, PROVE_MSGS,
        "prove per-party (sent, recv) message totals changed"
    );
}

#[test]
fn add3u64_witness_and_proof_test_poseidon2sponge() {
    const PROOF_FILE: &str = "../test_vectors/noir/add3u64/kat/add3u64_proof_with_pos";
    witness_and_proof_test::<Poseidon2Sponge>("add3u64", ZeroKnowledge::No, PROOF_FILE);
    witness_and_proof_test::<Poseidon2Sponge>("add3u64", ZeroKnowledge::Yes, PROOF_FILE);
}

#[test]
fn add3u64_proof_test_poseidon2sponge() {
    const PROOF_FILE: &str = "../test_vectors/noir/add3u64/kat/add3u64_proof_with_pos";
    proof_test::<Poseidon2Sponge>("add3u64", ZeroKnowledge::No, PROOF_FILE);
    proof_test::<Poseidon2Sponge>("add3u64", ZeroKnowledge::Yes, PROOF_FILE);
}

#[test]
fn add3u64_witness_and_proof_test_keccak256() {
    const PROOF_FILE: &str = "../test_vectors/noir/add3u64/kat/add3u64_proof_with_kec";
    witness_and_proof_test::<Keccak256>("add3u64", ZeroKnowledge::No, PROOF_FILE);
    witness_and_proof_test::<Keccak256>("add3u64", ZeroKnowledge::Yes, PROOF_FILE);
}

#[test]
fn add3u64_proof_test_keccak256() {
    const PROOF_FILE: &str = "../test_vectors/noir/add3u64/kat/add3u64_proof_with_kec";
    proof_test::<Keccak256>("add3u64", ZeroKnowledge::No, PROOF_FILE);
    proof_test::<Keccak256>("add3u64", ZeroKnowledge::Yes, PROOF_FILE);
}

#[test]
#[ignore = "REP3 methods on shared values are not yet implemented"]
fn recursion_witness_and_proof_test_poseidon2sponge() {
    witness_and_proof_test::<Poseidon2Sponge>("recursion", ZeroKnowledge::No, "");
    witness_and_proof_test::<Poseidon2Sponge>("recursion", ZeroKnowledge::Yes, "");
}

#[test]
#[ignore = "REP3 methods on shared values are not yet implemented"]
fn recursion_proof_test_poseidon2sponge() {
    proof_test::<Poseidon2Sponge>("recursion", ZeroKnowledge::No, "");
    proof_test::<Poseidon2Sponge>("recursion", ZeroKnowledge::Yes, "");
}

#[test]
#[ignore = "Test is too slow for the pipeline"]
fn zk_recursion_witness_and_proof_test_poseidon2sponge() {
    witness_and_proof_test::<Poseidon2Sponge>("recursion_zk", ZeroKnowledge::No, "");
    witness_and_proof_test::<Poseidon2Sponge>("recursion_zk", ZeroKnowledge::Yes, "");
}

#[test]
#[ignore = "Test is too slow for the pipeline"]
fn zk_recursion_proof_test_poseidon2sponge() {
    proof_test::<Poseidon2Sponge>("recursion_zk", ZeroKnowledge::No, "");
    proof_test::<Poseidon2Sponge>("recursion_zk", ZeroKnowledge::Yes, "");
}

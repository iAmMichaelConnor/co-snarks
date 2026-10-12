use crate::proof_tests::{CRS_PATH_G1, CRS_PATH_G2};
use ark_bn254::{Bn254, Fr};
use ark_serialize::CanonicalSerialize;
use bytes::Bytes;
use co_acvm::{solver::Rep3CoSolver, PlainAcvmSolver, Rep3AcvmType};
use co_builder::{
    keys::proving_key,
    prelude::{HonkRecursion, UltraCircuitBuilder},
};
use co_noir::ProgramArtifact;
use co_noir::{Bn254G1, HonkProof};
use co_noir_common::{
    crs::{parse::CrsParser, ProverCrs},
    honk_proof::TranscriptFieldType,
    keys::verification_key::VerifyingKey,
    mpc::plain::PlainUltraHonkDriver,
    transcript::{Poseidon2Sponge, TranscriptHasher},
    types::ZeroKnowledge,
    zk_masking::SeededZkBlinding,
};
use co_noir_types::Rep3Type;
use co_ultrahonk::prelude::{CoUltraHonk, Rep3CoUltraHonk, UltraHonk};
use itertools::izip;
use mpc_core::protocols::rep3::share_field_element;
use mpc_net::{local::LocalNetwork, ConnectionStats, Network};
use rand::{rngs::StdRng, CryptoRng, Rng, SeedableRng};
use sha3::Keccak256;
use std::collections::HashSet;
use std::sync::Mutex;
use std::{fs::File, sync::Arc};

fn proof_test<H: TranscriptHasher<TranscriptFieldType>>(
    name: &str,
    has_zk: ZeroKnowledge,
    proof_file: &str,
) {
    proof_test_with_recursion_visibility::<H>(
        name,
        has_zk,
        proof_file,
        co_noir::RecursionInputVisibility::KeepSecret,
    );
}

fn proof_test_with_recursion_visibility<H: TranscriptHasher<TranscriptFieldType>>(
    name: &str,
    has_zk: ZeroKnowledge,
    proof_file: &str,
    recursion_input_visibility: co_noir::RecursionInputVisibility,
) {
    let circuit_file = format!("../test_vectors/noir/{name}/kat/{name}.json");
    let witness_file = format!("../test_vectors/noir/{name}/kat/{name}.gz");

    let program_artifact =
        co_noir::program_artifact_from_reader(File::open(&circuit_file).unwrap())
            .expect("failed to parse program artifact");
    let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
    let public_inputs = &constraint_system.public_inputs;
    let is_private_recursion = name.starts_with("recursion_private");
    if is_private_recursion {
        assert!(
            public_inputs.is_empty(),
            "Inner public inputs must be PRIVATE outer inputs"
        );
    }

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

    let nets = LocalNetwork::new_3_parties();
    let mut threads = Vec::with_capacity(3);
    let prefix = CrsParser::<Bn254G1>::get_crs_g1(CRS_PATH_G1, 2, ZeroKnowledge::No).unwrap();
    let crs_size = co_noir::compute_circuit_size_with_recursion_input_visibility::<Bn254G1>(
        &constraint_system,
        &prefix,
        recursion_input_visibility,
    )
    .unwrap();
    let prover_crs =
        Arc::new(CrsParser::<Bn254G1>::get_crs_g1(CRS_PATH_G1, crs_size, has_zk).unwrap());
    // Get vk
    let verifier_crs = CrsParser::<Bn254G1>::get_crs_g2::<Bn254>(CRS_PATH_G2).unwrap();
    let is_rom_fixture = name == "rom_shared";
    let rom_threads = rayon::current_num_threads();
    for (net, witness) in izip!(nets, witnesses) {
        let prover_crs = prover_crs.clone();
        let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
        threads.push(std::thread::spawn(move || {
            let prove = || {
                // generate proving key and vk
                let pk = co_noir::generate_proving_key_rep3_with_recursion_input_visibility(
                    &constraint_system,
                    witness,
                    &net,
                    &prover_crs,
                    None,
                    recursion_input_visibility,
                )
                .unwrap();
                if is_rom_fixture {
                    assert!(
                        !pk.rom_logup_records.is_empty(),
                        "ROM regression must exercise LogUp rows"
                    );
                }
                let vk: VerifyingKey<Bn254> = pk.create_vk(&prover_crs, verifier_crs).unwrap();

                let (proof, public_input) =
                    Rep3CoUltraHonk::<_, H>::prove(&net, pk, &prover_crs, has_zk, &vk.inner_vk)
                        .unwrap();
                (proof, public_input, vk)
            };
            if is_rom_fixture {
                // Rayon pools are not inherited by std::thread::spawn.
                rayon::ThreadPoolBuilder::new()
                    .num_threads(rom_threads)
                    .build()
                    .unwrap()
                    .install(prove)
            } else {
                prove()
            }
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
    if is_private_recursion {
        // An empty-witness key must match the actual private MPC circuit. This
        // detects witness-dependent layout and profile/CRS sizing mismatches.
        let expected_vk =
            co_noir::generate_vk_barretenberg_with_recursion_input_visibility::<Bn254G1>(
                &constraint_system,
                prover_crs.clone(),
                recursion_input_visibility,
            )
            .unwrap();
        for (_, _, party_vk) in &results {
            assert_eq!(party_vk.inner_vk.to_buffer(), expected_vk.to_buffer());
        }
    }
    if is_rom_fixture {
        let expected_vk = std::fs::read(proof_file.replace("_proof_", "_vk_")).unwrap();
        for (_, _, party_vk) in &results {
            let serialized = if proof_file.ends_with("_pos") {
                party_vk.inner_vk.to_buffer()
            } else {
                party_vk.inner_vk.to_buffer_keccak()
            };
            assert_eq!(
                serialized, expected_vk,
                "ROM VK must match the v6 BB oracle"
            );
        }
    }
    if has_zk == ZeroKnowledge::No
        && name != "recursion"
        && name != "recursion_zk"
        && !is_private_recursion
    {
        let proof_u8 = H::to_buffer(proof.inner_as_ref());
        let read_proof_u8 = std::fs::read(proof_file).unwrap();
        assert_eq!(proof_u8, read_proof_u8);

        let read_proof = HonkProof::new(H::from_buffer(&read_proof_u8));
        assert_eq!(proof, read_proof);
    }

    if is_private_recursion {
        assert!(
            public_input.is_empty(),
            "Private inner statement must not become outer public input"
        );
        if let Ok(directory) = std::env::var("PRIVATE_RECURSION_EVIDENCE_DIR") {
            let directory = std::path::Path::new(&directory).join(format!("{name}-{has_zk:?}"));
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(directory.join("proof"), H::to_buffer(proof.inner_as_ref())).unwrap();
            std::fs::write(directory.join("public_inputs"), H::to_buffer(&public_input)).unwrap();
            std::fs::write(directory.join("vk"), vk.inner_vk.to_buffer()).unwrap();
        }
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

/// Computes the plain (single-prover, non-MPC) UltraHonk proof bytes for a
/// circuit's KAT witness, using the `PlainUltraHonkDriver` (mirrors
/// `tests/tests/noir/proof_tests/plaindriver.rs::proof_test`). Used as the
/// cross-check oracle for comms fences on circuits that don't (yet) have a
/// checked-in proof KAT file -- so the fence can still assert "this is
/// provably the real protocol's output", not just "the byte count didn't
/// change".
fn plain_proof_bytes<H: TranscriptHasher<TranscriptFieldType>>(
    name: &str,
    has_zk: ZeroKnowledge,
) -> Vec<u8> {
    let circuit_file = format!("../test_vectors/noir/{name}/kat/{name}.json");
    let witness_file = format!("../test_vectors/noir/{name}/kat/{name}.gz");

    let constraint_system =
        co_noir::constraint_system_from_reader(File::open(&circuit_file).unwrap())
            .expect("failed to parse constraint system");
    let witness = co_noir::witness_from_reader(File::open(&witness_file).unwrap())
        .expect("failed to parse witness");

    let mut driver = PlainAcvmSolver::new();
    let recursion_crs_size = constraint_system.get_honk_recursion_public_inputs_size::<Bn254G1>();
    let recursion_crs = if recursion_crs_size > 0 {
        CrsParser::<Bn254G1>::get_crs_g1(CRS_PATH_G1, recursion_crs_size, has_zk).unwrap()
    } else {
        ProverCrs::default()
    };
    let builder = UltraCircuitBuilder::<Bn254G1>::create_circuit(
        &constraint_system,
        0,
        witness,
        HonkRecursion::UltraHonk,
        &recursion_crs,
        &mut driver,
    )
    .unwrap();

    let crs_size = builder.compute_dyadic_size();
    let (prover_crs, verifier_crs) =
        CrsParser::<Bn254G1>::get_crs::<Bn254>(CRS_PATH_G1, CRS_PATH_G2, crs_size, has_zk)
            .expect("failed to get crs")
            .split();
    let (proving_key, inner_vk) = proving_key::create_keys_barretenberg::<
        Bn254G1,
        PlainUltraHonkDriver,
        _,
    >(0, builder, &prover_crs, &mut driver)
    .unwrap();
    let verifying_key = VerifyingKey {
        crs: verifier_crs,
        inner_vk,
    };

    let (proof, public_input) = CoUltraHonk::<PlainUltraHonkDriver, _, H>::prove(
        proving_key,
        &prover_crs,
        has_zk,
        &verifying_key.inner_vk,
    )
    .unwrap();

    let is_valid =
        UltraHonk::<_, H>::verify::<Bn254>(proof.clone(), &public_input, &verifying_key, has_zk)
            .unwrap();
    assert!(is_valid, "plain cross-check proof must itself verify");

    H::to_buffer(proof.inner_as_ref())
}

/// Runs the full 3-party REP3 proving flow on the given witness share-sets.
/// Asserts that all three parties produce identical proofs and public inputs
/// and that the proof verifies, then returns the serialized proof bytes.
fn prove_rep3_from_witness_shares<H: TranscriptHasher<TranscriptFieldType>>(
    program_artifact: &ProgramArtifact,
    witnesses: [Vec<Rep3Type<Fr>>; 3],
    has_zk: ZeroKnowledge,
) -> Vec<u8> {
    prove_rep3_with_lookup_batch_size::<H>(program_artifact, witnesses, has_zk, None)
}

fn prove_rep3_with_lookup_batch_size<H: TranscriptHasher<TranscriptFieldType>>(
    program_artifact: &ProgramArtifact,
    witnesses: [Vec<Rep3Type<Fr>>; 3],
    has_zk: ZeroKnowledge,
    lookup_batch_size: Option<usize>,
) -> Vec<u8> {
    let nets = LocalNetwork::new_3_parties();
    let mut threads = Vec::with_capacity(3);
    let constraint_system = co_noir::get_constraint_system_from_artifact(program_artifact);
    let crs_size = co_noir::compute_circuit_size::<Bn254G1>(&constraint_system).unwrap();
    let prover_crs =
        Arc::new(CrsParser::<Bn254G1>::get_crs_g1(CRS_PATH_G1, crs_size, has_zk).unwrap());
    let verifier_crs = CrsParser::<Bn254G1>::get_crs_g2::<Bn254>(CRS_PATH_G2).unwrap();
    for (net, witness) in izip!(nets, witnesses) {
        let prover_crs = prover_crs.clone();
        let constraint_system = co_noir::get_constraint_system_from_artifact(program_artifact);
        threads.push(std::thread::spawn(move || {
            let pk = co_noir::generate_proving_key_rep3(
                &constraint_system,
                witness,
                &net,
                &prover_crs,
                lookup_batch_size,
            )
            .unwrap();
            let vk: VerifyingKey<Bn254> = pk.create_vk(&prover_crs, verifier_crs).unwrap();

            let (proof, public_input) =
                Rep3CoUltraHonk::<_, H>::prove(&net, pk, &prover_crs, has_zk, &vk.inner_vk)
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
    witness_and_proof_test_with_visibility::<H>(name, has_zk, proof_file, false);
}

fn witness_and_proof_test_with_visibility<H: TranscriptHasher<TranscriptFieldType>>(
    name: &str,
    has_zk: ZeroKnowledge,
    proof_file: &str,
    require_public_inputs: bool,
) {
    let circuit_file = format!("../test_vectors/noir/{name}/kat/{name}.json");
    let prover_toml = format!("../test_vectors/noir/{name}/Prover.toml");

    let program_artifact =
        co_noir::program_artifact_from_reader(File::open(&circuit_file).unwrap())
            .expect("failed to parse program artifact");

    let nets = LocalNetwork::new_3_parties();
    let mut threads = Vec::with_capacity(3);
    let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
    let crs_size = co_noir::compute_circuit_size::<Bn254G1>(&constraint_system).unwrap();
    let prover_crs =
        Arc::new(CrsParser::<Bn254G1>::get_crs_g1(CRS_PATH_G1, crs_size, has_zk).unwrap());
    // Get vk
    let verifier_crs = CrsParser::<Bn254G1>::get_crs_g2::<Bn254>(CRS_PATH_G2).unwrap();
    // This helper reads plaintext TOML inputs. Keep the canonical public profile;
    // genuine private-recursion tests use independently shared witness fixtures.
    let vk = VerifyingKey::<Bn254> {
        crs: verifier_crs,
        inner_vk: co_noir::generate_vk_barretenberg_with_recursion_input_visibility::<Bn254G1>(
            &constraint_system,
            prover_crs.clone(),
            co_noir::RecursionInputVisibility::RevealToParticipants,
        )
        .unwrap(),
    };
    for net in nets {
        let prover_crs = prover_crs.clone();
        let vk = vk.clone();
        let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
        let artifact = program_artifact.clone();
        let prover_toml = prover_toml.clone();
        threads.push(std::thread::spawn(move || {
            let solver = if require_public_inputs {
                // Plain TOML values are Public even when the Noir ABI marks
                // their witnesses private. Make this support boundary explicit.
                let inputs =
                    Rep3CoSolver::<Fr, LocalNetwork>::read_abi_bn254(&prover_toml, &artifact.abi)
                        .unwrap();
                assert!(inputs.clone().into_iter().count() > 0);
                assert!(inputs
                    .clone()
                    .into_iter()
                    .all(|(_, value)| matches!(value, Rep3AcvmType::Public(_))));
                Rep3CoSolver::new_with_witness(&net, artifact, inputs).unwrap()
            } else {
                Rep3CoSolver::new(&net, artifact, prover_toml).unwrap()
            };
            let witness = solver.solve().unwrap();
            let witness = co_noir::witness_stack_to_vec_rep3(witness);
            if require_public_inputs {
                assert!(witness
                    .iter()
                    .all(|value| matches!(value, Rep3Type::Public(_))));
            }
            // generate proving key and vk
            let pk = co_noir::generate_proving_key_rep3_with_recursion_input_visibility(
                &constraint_system,
                witness,
                &net,
                &prover_crs,
                None,
                co_noir::RecursionInputVisibility::RevealToParticipants,
            )
            .unwrap();
            let (proof, public_input) =
                Rep3CoUltraHonk::<_, H>::prove(&net, pk, &prover_crs, has_zk, &vk.inner_vk)
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

/// Sums a party's per-peer payload-byte counters into a single
/// (total_sent_bytes, total_received_bytes) pair. Companion to
/// [`msg_totals`]: the byte totals catch a leak that keeps the frame COUNT
/// intact but fattens the payloads (e.g. accidentally serializing both share
/// limbs, or an unmasked value alongside the masked one), which the
/// message-count pins alone would miss.
fn byte_totals(stats: &mpc_net::ConnectionStats) -> (usize, usize) {
    stats
        .iter()
        .fold((0, 0), |(s, r), (_, (sent, recv))| (s + sent, r + recv))
}

/// Asserts each party's (sent, recv) byte totals sit within ±`tolerance`
/// bytes of the pinned values. Exact pins are preferred (and used) wherever
/// the totals are deterministic; phases that transmit Yao garbled circuits
/// need this small band instead, because the GC input/output serialization
/// contains variable-length encodings of per-run-randomized values (observed
/// drift: ±1 byte on multi-megabyte totals). The band is deliberately tight:
/// any systematic fattening of payloads (an extra share limb, an unmasked
/// value riding along -- 32 bytes per element over vector flows) lands far
/// outside ±8 bytes.
fn assert_byte_totals_within(
    measured: [(usize, usize); 3],
    pinned: [(usize, usize); 3],
    tolerance: usize,
    what: &str,
) {
    for (party, (&(ms, mr), &(ps, pr))) in measured.iter().zip(pinned.iter()).enumerate() {
        assert!(
            ms.abs_diff(ps) <= tolerance && mr.abs_diff(pr) <= tolerance,
            "{what}: party {party} (sent, recv) byte totals ({ms}, {mr}) outside \
             ±{tolerance} of pinned ({ps}, {pr})"
        );
    }
}

/// Share-level-identity witness for the batched big-quad pk-gen `mul_many`
/// (the L8-class change in `build_constraints`): one `driver.mul_many` per
/// circuit instead of one per big-quad constraint.
///
/// The REP3 claim backing "batching cannot move proof/VK bytes" at the SHARE
/// level (not merely the value level) is that `arithmetic::mul_vec` draws its
/// masks one element at a time from the correlated ChaCha streams
/// (`masking_field_element`, a per-element `F::rand` on rng1/rng2; the fixed
/// vector sampler now preserves that same uniform stream), so a
/// single call over a concatenation consumes exactly the mask sequence the
/// per-chunk calls consumed, and the reshared output shares are
/// bit-identical. This test pins that property directly: two identical Rep3
/// states (same correlated seeds), same input shares — one run chunked, one
/// run batched — must produce identical output SHARES (limb-for-limb), which
/// must also recombine to the plain products. If this ever fails (e.g.
/// `mul_vec` switches to length-dependent mask pre-squeezing), batching call
/// sites stops being share-transparent and every fence downstream of such a
/// batch must be re-justified at the value level instead.
#[test]
fn l8_batched_mul_vec_share_identity() {
    use ark_ff::UniformRand;
    use mpc_core::protocols::rep3::conversion::A2BType;
    use mpc_core::protocols::rep3::id::PartyID;
    use mpc_core::protocols::rep3::rngs::{Rep3CorrelatedRng, Rep3Rand, Rep3RandBitComp};
    use mpc_core::protocols::rep3::{
        arithmetic, combine_field_elements, share_field_elements, Rep3State,
    };

    // Chunk shape mimicking per-constraint product counts, including a
    // zero-product chunk (a length-1 big-quad constraint used to spend a
    // whole — empty — network frame on it).
    const CHUNKS: &[usize] = &[5, 1, 8, 0, 2, 4, 7];
    let total: usize = CHUNKS.iter().sum();

    let mut rng = StdRng::seed_from_u64(0x158);
    let xs: Vec<Fr> = (0..total).map(|_| Fr::rand(&mut rng)).collect();
    let ys: Vec<Fr> = (0..total).map(|_| Fr::rand(&mut rng)).collect();
    let x_shares = share_field_elements(&xs, &mut rng);
    let y_shares = share_field_elements(&ys, &mut rng);

    let nets = LocalNetwork::new_3_parties();
    let mut threads = Vec::with_capacity(3);
    for (net, x_sh, y_sh) in izip!(nets, x_shares, y_shares) {
        threads.push(std::thread::spawn(move || {
            let id = PartyID::try_from(net.id()).unwrap();
            let i = net.id();
            // Fixed correlated seeds with the production relation (each
            // party's rng2 seed = its prev party's rng1 seed, cf.
            // Rep3State::setup_prf + Network::reshare), so the masks are a
            // genuine zero-sharing and the recombination check below is
            // meaningful. The bitcomp streams are unused by mul_vec.
            let make_state = || {
                let prf: [[u8; 32]; 3] = [[1; 32], [2; 32], [3; 32]];
                Rep3State {
                    id,
                    rngs: Rep3CorrelatedRng::new(
                        Rep3Rand::new(prf[i], prf[(i + 2) % 3]),
                        Rep3RandBitComp::new_2keys([4; 32], [5; 32]),
                        Rep3RandBitComp::new_2keys([6; 32], [7; 32]),
                        id,
                    ),
                    rng: SeedableRng::from_seed([8 + i as u8; 32]),
                    a2b_type: A2BType::default(),
                }
            };
            let mut state_chunked = make_state();
            let mut state_batched = make_state();

            // The pre-L8 shape: one mul_vec (= one reshare round) per chunk.
            let mut chunked = Vec::with_capacity(total);
            let mut off = 0;
            for &n in CHUNKS {
                chunked.extend(
                    arithmetic::mul_vec(
                        &x_sh[off..off + n],
                        &y_sh[off..off + n],
                        &net,
                        &mut state_chunked,
                    )
                    .unwrap(),
                );
                off += n;
            }
            // The L8 shape: one mul_vec over the whole concatenation.
            let batched = arithmetic::mul_vec(&x_sh, &y_sh, &net, &mut state_batched).unwrap();

            assert_eq!(
                chunked, batched,
                "batched mul_vec must produce bit-identical SHARES to the \
                 per-chunk calls it replaces (same mask-draw sequence)"
            );
            batched
        }));
    }
    let outs: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();

    let recombined = combine_field_elements(&outs[0], &outs[1], &outs[2]);
    let expected: Vec<Fr> = izip!(&xs, &ys).map(|(x, y)| *x * *y).collect();
    assert_eq!(
        recombined, expected,
        "recombined batched products must equal the plain products"
    );
}

/// Everything a comms-fence test pins, measured per party (indexed by
/// party id): framed-message totals AND payload-byte totals for the pk-gen
/// and prove phases, plus the party-0 proof bytes for the KAT cross-check.
struct CommsFenceMeasurement {
    proof: Vec<u8>,
    pkgen_msgs: [(usize, usize); 3],
    prove_msgs: [(usize, usize); 3],
    pkgen_bytes: [(usize, usize); 3],
    prove_bytes: [(usize, usize); 3],
}

/// Generic T2-proper comms-fence harness: shares the named circuit's KAT
/// witness with a fixed seed, runs REP3 pk-gen + prove for the given
/// `has_zk` mode, and returns per-party (sent, recv) message AND byte
/// totals for both phases (see [`CommsFenceMeasurement`]). Generalizes the
/// body of `poseidon_prove_comms_message_fence_poseidon2sponge` (left
/// untouched above) so new per-circuit fences don't each re-derive the
/// harness.
///
/// Both pk-gen and prove use the upstream single REP3 network. Snapshots
/// separate their counters; `Rep3CoUltraHonk::prove` starts after pk-gen, and
/// matches the phase split documented in `rep3_comms_floor_table.json`.
fn rep3_prove_comms_fence<H: TranscriptHasher<TranscriptFieldType>>(
    name: &str,
    has_zk: ZeroKnowledge,
    seed: u64,
) -> CommsFenceMeasurement {
    let circuit_file = format!("../test_vectors/noir/{name}/kat/{name}.json");
    let witness_file = format!("../test_vectors/noir/{name}/kat/{name}.gz");

    let program_artifact =
        co_noir::program_artifact_from_reader(File::open(&circuit_file).unwrap())
            .expect("failed to parse program artifact");
    let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
    let witness = co_noir::witness_from_reader(File::open(&witness_file).unwrap()).unwrap();
    let mut rng = StdRng::seed_from_u64(seed);
    let witnesses = split_witness(&witness, &constraint_system.public_inputs, &mut rng);

    let nets = LocalNetwork::new_3_parties();
    let crs_size = co_noir::compute_circuit_size::<Bn254G1>(&constraint_system).unwrap();
    let prover_crs =
        Arc::new(CrsParser::<Bn254G1>::get_crs_g1(CRS_PATH_G1, crs_size, has_zk).unwrap());
    let verifier_crs = CrsParser::<Bn254G1>::get_crs_g2::<Bn254>(CRS_PATH_G2).unwrap();

    let mut threads = Vec::with_capacity(3);
    for (net, witness) in izip!(nets, witnesses) {
        let prover_crs = prover_crs.clone();
        let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
        threads.push(std::thread::spawn(move || {
            let pk = co_noir::generate_proving_key_rep3(
                &constraint_system,
                witness,
                &net,
                &prover_crs,
                None,
            )
            .unwrap();
            let vk: VerifyingKey<Bn254> = pk.create_vk(&prover_crs, verifier_crs).unwrap();

            let pkgen_snapshot = msg_totals(&net.get_connection_stats());
            let pkgen_bytes_snapshot = byte_totals(&net.get_connection_stats());

            let (proof, _) =
                Rep3CoUltraHonk::<_, H>::prove(&net, pk, &prover_crs, has_zk, &vk.inner_vk)
                    .unwrap();

            let after = msg_totals(&net.get_connection_stats());
            let after_b = byte_totals(&net.get_connection_stats());
            let pkgen = pkgen_snapshot;
            let prove = (after.0 - pkgen_snapshot.0, after.1 - pkgen_snapshot.1);
            let pkgen_b = pkgen_bytes_snapshot;
            let prove_b = (
                after_b.0 - pkgen_bytes_snapshot.0,
                after_b.1 - pkgen_bytes_snapshot.1,
            );
            (proof, pkgen, prove, pkgen_b, prove_b)
        }));
    }

    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    let proof_u8 = H::to_buffer(results[0].0.inner_as_ref());
    let measurement = CommsFenceMeasurement {
        proof: proof_u8,
        pkgen_msgs: std::array::from_fn(|i| results[i].1),
        prove_msgs: std::array::from_fn(|i| results[i].2),
        pkgen_bytes: std::array::from_fn(|i| results[i].3),
        prove_bytes: std::array::from_fn(|i| results[i].4),
    };
    eprintln!(
        "{name} communication: pkgen messages {:?}, prove messages {:?}, pkgen bytes {:?}, prove bytes {:?}",
        measurement.pkgen_msgs,
        measurement.prove_msgs,
        measurement.pkgen_bytes,
        measurement.prove_bytes,
    );
    measurement
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
    // PKGEN_MSGS covers proving-key generation; PROVE_MSGS
    // covers Rep3CoUltraHonk::prove only. See the doc comment above for the
    // bump policy.
    // 116 -> 3: the big-quad constraint loop in build_constraints now issues
    // ONE driver.mul_many for the whole circuit instead of one per constraint
    // (poseidon KAT: 114 constraints -> 114 reshare frames merge into 1; the
    // other 2 pk-gen frames are untouched).
    const PKGEN_MSGS: [(usize, usize); 3] = [(3, 3), (3, 3), (3, 3)];
    // 199 -> 198: the two independent mul_many calls in array_prod_inner_mul_many
    // were merged into one (one fewer round per grand-product computation).
    // 198 -> 204: L0d half-share commit MSMs — the 6 non-ZK commit-open calls
    // (oink wires, counts/tags/w4, inverses/z_perm, shplemini folds, Q, KZG:W)
    // now open via 3-way broadcast (2 sends + 2 recvs per party) instead of a
    // ring reshare (1 + 1), buying half the local MSM work per commitment.
    const PROVE_MSGS: [(usize, usize); 3] = [(204, 204), (204, 204), (204, 204)];
    // Per-party (total_sent_bytes, total_received_bytes) — same bump policy.
    // The byte pins catch a leak that keeps the frame count intact but fattens
    // payloads (e.g. serializing both share limbs); see byte_totals. Poseidon
    // is pure-arithmetic (no Yao GC anywhere), so both phases pin EXACT totals.
    // 30336/30368 -> 29432/29464: the big-quad mul_many batching (see
    // PKGEN_MSGS) merges 114 reshare frames into 1 — element payloads are
    // byte-identical (share-level identity), only 113 ark slice length
    // prefixes (8 B each = 904 B) disappear per direction.
    const PKGEN_BYTES: [(usize, usize); 3] = [(29432, 29432), (29464, 29432), (29432, 29464)];
    // prove bytes re-pinned with PROVE_MSGS for L0d (broadcast opens carry the
    // same points to one extra peer).
    const PROVE_BYTES: [(usize, usize); 3] =
        [(6242368, 6242368), (6242400, 6242368), (6242368, 6242400)];

    let program_artifact = co_noir::program_artifact_from_reader(File::open(circuit_file).unwrap())
        .expect("failed to parse program artifact");
    let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
    let witness = co_noir::witness_from_reader(File::open(witness_file).unwrap()).unwrap();
    let mut rng = StdRng::seed_from_u64(0xFE_ACE);
    let witnesses = split_witness(&witness, &constraint_system.public_inputs, &mut rng);

    let nets = LocalNetwork::new_3_parties();
    let crs_size = co_noir::compute_circuit_size::<Bn254G1>(&constraint_system).unwrap();
    let prover_crs = Arc::new(
        CrsParser::<Bn254G1>::get_crs_g1(CRS_PATH_G1, crs_size, ZeroKnowledge::No).unwrap(),
    );
    let verifier_crs = CrsParser::<Bn254G1>::get_crs_g2::<Bn254>(CRS_PATH_G2).unwrap();

    let mut threads = Vec::with_capacity(3);
    for (net, witness) in izip!(nets, witnesses) {
        let prover_crs = prover_crs.clone();
        let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
        threads.push(std::thread::spawn(move || {
            let pk = co_noir::generate_proving_key_rep3(
                &constraint_system,
                witness,
                &net,
                &prover_crs,
                None,
            )
            .unwrap();
            let vk: VerifyingKey<Bn254> = pk.create_vk(&prover_crs, verifier_crs).unwrap();

            // Snapshot after pk-gen: everything so far is the pk-gen phase,
            // and the net totals double as the baseline for the prove phase.
            let pkgen_snapshot = msg_totals(&net.get_connection_stats());
            let pkgen_bytes_snapshot = byte_totals(&net.get_connection_stats());

            let (proof, _) = Rep3CoUltraHonk::<_, Poseidon2Sponge>::prove(
                &net,
                pk,
                &prover_crs,
                ZeroKnowledge::No,
                &vk.inner_vk,
            )
            .unwrap();

            let after = msg_totals(&net.get_connection_stats());
            let after_b = byte_totals(&net.get_connection_stats());
            let pkgen = pkgen_snapshot;
            let prove = (after.0 - pkgen_snapshot.0, after.1 - pkgen_snapshot.1);
            let pkgen_b = pkgen_bytes_snapshot;
            let prove_b = (
                after_b.0 - pkgen_bytes_snapshot.0,
                after_b.1 - pkgen_bytes_snapshot.1,
            );
            (proof, pkgen, prove, pkgen_b, prove_b)
        }));
    }

    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();

    // Sanity check that we ran the real protocol: the proof must match the
    // single-prover known-answer proof bytes.
    let proof_u8 = Poseidon2Sponge::to_buffer(results[0].0.inner_as_ref());
    assert_eq!(proof_u8, std::fs::read(PROOF_FILE).unwrap());

    let measured_pkgen: [(usize, usize); 3] = std::array::from_fn(|i| results[i].1);
    let measured_prove: [(usize, usize); 3] = std::array::from_fn(|i| results[i].2);
    let measured_pkgen_b: [(usize, usize); 3] = std::array::from_fn(|i| results[i].3);
    let measured_prove_b: [(usize, usize); 3] = std::array::from_fn(|i| results[i].4);
    assert_eq!(
        measured_pkgen, PKGEN_MSGS,
        "pk-gen per-party (sent, recv) message totals changed"
    );
    assert_eq!(
        measured_prove, PROVE_MSGS,
        "prove per-party (sent, recv) message totals changed"
    );
    assert_eq!(
        measured_pkgen_b, PKGEN_BYTES,
        "pk-gen per-party (sent, recv) byte totals changed"
    );
    assert_eq!(
        measured_prove_b, PROVE_BYTES,
        "prove per-party (sent, recv) byte totals changed"
    );
}

/// ZK-mode counterpart of `poseidon_prove_comms_message_fence_poseidon2sponge`.
///
/// ZK proof BYTES legitimately vary run-to-run (the masking values are drawn
/// from an unseedable `thread_rng()` inside the proving-key/prove path -- see
/// the share-rerandomization-invariance test's doc comment above for the same
/// finding at the API level), so this test cannot byte-compare against a KAT.
/// But masking only changes the VALUES placed on the wire, not the NUMBER or
/// SHAPE of messages: pinning is still possible if the message counts
/// themselves are deterministic. Measured directly (see PROGRESS): they are,
/// across repeated runs, so this pins EXACT counts rather than a floor. If
/// that ever stops being true (e.g. a masking scheme that conditionally
/// resamples and occasionally sends an extra frame), replace the `assert_eq!`
/// below with a `>=` floor against the non-ZK `PROVE_MSGS` constants above
/// (ZK strictly adds masking communication on top of non-ZK, never removes
/// it) and note the change here.
#[test]
fn poseidon_prove_comms_message_fence_zk_poseidon2sponge() {
    // Per-party (total_sent_msgs, total_received_msgs). Measured directly via
    // `Network::get_connection_stats()`, exactly like the non-ZK fence above.
    // 116 -> 3: big-quad mul_many batched circuit-wide (see the non-ZK fence).
    const PKGEN_MSGS: [(usize, usize); 3] = [(3, 3), (3, 3), (3, 3)];
    // 273 -> 272: array_prod_inner_mul_many mul_many merge (see non-ZK fence).
    // 272 -> 282: L0d half-share commit MSMs — the non-ZK fence's 6 broadcast
    // opens plus the 4 ZK-only commitments (gemini masking poly, libra
    // concatenation, SSIPA grand-sum + quotient), each +1 send/+1 recv.
    const PROVE_MSGS: [(usize, usize); 3] = [(282, 282), (282, 282), (282, 282)];
    // Per-party (total_sent_bytes, total_received_bytes) — the ZK masking
    // values are random but FIXED-LENGTH field elements, so byte totals are
    // deterministic too (measured across repeated runs). See byte_totals'
    // doc comment for what the byte pins catch beyond the message pins.
    // pk-gen byte totals must equal the non-ZK fence's exactly.
    // 30336/30368 -> 29432/29464: big-quad mul_many batched circuit-wide —
    // 113 fewer 8-byte slice length prefixes per direction (see the non-ZK
    // fence).
    const PKGEN_BYTES: [(usize, usize); 3] = [(29432, 29432), (29464, 29432), (29432, 29464)];
    // prove bytes re-pinned with PROVE_MSGS for L0d.
    const PROVE_BYTES: [(usize, usize); 3] =
        [(6276208, 6276208), (6276240, 6276208), (6276208, 6276240)];

    let m = rep3_prove_comms_fence::<Poseidon2Sponge>("poseidon", ZeroKnowledge::Yes, 0xFE_ACE);

    // No byte-KAT cross-check possible in ZK mode (bytes legitimately vary),
    // but the proof must still verify -- rep3_prove_comms_fence's callee
    // (Rep3CoUltraHonk::prove) already asserts protocol success via `.unwrap()`,
    // and `proof` being non-empty plus the exact message-count pins below is
    // the available evidence that the real (masked) protocol ran.
    assert!(!m.proof.is_empty());

    // Non-ZK pk-gen is unaffected by has_zk, so pk-gen counts must match the
    // non-ZK fence exactly -- a cross-check that has_zk didn't leak into the
    // wrong phase.
    assert_eq!(
        m.pkgen_msgs, PKGEN_MSGS,
        "ZK pk-gen per-party (sent, recv) message totals changed (or diverged from non-ZK pk-gen)"
    );
    assert_eq!(
        m.prove_msgs, PROVE_MSGS,
        "ZK prove per-party (sent, recv) message totals changed"
    );
    assert_eq!(
        m.pkgen_bytes, PKGEN_BYTES,
        "ZK pk-gen per-party (sent, recv) byte totals changed"
    );
    assert_eq!(
        m.prove_bytes, PROVE_BYTES,
        "ZK prove per-party (sent, recv) byte totals changed"
    );
}

/// Lookup-gate comms fence: `blackbox_and` lowers `x & y` to REP3's lookup
/// path (2 lookup tables / 12 lookup gates per `co-noir circuit-info`) --
/// structurally distinct from poseidon's pure-arithmetic path. This is the
/// fence upcoming `construct_lookup_read_counts` optimisation work must keep
/// honest: comms here MUST stay nonzero, and this pin is expected to change
/// (deliberately, with the constants updated) the day that lever lands. No
/// proof KAT is checked in for this circuit, so the cross-check oracle is a
/// plain (non-MPC) proof computed in-test via `plain_proof_bytes`.
#[test]
fn blackbox_and_prove_comms_message_fence_poseidon2sponge() {
    // Per-party (total_sent_msgs, total_received_msgs). See the doc comment
    // on `poseidon_prove_comms_message_fence_poseidon2sponge` for the bump
    // policy (increase = investigate a regression; decrease = an
    // optimisation landed, lower deliberately).
    // [(155,203),(185,161),(191,167)] -> [(155,200),(185,158),(185,167)]: merged GC
    // input rounds in the Yao decompose blueprints (mpc-core L0c): -2 sends at ID2,
    // -1 recv at ID0/ID1 per GC invocation (3 invocations in this pk-gen).
    // [(155,200),(185,158),(185,167)] -> [(151,160),(157,154),(157,151)]: L2-1a batched
    // construct_lookup_read_counts. The 12 per-gate Yao a2y2b index
    // bit-decompositions (per-party msgs ID0 (1,4), ID1 (3,1), ID2 (3,2) each) and 12
    // per-gate bit-injection rounds are replaced by ONE Direct a2b_many (19 reshare
    // rounds, all parties symmetric) + ONE bit injection; the per-gate OHV recursion
    // (116 rounds) and tag write_luts (10) were unchanged (L2-1b's target). Per party
    // read-counts msgs after 1a = a2b_many(19)+inject(1)+ohv(116)+tags(10) = (146,146).
    // [(151,160),(157,154),(157,151)] -> current: L2-1b batches the last two terms.
    // The per-gate OHV recursion becomes ONE level-synchronous `ohv_many`
    // (Σ(k-1)=116 -> k_max-1=11 rounds) and the per-gate tag cmux chain becomes ONE
    // batched field OR-tree (Σ(g-1)=10 -> max⌈log2 g⌉=4 rounds). read-counts msgs
    // per party = a2b_many(19)+inject(1)+ohv_many(11)+or_tree(4) = (35,35), i.e. -111
    // symmetric in both directions. Predicted exactly in advance from the round
    // formula (session-19 l2-1b evidence); a2b_many(19)+inject(1) untouched.
    // Limb decomposition now uses Yao input conversion followed by batched bit
    // injection instead of masked field-output garbling. One batched call adds
    // (sent, recv) = [(1,1), (1,0), (1,2)] while reducing the payload below.
    // Proof/KAT equality, proving traffic, and byte tolerances remain pinned.
    const PKGEN_MSGS: [(usize, usize); 3] = [(41, 50), (47, 43), (47, 42)];
    // 199 -> 198: array_prod_inner_mul_many mul_many merge (grand product),
    // NOT a lookup-path change (see the assert message below).
    // 198 -> 204: L0d half-share commit MSMs (see the poseidon fence).
    const PROVE_MSGS: [(usize, usize); 3] = [(204, 204), (204, 204), (204, 204)];
    // Per-party (total_sent_bytes, total_received_bytes); see byte_totals.
    // pk-gen transmits Yao garbled circuits (lookup path), whose
    // serialization length wobbles by ±1 byte run-to-run (see
    // assert_byte_totals_within) — pinned as a tight band. Prove is pure
    // field flows: exact (re-pinned for L0d with PROVE_MSGS).
    // Re-pinned for L2-1a (see PKGEN_MSGS): the per-gate a2y2b garbled adder circuits
    // (~32.5 KB each, ID1->ID0 dominated) disappear; the Direct a2b_many adds ~15.7 KB
    // per party per direction of masked BigUint payloads (value-length encoded, hence
    // still banded). ID0's SENT bytes rise slightly: as the GC evaluator it mostly
    // received; the direct adder is ring-symmetric.
    // Re-pinned for L2-1b (see PKGEN_MSGS): OHV-recursion and OR-tree PAYLOADS are
    // byte-identical to 1a (same reshared ring bits, same Σ(g-1)·L field muls); only
    // the per-frame length prefixes shrink as 116->11 ohv frames + 10->4 tag frames
    // merge, dropping ~1.1 KB per party per direction from the 1a pin
    // [(2676760,4132506),(3969830,2863728),(2888258,2538614)]. Band widened 8->64:
    // the blackbox_and AND lowering's Yao GC serialization (variable-length random
    // wire labels) was measured to drift up to ~13 B/run here (4 runs); ±64 still sits
    // ~20,000x below a real share-limb leak (~32 B x 40,992 elems ≈ 1.3 MB). Prove is
    // pure field flows: exact.
    // v6 port: upstream e2177d9c replaces variable BigUint serialization with
    // fixed-width integers. Message counts and proving traffic are unchanged.
    const PKGEN_BYTES: [(usize, usize); 3] =
        [(2661696, 3999616), (3853200, 2832336), (2856872, 2539816)];
    const PROVE_BYTES: [(usize, usize); 3] = [
        (21040064, 21040064),
        (21040096, 21040064),
        (21040064, 21040096),
    ];

    let m = rep3_prove_comms_fence::<Poseidon2Sponge>("blackbox_and", ZeroKnowledge::No, 0xFE_ACE);

    let expected = plain_proof_bytes::<Poseidon2Sponge>("blackbox_and", ZeroKnowledge::No);
    assert_eq!(
        m.proof, expected,
        "REP3 proof bytes must match the plain (non-MPC) prover on the same witness"
    );

    assert_eq!(
        m.pkgen_msgs, PKGEN_MSGS,
        "pk-gen per-party (sent, recv) message totals changed"
    );
    assert_eq!(
        m.prove_msgs, PROVE_MSGS,
        "prove per-party (sent, recv) message totals changed -- if this DECREASED, check it \
         isn't `construct_lookup_read_counts` (or another lookup step) silently degenerating to \
         local computation: lookup comms must stay nonzero"
    );
    assert_byte_totals_within(
        m.pkgen_bytes,
        PKGEN_BYTES,
        64,
        "pk-gen (GC-bearing, banded) byte totals",
    );
    assert_eq!(
        m.prove_bytes, PROVE_BYTES,
        "prove per-party (sent, recv) byte totals changed"
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

/// Range/delta-range comms fence: `add3u64` (u64 addition with overflow range
/// checks; 1,396 delta-range gates per `co-noir circuit-info`, zero lookup
/// gates) exercises REP3's bit-decomposition / range-check path -- distinct
/// from both poseidon's pure-arithmetic path and blackbox_and's lookup path.
/// A checked-in proof KAT already exists for this circuit (used by the
/// existing `add3u64_*_test_*` tests above), so no plain in-test proof is
/// needed for the cross-check.
#[test]
fn add3u64_prove_comms_message_fence_poseidon2sponge() {
    const PROOF_FILE: &str = "../test_vectors/noir/add3u64/kat/add3u64_proof_with_pos";

    // Per-party (total_sent_msgs, total_received_msgs). See the doc comment
    // on `poseidon_prove_comms_message_fence_poseidon2sponge` for the bump
    // policy.
    // [(146,193),(220,190),(222,205)] -> current: merged GC input rounds in the
    // Yao decompose blueprints (mpc-core L0c): -2 sends at ID2, -1 recv at
    // ID0/ID1 per GC invocation (1 invocation in this pk-gen).
    // Upstream 01296e43 batches sorting's arithmetic-to-binary conversion;
    // e2177d9c also replaces variable BigUint serialization with fixed width.
    // Re-pin only pk-gen: the proving message/byte counts remain unchanged.
    // One batched limb-decomposition call changes from field-output garbling
    // to Yao input conversion plus bit injection: [(+1,+1),(+1,0),(+1,+2)].
    // The lower payload is repinned without changing proof checks or tolerance.
    const PKGEN_MSGS: [(usize, usize); 3] = [(134, 141), (182, 176), (182, 181)];
    // 249 -> 248: array_prod_inner_mul_many mul_many merge (see poseidon fence).
    // 248 -> 254: L0d half-share commit MSMs (see the poseidon fence).
    const PROVE_MSGS: [(usize, usize); 3] = [(254, 254), (254, 254), (254, 254)];
    // Per-party (total_sent_bytes, total_received_bytes); see byte_totals.
    // pk-gen transmits a Yao garbled circuit (delta-range path) — banded like
    // the blackbox_and fence. Prove is pure field flows: exact (re-pinned for
    // L0d with PROVE_MSGS).
    const PKGEN_BYTES: [(usize, usize); 3] =
        [(1647844, 2053684), (2986108, 2474540), (2391760, 2497488)];
    const PROVE_BYTES: [(usize, usize); 3] = [
        (16249680, 16249680),
        (16249712, 16249680),
        (16249680, 16249712),
    ];

    let m = rep3_prove_comms_fence::<Poseidon2Sponge>("add3u64", ZeroKnowledge::No, 0xFE_ACE);

    assert_eq!(m.proof, std::fs::read(PROOF_FILE).unwrap());

    assert_eq!(
        m.pkgen_msgs, PKGEN_MSGS,
        "pk-gen per-party (sent, recv) message totals changed"
    );
    assert_eq!(
        m.prove_msgs, PROVE_MSGS,
        "prove per-party (sent, recv) message totals changed"
    );
    assert_byte_totals_within(
        m.pkgen_bytes,
        PKGEN_BYTES,
        8,
        "pk-gen (GC-bearing, banded) byte totals",
    );
    assert_eq!(
        m.prove_bytes, PROVE_BYTES,
        "prove per-party (sent, recv) byte totals changed"
    );
}

/// A [`Network`] wrapper that copies every sent and received frame into a
/// shared log before/after delegating to the wrapped [`LocalNetwork`]. Used
/// by the T4 view-scan test below to capture one full protocol run's traffic
/// for offline inspection. Test-only by construction (lives in the test
/// crate; production binaries cannot reach it).
struct RecordingNetwork {
    inner: LocalNetwork,
    log: Arc<Mutex<Vec<Bytes>>>,
}

impl RecordingNetwork {
    fn new(inner: LocalNetwork, log: Arc<Mutex<Vec<Bytes>>>) -> Self {
        Self { inner, log }
    }
}

impl Network for RecordingNetwork {
    fn id(&self) -> usize {
        self.inner.id()
    }

    fn send(&self, to: usize, data: Bytes) -> eyre::Result<()> {
        self.log.lock().unwrap().push(data.clone());
        self.inner.send(to, data)
    }

    fn recv(&self, from: usize) -> eyre::Result<Bytes> {
        let data = self.inner.recv(from)?;
        self.log.lock().unwrap().push(data.clone());
        Ok(data)
    }

    fn get_connection_stats(&self) -> ConnectionStats {
        self.inner.get_connection_stats()
    }
}

/// Returns the location of the first 32-byte window in `frames` that matches
/// any pattern in `patterns`, as (frame_index, offset), or None.
fn scan_frames_for_patterns(
    frames: &[Bytes],
    patterns: &HashSet<[u8; 32]>,
) -> Option<(usize, usize)> {
    for (fi, frame) in frames.iter().enumerate() {
        if frame.len() < 32 {
            continue;
        }
        for off in 0..=frame.len() - 32 {
            let window: [u8; 32] = frame[off..off + 32].try_into().unwrap();
            if patterns.contains(&window) {
                return Some((fi, off));
            }
        }
    }
    None
}

/// T4 witness view scan (ch. 24 §5): record EVERY frame sent or received by
/// EVERY party across a full REP3 run -- witness extension, pk-gen and prove
/// -- and assert that no private witness value ever appears in the traffic in
/// plaintext.
///
/// This is the tripwire for the grossest possible MPC-performance-work
/// regression: code that "optimises" by opening (or simply serializing) the
/// witness instead of computing on shares. The message/byte-count fences
/// above can't catch a leak that replaces a masked payload with a plaintext
/// one of the same shape; this scan can.
///
/// Method and honest limits (heuristic, per the ch. 24 §5 spec):
/// - Targets are the KAT witness's PRIVATE values (public inputs are known to
///   everyone and legitimately handled in the clear), filtered to those whose
///   32-byte encoding has at least 16 nonzero bytes, so that low-entropy
///   values (small integers) can't false-positive against structural zeros or
///   length fields in frames. A uniformly random share/masked value matches a
///   specific high-entropy 32-byte pattern with probability ~2^-256 per
///   window -- a hit is a leak, not a coincidence.
/// - Each target is searched in BOTH its canonical little-endian field
///   encoding (what `CanonicalSerialize` puts on the wire) and its raw
///   Montgomery-limb encoding (what a memory-dump-style serialization of an
///   ark field element would emit), at every byte offset of every frame.
/// - What this cannot catch: leaks under any further encoding (compressed,
///   split across frames, arithmetically re-blinded with a KNOWN mask, ...).
///   It is a tripwire, not a proof of privacy.
#[test]
fn poseidon_witness_view_scan_no_plaintext_leak_poseidon2sponge() {
    use ark_ff::BigInteger;

    const PROOF_FILE: &str = "../test_vectors/noir/poseidon/kat/pos_proof_with_pos";
    const NAME: &str = "poseidon";
    let circuit_file = format!("../test_vectors/noir/{NAME}/kat/{NAME}.json");
    let witness_file = format!("../test_vectors/noir/{NAME}/kat/{NAME}.gz");
    let prover_toml = format!("../test_vectors/noir/{NAME}/Prover.toml");

    let program_artifact =
        co_noir::program_artifact_from_reader(File::open(&circuit_file).unwrap())
            .expect("failed to parse program artifact");
    let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
    let public_inputs = constraint_system.public_inputs.clone();

    // Build the plaintext-pattern set from the known (KAT) witness: the
    // values below are exactly what the MPC run computes under sharing, so
    // none of them may ever cross the network in the clear.
    let witness: Vec<Fr> = co_noir::witness_from_reader(File::open(&witness_file).unwrap())
        .expect("failed to parse witness");
    let mut patterns: HashSet<[u8; 32]> = HashSet::new();
    let mut n_targets = 0usize;
    for (index, value) in witness.iter().enumerate() {
        if public_inputs.contains(&(index as u32)) {
            continue;
        }
        let mut canonical = Vec::with_capacity(32);
        value.serialize_uncompressed(&mut canonical).unwrap();
        assert_eq!(canonical.len(), 32);
        if canonical.iter().filter(|&&b| b != 0).count() < 16 {
            continue; // low-entropy value; would false-positive on zeros
        }
        n_targets += 1;
        patterns.insert(canonical.try_into().unwrap());
        // Raw Montgomery limbs (ark's in-memory representation).
        let mont: [u8; 32] = value.0.to_bytes_le().try_into().unwrap();
        patterns.insert(mont);
    }
    // Anti-vacuity: the poseidon witness must supply a healthy number of
    // high-entropy private targets (hash-round intermediates), otherwise the
    // scan below proves nothing.
    assert!(
        n_targets >= 32,
        "too few high-entropy private witness targets ({n_targets}); scan would be vacuous"
    );

    // Anti-vacuity for the scanner itself: it must find a target that we
    // deliberately embed mid-frame.
    let some_pattern = *patterns.iter().next().unwrap();
    let mut planted = vec![0xAB_u8; 7];
    planted.extend_from_slice(&some_pattern);
    planted.extend_from_slice(&[0xCD_u8; 5]);
    assert_eq!(
        scan_frames_for_patterns(&[Bytes::from(planted)], &patterns),
        Some((0, 7)),
        "scanner failed to find a deliberately planted witness value"
    );

    // Full REP3 run -- witext + pk-gen + prove -- with every party's traffic
    // on the single network recorded.
    let log = Arc::new(Mutex::new(Vec::new()));
    let nets = LocalNetwork::new_3_parties().map(|n| RecordingNetwork::new(n, log.clone()));
    let crs_size = co_noir::compute_circuit_size::<Bn254G1>(&constraint_system).unwrap();
    let prover_crs = Arc::new(
        CrsParser::<Bn254G1>::get_crs_g1(CRS_PATH_G1, crs_size, ZeroKnowledge::No).unwrap(),
    );
    let verifier_crs = CrsParser::<Bn254G1>::get_crs_g2::<Bn254>(CRS_PATH_G2).unwrap();

    let mut threads = Vec::with_capacity(3);
    for net in nets {
        let prover_crs = prover_crs.clone();
        let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
        let artifact = program_artifact.clone();
        let prover_toml = prover_toml.clone();
        threads.push(std::thread::spawn(move || {
            let solver = Rep3CoSolver::new(&net, artifact, prover_toml).unwrap();
            let witness = solver.solve().unwrap();
            let witness = co_noir::witness_stack_to_vec_rep3(witness);
            let pk = co_noir::generate_proving_key_rep3(
                &constraint_system,
                witness,
                &net,
                &prover_crs,
                None,
            )
            .unwrap();
            let vk: VerifyingKey<Bn254> = pk.create_vk(&prover_crs, verifier_crs).unwrap();
            let (proof, _) = Rep3CoUltraHonk::<_, Poseidon2Sponge>::prove(
                &net,
                pk,
                &prover_crs,
                ZeroKnowledge::No,
                &vk.inner_vk,
            )
            .unwrap();
            proof
        }));
    }
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();

    // The run must be the real protocol: proof bytes match the plain KAT.
    let proof_u8 = Poseidon2Sponge::to_buffer(results[0].inner_as_ref());
    assert_eq!(proof_u8, std::fs::read(PROOF_FILE).unwrap());

    // Volume sanity: we must actually have captured a full run's traffic.
    let frames = Arc::try_unwrap(log).unwrap().into_inner().unwrap();
    let total_bytes: usize = frames.iter().map(|f| f.len()).sum();
    assert!(
        total_bytes >= 1_000_000,
        "captured only {total_bytes} bytes of traffic; recording is broken"
    );

    // The scan proper: no private witness value, in either encoding, at any
    // offset, in any frame, at any party, in either direction.
    if let Some((frame, offset)) = scan_frames_for_patterns(&frames, &patterns) {
        panic!(
            "PLAINTEXT WITNESS LEAK: witness value found in network traffic \
             (frame {frame} at byte offset {offset} of {} frames / {total_bytes} bytes scanned)",
            frames.len()
        );
    }
}

#[test]
#[ignore = "Expensive full REP3 recursive witness construction and both outer proof modes"]
fn recursion_public_inputs_witness_and_proof_test_poseidon2sponge() {
    // This tests a non-ZK inner proof whose proof, key and inputs are already
    // public to every party. It does not provide private recursive verification.
    for outer_zk in [ZeroKnowledge::No, ZeroKnowledge::Yes] {
        witness_and_proof_test_with_visibility::<Poseidon2Sponge>("recursion", outer_zk, "", true);
    }
}

#[test]
#[ignore = "Expensive private REP3 recursive witness construction with a ZK outer proof"]
fn private_non_zk_recursion_proof_test_poseidon2sponge() {
    proof_test::<Poseidon2Sponge>("recursion_private", ZeroKnowledge::Yes, "");
}

#[test]
#[ignore = "Expensive private REP3 disabled recursive witness construction with a ZK outer proof"]
fn private_disabled_recursion_proof_test_poseidon2sponge() {
    // Same ACIR and private ABI as recursion_private. The hidden predicate is
    // false and one inner sumcheck scalar is corrupt; valid encodings remain.
    proof_test::<Poseidon2Sponge>("recursion_private_disabled", ZeroKnowledge::Yes, "");
}

#[test]
#[ignore = "Expensive private REP3 recursive witness construction with a ZK outer proof"]
fn private_zk_recursion_proof_test_poseidon2sponge() {
    proof_test::<Poseidon2Sponge>("recursion_private_zk", ZeroKnowledge::Yes, "");
}

#[test]
#[ignore = "Test is too slow for the pipeline"]
fn zk_recursion_witness_and_proof_test_poseidon2sponge() {
    witness_and_proof_test::<Poseidon2Sponge>("recursion_zk", ZeroKnowledge::No, "");
    witness_and_proof_test::<Poseidon2Sponge>("recursion_zk", ZeroKnowledge::Yes, "");
}

#[test]
#[ignore = "Expensive full REP3 recursive proof with explicit input disclosure"]
fn non_zk_recursion_explicit_reveal_proof_test_poseidon2sponge() {
    for outer_zk in [ZeroKnowledge::No, ZeroKnowledge::Yes] {
        proof_test_with_recursion_visibility::<Poseidon2Sponge>(
            "recursion",
            outer_zk,
            "",
            co_noir::RecursionInputVisibility::RevealToParticipants,
        );
    }
}

#[test]
#[ignore = "Test is too slow for the pipeline"]
fn zk_recursion_explicit_reveal_proof_test_poseidon2sponge() {
    for outer_zk in [ZeroKnowledge::No, ZeroKnowledge::Yes] {
        proof_test_with_recursion_visibility::<Poseidon2Sponge>(
            "recursion_zk",
            outer_zk,
            "",
            co_noir::RecursionInputVisibility::RevealToParticipants,
        );
    }
}

/// Loads the committed comms floor-table: median per-phase, per-party
/// framed-message/byte totals from the 2026-07-25 full 12-circuit bench run
/// (`bench-results/2026-07-25/netstats/`), PLUS a separate in-process
/// LocalNetwork baseline for the slow test below. See the embedded
/// `_provenance` object for methodology, phase definitions, and known data
/// anomalies (sha256 family REP3-prove timeout/pruning, party asymmetry,
/// and -- found while landing the slow test below -- a large gap between
/// in-process and cross-process message/byte counts at high data volumes).
fn comms_floor_table() -> serde_json::Value {
    let raw = include_str!("rep3_comms_floor_table.json");
    serde_json::from_str(raw).expect("rep3_comms_floor_table.json must parse as JSON")
}

/// Reads the `total_msgs` in-process baseline for `circuit`/`phase` out of
/// `circuits_inprocess_baseline` (NOT the cross-process `circuits` section --
/// see that section's `_methodology` and `_provenance.known_anomalies` for
/// why the two are not comparable at this data volume).
fn inprocess_baseline_total_msgs(table: &serde_json::Value, circuit: &str, phase: &str) -> u64 {
    table["circuits_inprocess_baseline"][circuit][phase]["total_msgs"]
        .as_u64()
        .unwrap_or_else(|| {
            panic!(
                "no in-process baseline for {circuit}/{phase} in \
                 rep3_comms_floor_table.json `circuits_inprocess_baseline`"
            )
        })
}

/// T2-proper: end-to-end comms BAND fence for a mid-size circuit. Unlike the
/// exact-pin fences above, this asserts each phase's total message count
/// falls inside `[0.5x, 2x]` of a measured baseline (ch. 24 §5's band idea):
/// loose enough to tolerate implementation-detail drift across a full
/// end-to-end run (real witness extension via `Rep3CoSolver` + pk-gen +
/// prove, three genuine REP3 parties), tight enough to catch both a silent
/// protocol-skip (comms collapsing towards 0 -- the "optimisation" that
/// stops doing the MPC) and an accidental round explosion (10x+ blow-up).
///
/// `bb_sha256_compression` was chosen over the poseidon/sha256 size sweeps
/// because per `bench-results/2026-07-25/RESULTS.md` it is the only "big"
/// circuit in the 12-circuit matrix with COMPLETE REP3 netstats: the sha256
/// 2^16-2^20 sweep's REP3 prove either hit the 600s cell timeout (2^16) or
/// was never attempted at all (2^17-2^20, family pruned after that timeout)
/// -- see `_provenance.known_anomalies` in the floor table JSON. It also
/// exercises the lookup-heavy path at scale (2,896 lookup gates / 12 tables
/// / 33,944 table rows per `co-noir circuit-info`), unlike poseidon.
///
/// The band is checked against `circuits_inprocess_baseline` in the floor
/// table, NOT the cross-process `circuits` bench data, for a reason found
/// while landing this test: `bench-results/2026-07-25/RESULTS.md` measured
/// ~140s wall-clock and ~268k total messages / ~17.2GB total bytes for a
/// cross-process (3 independent OS processes, real TCP loopback) REP3 run of
/// this circuit's prove phase. This test's in-process `LocalNetwork` harness
/// (matching every other test in this file: 3 `std::thread::spawn` "parties"
/// sharing one process and one 16-thread rayon pool) instead measures ~2.5k
/// messages / ~1.07GB bytes and finishes in ~5-6s -- ~100x fewer messages,
/// ~16x fewer bytes, ~25x faster -- for a PROVABLY CORRECT run (the proof
/// byte-matches the plain-prover KAT below). That is a real measurement-
/// methodology gap (see `_provenance.known_anomalies` for the numbers and
/// what was and wasn't verified about its cause), not a protocol difference,
/// so comparing this harness's counts against the cross-process floor would
/// be comparing two different things and either need a permanently-loose
/// band or spuriously fail. `#[ignore]`-gated: milestone/acceptance runs
/// only, never fast-check or CI's default tier (it is the heaviest test in
/// this file even at ~5-6s).
#[test]
#[ignore = "slow relative to the rest of this file (~5-6s, full REP3 witext+pkgen+prove on \
            the lookup-heavy bb_sha256_compression circuit): milestone/acceptance runs only"]
fn bb_sha256_compression_comms_band_fence_poseidon2sponge() {
    const NAME: &str = "bb_sha256_compression";
    let circuit_file = format!("../test_vectors/noir/{NAME}/kat/{NAME}.json");
    let prover_toml = format!("../test_vectors/noir/{NAME}/Prover.toml");

    let program_artifact =
        co_noir::program_artifact_from_reader(File::open(&circuit_file).unwrap())
            .expect("failed to parse program artifact");
    let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);

    let nets = LocalNetwork::new_3_parties();
    let crs_size = co_noir::compute_circuit_size::<Bn254G1>(&constraint_system).unwrap();
    let prover_crs = Arc::new(
        CrsParser::<Bn254G1>::get_crs_g1(CRS_PATH_G1, crs_size, ZeroKnowledge::No).unwrap(),
    );
    let verifier_crs = CrsParser::<Bn254G1>::get_crs_g2::<Bn254>(CRS_PATH_G2).unwrap();

    let mut threads = Vec::with_capacity(3);
    for net in nets {
        let prover_crs = prover_crs.clone();
        let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
        let artifact = program_artifact.clone();
        let prover_toml = prover_toml.clone();
        threads.push(std::thread::spawn(move || {
            let solver = Rep3CoSolver::new(&net, artifact, prover_toml).unwrap();
            let witness = solver.solve().unwrap();
            let witness = co_noir::witness_stack_to_vec_rep3(witness);

            // Snapshot after witext on the single network.
            // (Byte totals were also inspected while
            // landing this test -- see the doc comment above and the floor
            // table's `known_anomalies` for the in-process-vs-cross-process
            // byte comparison; only message counts are asserted below.)
            let witext_snapshot = msg_totals(&net.get_connection_stats());
            let witext_total = witext_snapshot.0 + witext_snapshot.1;

            let pk = co_noir::generate_proving_key_rep3(
                &constraint_system,
                witness,
                &net,
                &prover_crs,
                None,
            )
            .unwrap();
            let vk: VerifyingKey<Bn254> = pk.create_vk(&prover_crs, verifier_crs).unwrap();

            // pk-gen delta since the witext snapshot.
            let pkgen_snapshot = msg_totals(&net.get_connection_stats());
            let pkgen_total =
                pkgen_snapshot.0 - witext_snapshot.0 + pkgen_snapshot.1 - witext_snapshot.1;

            let (proof, _) = Rep3CoUltraHonk::<_, Poseidon2Sponge>::prove(
                &net,
                pk,
                &prover_crs,
                ZeroKnowledge::No,
                &vk.inner_vk,
            )
            .unwrap();

            // Prove delta on the same network since the pk-gen snapshot.
            let after_stats = msg_totals(&net.get_connection_stats());
            let prove_total =
                (after_stats.0 - pkgen_snapshot.0) + (after_stats.1 - pkgen_snapshot.1);

            // "prove_nonzk" in the floor table combines pk-gen and prove;
            // see rep3_comms_floor_table.json
            // `_provenance.phase_definitions`.
            let prove_nonzk_total = pkgen_total + prove_total;

            (proof, witext_total, prove_nonzk_total)
        }));
    }

    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();

    // Cross-check against a plain (non-MPC) proof computed in-test: no KAT
    // proof file is checked in for this circuit.
    let proof_u8 = Poseidon2Sponge::to_buffer(results[0].0.inner_as_ref());
    let expected = plain_proof_bytes::<Poseidon2Sponge>(NAME, ZeroKnowledge::No);
    assert_eq!(
        proof_u8, expected,
        "REP3 proof bytes must match the plain (non-MPC) prover on the same witness"
    );
    for (i, r) in results.iter().enumerate() {
        let bytes_i = Poseidon2Sponge::to_buffer(r.0.inner_as_ref());
        assert_eq!(bytes_i, expected, "party {i} proof bytes diverged");
    }

    let measured_witext_total: u64 = results.iter().map(|r| r.1 as u64).sum();
    let measured_prove_total: u64 = results.iter().map(|r| r.2 as u64).sum();

    let table = comms_floor_table();
    let baseline_witext = inprocess_baseline_total_msgs(&table, NAME, "witext");
    let baseline_prove = inprocess_baseline_total_msgs(&table, NAME, "prove_nonzk");

    let band = |measured: u64, baseline: u64, label: &str| {
        let lo = baseline as f64 * 0.5;
        let hi = baseline as f64 * 2.0;
        assert!(
            (measured as f64) >= lo && (measured as f64) <= hi,
            "{label}: measured total_msgs={measured} outside [0.5x, 2x] of the in-process \
             LocalNetwork baseline={baseline} (band=[{lo}, {hi}]) from \
             rep3_comms_floor_table.json `circuits_inprocess_baseline` -- a value BELOW the \
             band suggests a silent protocol-skip (comms collapsed); ABOVE suggests a \
             round/message explosion"
        );
    };
    band(measured_witext_total, baseline_witext, "witext");
    band(
        measured_prove_total,
        baseline_prove,
        "prove_nonzk (pk-gen + prove combined)",
    );
}

/// L0e evidence + referee: full 3-party REP3 pk-gen + prove of `bb_sha256_compression` from a
/// SHARED KAT witness. Unlike the band fence above (whose `Prover.toml` inputs enter the solver
/// as PUBLIC AcvmTypes via `Rep3CoSolver::new`, so its sha-gadget plookup reads all take the
/// public branch), this shares every private witness value like `proof_test` does — the profiled
/// case where the builder's sha gadget issues its per-read driver calls on shared keys. It is
/// therefore the byte-level referee for the L0e sha-gadget work (design §5.3-U3/§5.4):
///
/// - runs TWO reps with DIFFERENT sharing randomness: per-rep pk-gen wall time + pk-gen comms
///   deltas are printed as evidence, and the two reps' proof/VK bytes must be IDENTICAL
///   (sha-path share-rerandomization invariance, the sha analog of
///   `poseidon_proof_share_rerandomization_invariance_poseidon2sponge`);
/// - asserts all 3 parties' proof and VK bytes agree and the proof byte-matches the plain
///   (non-MPC) prover on the same witness — any sha read served with a wrong VALUE anywhere
///   fails here;
/// - if `U3_EVIDENCE_DIR` is set, writes each party's proof and VK bytes there for external
///   md5 comparison across code versions (the L0e before/after gate).
///
/// `#[ignore]`-gated: pk-gen from shared witness replays the full sha-gadget MPC cost
/// (~2×140 s per rep before L0e-U3; seconds after), milestone/acceptance runs only.
#[test]
#[ignore = "slow (full shared-witness REP3 pk-gen+prove on the sha-gadget circuit, 2 reps): \
            L0e milestone/acceptance evidence runs only"]
fn bb_sha256_compression_shared_witness_proof_evidence_poseidon2sponge() {
    shared_witness_proof_evidence_poseidon2sponge(
        "bb_sha256_compression",
        [(0, 0x10E03A), (1, 0x10E03B)],
    );
}

/// `blackbox_and` analog of the shared-witness evidence test above (same helper): a SMALL
/// lookup-path circuit (2 tables / 12 lookup gates), used as the cheap before/after
/// md5 + pk-gen-wall evidence harness for lookup-path levers (L2-1a's "measure the
/// plumbing early on a small circuit" gate) without paying the sha-sized run.
#[test]
#[ignore = "evidence harness (2 full REP3 pk-gen+prove reps from a shared witness): \
            milestone/acceptance evidence runs only"]
fn blackbox_and_shared_witness_proof_evidence_poseidon2sponge() {
    shared_witness_proof_evidence_poseidon2sponge("blackbox_and", [(0, 0x10E03A), (1, 0x10E03B)]);
}

/// Shared body of the `*_shared_witness_proof_evidence_poseidon2sponge` tests: full 3-party
/// REP3 pk-gen + prove of `name` from a SHARED KAT witness, two reps with different sharing
/// randomness; prints per-rep pk-gen wall + comms, asserts cross-party/cross-rep proof+VK
/// byte-identity and byte-equality to the plain prover, and (if `U3_EVIDENCE_DIR` is set)
/// writes `{name}_proof_rep{rep}_party{party}` / `{name}_vk_rep{rep}_party{party}` files
/// there for external md5 comparison across code versions.
fn shared_witness_proof_evidence_poseidon2sponge(name: &str, reps: [(u32, u64); 2]) {
    let circuit_file = format!("../test_vectors/noir/{name}/kat/{name}.json");
    let witness_file = format!("../test_vectors/noir/{name}/kat/{name}.gz");

    let program_artifact =
        co_noir::program_artifact_from_reader(File::open(&circuit_file).unwrap())
            .expect("failed to parse program artifact");
    let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
    let witness: Vec<Fr> = co_noir::witness_from_reader(File::open(&witness_file).unwrap())
        .expect("failed to parse witness");

    // The referee: plain (non-MPC) proof bytes on the same witness.
    let expected = plain_proof_bytes::<Poseidon2Sponge>(name, ZeroKnowledge::No);
    let evidence_dir = std::env::var_os("U3_EVIDENCE_DIR").map(std::path::PathBuf::from);
    if let Some(dir) = &evidence_dir {
        std::fs::create_dir_all(dir).unwrap();
    }

    let mut rep_proofs: Vec<Vec<u8>> = Vec::new();
    let mut rep_vks: Vec<Vec<u8>> = Vec::new();
    for (rep, seed) in reps {
        let mut rng = StdRng::seed_from_u64(seed);
        let witnesses = split_witness(&witness, &constraint_system.public_inputs, &mut rng);

        let nets = LocalNetwork::new_3_parties();
        let crs_size = co_noir::compute_circuit_size::<Bn254G1>(&constraint_system).unwrap();
        let prover_crs = Arc::new(
            CrsParser::<Bn254G1>::get_crs_g1(CRS_PATH_G1, crs_size, ZeroKnowledge::No).unwrap(),
        );
        let verifier_crs = CrsParser::<Bn254G1>::get_crs_g2::<Bn254>(CRS_PATH_G2).unwrap();

        let mut threads = Vec::with_capacity(3);
        for (net, witness) in izip!(nets, witnesses) {
            let prover_crs = prover_crs.clone();
            let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
            threads.push(std::thread::spawn(move || {
                let before_stats = net.get_connection_stats();
                let start = std::time::Instant::now();
                let pk = co_noir::generate_proving_key_rep3(
                    &constraint_system,
                    witness,
                    &net,
                    &prover_crs,
                    None,
                )
                .unwrap();
                let pkgen_time = start.elapsed();
                let after_stats = net.get_connection_stats();
                let (sent_msgs, recv_msgs) = {
                    let (s0, r0) = msg_totals(&after_stats);
                    let (bs0, br0) = msg_totals(&before_stats);
                    (s0 - bs0, r0 - br0)
                };
                let (sent_bytes, recv_bytes) = {
                    let (s0, r0) = byte_totals(&after_stats);
                    let (bs0, br0) = byte_totals(&before_stats);
                    (s0 - bs0, r0 - br0)
                };

                let vk: VerifyingKey<Bn254> = pk.create_vk(&prover_crs, verifier_crs).unwrap();
                let (proof, public_input) = Rep3CoUltraHonk::<_, Poseidon2Sponge>::prove(
                    &net,
                    pk,
                    &prover_crs,
                    ZeroKnowledge::No,
                    &vk.inner_vk,
                )
                .unwrap();
                (
                    proof,
                    public_input,
                    vk,
                    pkgen_time,
                    (sent_msgs, recv_msgs, sent_bytes, recv_bytes),
                )
            }));
        }

        let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();

        for (party, (_, _, _, pkgen_time, (sm, rm, sb, rb))) in results.iter().enumerate() {
            println!(
                "[evidence {name}] rep {rep} party {party}: pk-gen {:.3} s; pk-gen comms \
                 (single network): sent {sm} msgs / {sb} B, recv {rm} msgs / {rb} B",
                pkgen_time.as_secs_f64()
            );
        }

        let proof_u8 = Poseidon2Sponge::to_buffer(results[0].0.inner_as_ref());
        let vk_u8 = results[0].2.inner_vk.to_buffer();
        for (party, r) in results.iter().enumerate() {
            let party_proof = Poseidon2Sponge::to_buffer(r.0.inner_as_ref());
            assert_eq!(
                party_proof, proof_u8,
                "rep {rep} party {party} proof diverged"
            );
            let party_vk = r.2.inner_vk.to_buffer();
            assert_eq!(party_vk, vk_u8, "rep {rep} party {party} VK diverged");
            if let Some(dir) = &evidence_dir {
                std::fs::write(
                    dir.join(format!("{name}_proof_rep{rep}_party{party}")),
                    &party_proof,
                )
                .unwrap();
                std::fs::write(
                    dir.join(format!("{name}_vk_rep{rep}_party{party}")),
                    &party_vk,
                )
                .unwrap();
            }
        }
        assert_eq!(
            proof_u8, expected,
            "rep {rep}: REP3 proof bytes must match the plain (non-MPC) prover"
        );
        let is_valid = UltraHonk::<Bn254G1, Poseidon2Sponge>::verify(
            results[0].0.clone(),
            &results[0].1,
            &results[0].2,
            ZeroKnowledge::No,
        )
        .unwrap();
        assert!(is_valid, "rep {rep}: proof must verify");

        rep_proofs.push(proof_u8);
        rep_vks.push(vk_u8);
    }

    // Sha-path share-rerandomization invariance: fresh sharing randomness must not move a byte.
    assert_eq!(
        rep_proofs[0], rep_proofs[1],
        "proof bytes must not depend on the sharing randomness"
    );
    assert_eq!(
        rep_vks[0], rep_vks[1],
        "VK bytes must not depend on the sharing randomness"
    );
}

/// Computes the ZK plaindriver (single-prover, `PlainUltraHonkDriver`) proof bytes for a
/// circuit's KAT witness with the ZK masking values drawn deterministically from
/// `zk_blinding` (seedable-ZK-blinding fence; see
/// `co_noir_common::zk_masking`). Mirrors `plain_proof_bytes` above, but ZK-only and
/// seeded. Asserts the proof verifies before returning the bytes.
fn plaindriver_zk_seeded_proof_bytes<H: TranscriptHasher<TranscriptFieldType>>(
    name: &str,
    zk_blinding: &SeededZkBlinding,
) -> Vec<u8> {
    let has_zk = ZeroKnowledge::Yes;
    let circuit_file = format!("../test_vectors/noir/{name}/kat/{name}.json");
    let witness_file = format!("../test_vectors/noir/{name}/kat/{name}.gz");

    let constraint_system =
        co_noir::constraint_system_from_reader(File::open(&circuit_file).unwrap())
            .expect("failed to parse constraint system");
    let witness = co_noir::witness_from_reader(File::open(&witness_file).unwrap())
        .expect("failed to parse witness");

    let mut driver = PlainAcvmSolver::new();
    let recursion_crs_size = constraint_system.get_honk_recursion_public_inputs_size::<Bn254G1>();
    let recursion_crs = if recursion_crs_size > 0 {
        CrsParser::<Bn254G1>::get_crs_g1(CRS_PATH_G1, recursion_crs_size, has_zk).unwrap()
    } else {
        ProverCrs::default()
    };
    let builder = UltraCircuitBuilder::<Bn254G1>::create_circuit(
        &constraint_system,
        0,
        witness,
        HonkRecursion::UltraHonk,
        &recursion_crs,
        &mut driver,
    )
    .unwrap();

    let crs_size = builder.compute_dyadic_size();
    let (prover_crs, verifier_crs) =
        CrsParser::<Bn254G1>::get_crs::<Bn254>(CRS_PATH_G1, CRS_PATH_G2, crs_size, has_zk)
            .expect("failed to get crs")
            .split();
    let (proving_key, inner_vk) = proving_key::create_keys_barretenberg::<
        Bn254G1,
        PlainUltraHonkDriver,
        _,
    >(0, builder, &prover_crs, &mut driver)
    .unwrap();
    let verifying_key = VerifyingKey {
        crs: verifier_crs,
        inner_vk,
    };

    let (proof, public_input) =
        CoUltraHonk::<PlainUltraHonkDriver, _, H>::prove_with_seeded_zk_blinding(
            proving_key,
            &prover_crs,
            has_zk,
            &verifying_key.inner_vk,
            zk_blinding,
        )
        .unwrap();

    let is_valid =
        UltraHonk::<_, H>::verify::<Bn254>(proof.clone(), &public_input, &verifying_key, has_zk)
            .unwrap();
    assert!(is_valid, "seeded plaindriver ZK proof must verify");

    H::to_buffer(proof.inner_as_ref())
}

/// Runs the full 3-party REP3 ZK proving flow with the ZK masking values drawn
/// deterministically from `zk_blinding` (all parties get the same source, exactly like they
/// would agree on masking randomness out of band). Returns each party's serialized proof
/// bytes plus party 0's (proof, public inputs, vk) so the caller can order the
/// verification assert AFTER its byte-parity asserts (red-validation then fails at the
/// parity assert, the sharpest signal).
#[expect(clippy::type_complexity)]
fn rep3_zk_seeded_proof_bytes_per_party<H: TranscriptHasher<TranscriptFieldType>>(
    program_artifact: &ProgramArtifact,
    witnesses: [Vec<Rep3Type<Fr>>; 3],
    zk_blinding: &SeededZkBlinding,
) -> (
    [Vec<u8>; 3],
    HonkProof<H::DataType>,
    Vec<H::DataType>,
    VerifyingKey<Bn254>,
) {
    let has_zk = ZeroKnowledge::Yes;
    let nets = LocalNetwork::new_3_parties();
    let mut threads = Vec::with_capacity(3);
    let constraint_system = co_noir::get_constraint_system_from_artifact(program_artifact);
    let crs_size = co_noir::compute_circuit_size::<Bn254G1>(&constraint_system).unwrap();
    let prover_crs =
        Arc::new(CrsParser::<Bn254G1>::get_crs_g1(CRS_PATH_G1, crs_size, has_zk).unwrap());
    let verifier_crs = CrsParser::<Bn254G1>::get_crs_g2::<Bn254>(CRS_PATH_G2).unwrap();
    for (net, witness) in izip!(nets, witnesses) {
        let prover_crs = prover_crs.clone();
        let constraint_system = co_noir::get_constraint_system_from_artifact(program_artifact);
        let zk_blinding = zk_blinding.clone();
        threads.push(std::thread::spawn(move || {
            let pk = co_noir::generate_proving_key_rep3(
                &constraint_system,
                witness,
                &net,
                &prover_crs,
                None,
            )
            .unwrap();
            let vk: VerifyingKey<Bn254> = pk.create_vk(&prover_crs, verifier_crs).unwrap();

            let (proof, public_input) = Rep3CoUltraHonk::<_, H>::prove_with_seeded_zk_blinding(
                &net,
                pk,
                &prover_crs,
                has_zk,
                &vk.inner_vk,
                &zk_blinding,
            )
            .unwrap();
            (proof, public_input, vk)
        }));
    }

    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    let bytes: [Vec<u8>; 3] = std::array::from_fn(|i| H::to_buffer(results[i].0.inner_as_ref()));
    let (proof, public_input, vk) = results.into_iter().next().unwrap();
    (bytes, proof, public_input, vk)
}

/// Seedable-ZK-blinding byte-parity fence (plaindriver vs REP3, ZK mode).
///
/// ZK proof bytes normally can't be cross-checked between drivers because the masking
/// randomness comes from an unseedable secure RNG (see the ZK comms fence's doc comment
/// above). This fence closes that gap: with the SAME witness and the SAME injected blinding
/// randomness (`SeededZkBlinding`, testing-only API), the plaindriver ZK proof and all
/// three REP3 parties' ZK proofs must be BYTE-IDENTICAL -- the strongest possible statement
/// that the MPC ZK path computes exactly the plain protocol, masking included. Also pins:
/// - determinism: same seed twice => identical bytes;
/// - anti-vacuity: a different seed => different bytes, and seeded != unseeded
///   (overwhelmingly), so the parity assert can't pass by comparing constants.
#[test]
fn zk_blinding_seeded_plaindriver_rep3_byte_parity_poseidon2sponge() {
    let circuit_file = "../test_vectors/noir/poseidon/kat/poseidon.json";
    let witness_file = "../test_vectors/noir/poseidon/kat/poseidon.gz";

    let program_artifact = co_noir::program_artifact_from_reader(File::open(circuit_file).unwrap())
        .expect("failed to parse program artifact");
    let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
    let witness = co_noir::witness_from_reader(File::open(witness_file).unwrap()).unwrap();

    let seed_a = SeededZkBlinding::from_u64(0x5EED_B11D);
    let seed_b = SeededZkBlinding::from_u64(0x0DD5_EED5);

    // Plaindriver, seed A, twice: seeded proving must be deterministic.
    let plain_a = plaindriver_zk_seeded_proof_bytes::<Poseidon2Sponge>("poseidon", &seed_a);
    let plain_a_again = plaindriver_zk_seeded_proof_bytes::<Poseidon2Sponge>("poseidon", &seed_a);
    assert_eq!(
        plain_a, plain_a_again,
        "same blinding seed must reproduce identical proof bytes"
    );

    // Anti-vacuity 1: a different seed must change the bytes (the seed actually reaches
    // the committed masking values).
    let plain_b = plaindriver_zk_seeded_proof_bytes::<Poseidon2Sponge>("poseidon", &seed_b);
    assert_ne!(
        plain_a, plain_b,
        "different blinding seeds must produce different ZK proof bytes"
    );

    // Anti-vacuity 2: seeded vs unseeded (secure-RNG) bytes differ overwhelmingly. This
    // also re-runs the existing unseeded ZK plaindriver prove+verify path, pinning that the
    // default path still works alongside the new API.
    let plain_unseeded = plain_proof_bytes::<Poseidon2Sponge>("poseidon", ZeroKnowledge::Yes);
    assert_ne!(
        plain_a, plain_unseeded,
        "seeded proof bytes must differ from a secure-RNG (unseeded) run"
    );

    // REP3, seed A: every party's ZK proof bytes must equal the plaindriver's.
    let mut rng = StdRng::seed_from_u64(0xFE_ACE);
    let witnesses = split_witness(&witness, &constraint_system.public_inputs, &mut rng);
    let (rep3_bytes, proof, public_input, vk) = rep3_zk_seeded_proof_bytes_per_party::<
        Poseidon2Sponge,
    >(&program_artifact, witnesses, &seed_a);
    for (i, party_bytes) in rep3_bytes.iter().enumerate() {
        assert_eq!(
            party_bytes, &plain_a,
            "REP3 party {i}'s seeded ZK proof bytes must equal the plaindriver's"
        );
    }

    // And the (shared) REP3 proof must verify.
    let is_valid = UltraHonk::<Bn254G1, Poseidon2Sponge>::verify(
        proof,
        &public_input,
        &vk,
        ZeroKnowledge::Yes,
    )
    .unwrap();
    assert!(is_valid, "seeded REP3 ZK proof must verify");
}

#[test]
fn lookup_chunk_boundaries_preserve_shared_proof() {
    let name = "blackbox_and";
    let artifact = co_noir::program_artifact_from_reader(
        File::open(format!("../test_vectors/noir/{name}/kat/{name}.json")).unwrap(),
    )
    .unwrap();
    let constraint_system = co_noir::get_constraint_system_from_artifact(&artifact);
    let witness = co_noir::witness_from_reader(
        File::open(format!("../test_vectors/noir/{name}/kat/{name}.gz")).unwrap(),
    )
    .unwrap();
    let expected = plain_proof_bytes::<Poseidon2Sponge>(name, ZeroKnowledge::No);
    for batch_size in [Some(1), Some(3), Some(7), None, Some(0)] {
        let mut rng = StdRng::seed_from_u64(0xC0_10_0B);
        let shares = split_witness(&witness, &constraint_system.public_inputs, &mut rng);
        let proof = prove_rep3_with_lookup_batch_size::<Poseidon2Sponge>(
            &artifact,
            shares,
            ZeroKnowledge::No,
            batch_size,
        );
        assert_eq!(proof, expected, "lookup batch size {batch_size:?}");
    }
}

/// Real secret-index ROM regression for the memory LogUp accumulators. In v6,
/// dropping r6/r7 when merging sumcheck chunks breaks even honest proofs.
/// Exercise independent thread schedules, both transcript modes, and ZK.
#[test]
fn rom_logup_shared_proofs_match_v6_oracle() {
    for num_threads in [1, 4] {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build()
            .unwrap();
        pool.install(|| {
            for has_zk in [ZeroKnowledge::No, ZeroKnowledge::Yes] {
                proof_test::<Poseidon2Sponge>(
                    "rom_shared",
                    has_zk,
                    "../test_vectors/noir/rom_shared/kat/rom_shared_proof_with_pos",
                );
                proof_test::<Keccak256>(
                    "rom_shared",
                    has_zk,
                    "../test_vectors/noir/rom_shared/kat/rom_shared_proof_with_kec",
                );
            }
        });
    }
    // The plain MPC driver uses the same chunk accumulator plumbing. Check it
    // independently against BB, rather than using it as the only MPC oracle.
    assert_eq!(
        plain_proof_bytes::<Poseidon2Sponge>("rom_shared", ZeroKnowledge::No),
        std::fs::read("../test_vectors/noir/rom_shared/kat/rom_shared_proof_with_pos").unwrap(),
    );
    assert_eq!(
        plain_proof_bytes::<Keccak256>("rom_shared", ZeroKnowledge::No),
        std::fs::read("../test_vectors/noir/rom_shared/kat/rom_shared_proof_with_kec").unwrap(),
    );
}

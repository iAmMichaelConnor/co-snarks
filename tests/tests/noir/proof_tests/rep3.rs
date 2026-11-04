use crate::proof_tests::{CRS_PATH_G1, CRS_PATH_G2};
use ark_bn254::{Bn254, Fr};
use co_acvm::solver::Rep3CoSolver;
use co_noir::{Bn254G1, HonkProof, RecursionInputVisibility};
use co_noir_common::{
    crs::parse::CrsParser,
    honk_proof::TranscriptFieldType,
    keys::verification_key::VerifyingKey,
    transcript::{Poseidon2Sponge, TranscriptHasher},
    types::ZeroKnowledge,
};
use co_noir_types::Rep3Type;
use co_ultrahonk::prelude::{Rep3CoUltraHonk, UltraHonk};
use itertools::izip;
use mpc_core::protocols::rep3::share_field_element;
use mpc_net::{bytes::Bytes, local::LocalNetwork, ConnectionStats, Network};
use sha3::Keccak256;
use std::{
    collections::HashSet,
    fs::File,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

fn proof_test<H: TranscriptHasher<TranscriptFieldType>>(
    name: &str,
    has_zk: ZeroKnowledge,
    proof_file: &str,
) {
    proof_test_with_visibility::<H>(
        name,
        &format!("../test_vectors/noir/{name}/kat"),
        has_zk,
        proof_file,
        RecursionInputVisibility::default(),
    )
}

/// Like [`proof_test`], for the circuit and witness `{name}.json` and `{name}.gz` in `dir`.
fn proof_test_with_visibility<H: TranscriptHasher<TranscriptFieldType>>(
    name: &str,
    dir: &str,
    has_zk: ZeroKnowledge,
    proof_file: &str,
    recursion_input_visibility: RecursionInputVisibility,
) {
    let circuit_file = format!("{dir}/{name}.json");
    let witness_file = format!("{dir}/{name}.gz");

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

    let nets = LocalNetwork::new_3_parties();
    let mut threads = Vec::with_capacity(3);
    let crs_size = co_noir::compute_circuit_size::<Bn254G1>(&constraint_system).unwrap();
    let prover_crs =
        Arc::new(CrsParser::<Bn254G1>::get_crs_g1(CRS_PATH_G1, crs_size, has_zk).unwrap());
    // Get vk
    let verifier_crs = CrsParser::<Bn254G1>::get_crs_g2::<Bn254>(CRS_PATH_G2).unwrap();
    for (net, witness) in izip!(nets, witnesses) {
        let prover_crs = prover_crs.clone();
        let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
        threads.push(std::thread::spawn(move || {
            // generate proving key and vk
            let pk = co_noir::generate_proving_key_rep3_with_recursion_input_visibility(
                &constraint_system,
                witness,
                &net,
                &prover_crs,
                recursion_input_visibility,
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

    let nets = LocalNetwork::new_3_parties();
    let mut threads = Vec::with_capacity(3);
    let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
    let crs_size = co_noir::compute_circuit_size::<Bn254G1>(&constraint_system).unwrap();
    let prover_crs =
        Arc::new(CrsParser::<Bn254G1>::get_crs_g1(CRS_PATH_G1, crs_size, has_zk).unwrap());
    // Get vk
    let verifier_crs = CrsParser::<Bn254G1>::get_crs_g2::<Bn254>(CRS_PATH_G2).unwrap();
    let vk = co_noir::generate_vk::<Bn254>(&constraint_system, prover_crs.clone(), verifier_crs)
        .unwrap();
    for net in nets {
        let prover_crs = prover_crs.clone();
        let vk = vk.clone();
        let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
        let artifact = program_artifact.clone();
        let prover_toml = prover_toml.clone();
        threads.push(std::thread::spawn(move || {
            let solver = Rep3CoSolver::new(&net, artifact, prover_toml).unwrap();
            let witness = solver.solve().unwrap();
            let witness = co_noir::witness_stack_to_vec_rep3(witness);
            // generate proving key and vk
            let pk =
                co_noir::generate_proving_key_rep3(&constraint_system, witness, &net, &prover_crs)
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

/// A [`Network`] that records every frame a party sends or receives.
struct RecordingNetwork {
    inner: LocalNetwork,
    log: Arc<Mutex<Vec<Bytes>>>,
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

/// Returns the first (frame, offset) at which a 32-byte window of `frames` is one of `patterns`.
fn find_pattern(frames: &[Bytes], patterns: &HashSet<[u8; 32]>) -> Option<(usize, usize)> {
    frames.iter().enumerate().find_map(|(index, frame)| {
        frame
            .windows(32)
            .position(|window| patterns.contains(<&[u8; 32]>::try_from(window).unwrap()))
            .map(|offset| (index, offset))
    })
}

/// Records all traffic of a full REP3 run from secret-shared inputs (witness extension, proving key and proof) and
/// checks that no private witness value is sent in plaintext, in its canonical or its Montgomery little-endian
/// encoding, at any offset of any frame. Only values with at least 16 nonzero bytes are searched, so small values
/// cannot match structural bytes by chance; a uniformly random share matches a given 32-byte pattern with
/// probability 2^-256. This is a tripwire for code that sends a witness value where a share or a masked value
/// belongs, not a privacy proof: opening a value sends only shares, and values that are encoded differently or
/// split across frames are not found.
#[test]
fn poseidon_network_traffic_contains_no_plaintext_witness() {
    use ark_ff::{BigInteger, PrimeField};

    const PROOF_FILE: &str = "../test_vectors/noir/poseidon/kat/pos_proof_with_pos";
    let circuit_file = "../test_vectors/noir/poseidon/kat/poseidon.json";
    let witness_file = "../test_vectors/noir/poseidon/kat/poseidon.gz";
    let prover_toml = "../test_vectors/noir/poseidon/Prover.toml";

    let program_artifact = co_noir::program_artifact_from_reader(File::open(circuit_file).unwrap())
        .expect("failed to parse program artifact");
    let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);

    let witness = co_noir::witness_from_reader(File::open(witness_file).unwrap()).unwrap();
    let mut patterns = HashSet::new();
    for (index, value) in witness.iter().enumerate() {
        if constraint_system.public_inputs.contains(&(index as u32)) {
            continue;
        }
        let canonical: [u8; 32] = value.into_bigint().to_bytes_le().try_into().unwrap();
        if canonical.iter().filter(|byte| **byte != 0).count() >= 16 {
            patterns.insert(canonical);
            patterns.insert(value.0.to_bytes_le().try_into().unwrap());
        }
    }
    assert!(
        patterns.len() >= 64,
        "too few private witness values to search for"
    );
    let planted = [&[0xab; 7][..], patterns.iter().next().unwrap(), &[0xcd; 5]].concat();
    assert_eq!(find_pattern(&[planted.into()], &patterns), Some((0, 7)));

    let log = Arc::new(Mutex::new(Vec::new()));
    let crs_size = co_noir::compute_circuit_size::<Bn254G1>(&constraint_system).unwrap();
    let prover_crs = Arc::new(
        CrsParser::<Bn254G1>::get_crs_g1(CRS_PATH_G1, crs_size, ZeroKnowledge::No).unwrap(),
    );
    let verifier_crs = CrsParser::<Bn254G1>::get_crs_g2::<Bn254>(CRS_PATH_G2).unwrap();
    let inputs = noir_types::partially_read_abi_bn254(
        File::open(prover_toml).unwrap(),
        &program_artifact.abi,
        &program_artifact.bytecode.functions[0]
            .public_inputs()
            .indices(),
    )
    .unwrap();
    let mut threads = Vec::with_capacity(3);
    for (inner, input) in izip!(
        LocalNetwork::new_3_parties(),
        co_noir::split_input_rep3(inputs)
    ) {
        let net = RecordingNetwork {
            inner,
            log: log.clone(),
        };
        let prover_crs = prover_crs.clone();
        let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
        let artifact = program_artifact.clone();
        threads.push(std::thread::spawn(move || {
            let witness = co_noir::generate_witness_rep3(input, artifact, &net).unwrap();
            let pk =
                co_noir::generate_proving_key_rep3(&constraint_system, witness, &net, &prover_crs)
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
    let proofs: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    // The recorded run is the real protocol: its proof is barretenberg's.
    assert_eq!(
        Poseidon2Sponge::to_buffer(proofs[0].inner_as_ref()),
        std::fs::read(PROOF_FILE).unwrap()
    );

    let frames = Arc::try_unwrap(log).unwrap().into_inner().unwrap();
    let total_bytes: usize = frames.iter().map(Bytes::len).sum();
    assert!(total_bytes >= 100_000, "recorded only {total_bytes} bytes");
    if let Some((frame, offset)) = find_pattern(&frames, &patterns) {
        panic!(
            "private witness value in plaintext in frame {frame} at offset {offset} ({} frames, {total_bytes} bytes)",
            frames.len()
        );
    }
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
fn random_access_witness_and_proof_test_poseidon2sponge() {
    witness_and_proof_test::<Poseidon2Sponge>("random_access", ZeroKnowledge::Yes, "");
}

#[test]
fn random_access_proof_test_poseidon2sponge() {
    proof_test::<Poseidon2Sponge>("random_access", ZeroKnowledge::Yes, "");
}

#[test]
fn embedded_curve_predicate_witness_and_proof_test_poseidon2sponge() {
    witness_and_proof_test::<Poseidon2Sponge>("embedded_curve_predicate", ZeroKnowledge::Yes, "");
}

#[test]
fn rom_shared_witness_and_proof_test_poseidon2sponge() {
    witness_and_proof_test::<Poseidon2Sponge>("rom_shared", ZeroKnowledge::Yes, "");
}

#[test]
fn rom_shared_proof_test_poseidon2sponge() {
    proof_test::<Poseidon2Sponge>("rom_shared", ZeroKnowledge::Yes, "");
}

// rom_shared reads a ROM at a secret index: the non-ZK proofs must match barretenberg byte for byte.
#[test]
fn rom_shared_witness_and_proof_kat_test_poseidon2sponge() {
    const PROOF_FILE: &str = "../test_vectors/noir/rom_shared/kat/rom_shared_proof_with_pos";
    witness_and_proof_test::<Poseidon2Sponge>("rom_shared", ZeroKnowledge::No, PROOF_FILE);
}

#[test]
fn rom_shared_proof_kat_test_poseidon2sponge() {
    const PROOF_FILE: &str = "../test_vectors/noir/rom_shared/kat/rom_shared_proof_with_pos";
    proof_test::<Poseidon2Sponge>("rom_shared", ZeroKnowledge::No, PROOF_FILE);
}

#[test]
fn rom_shared_witness_and_proof_test_keccak256() {
    const PROOF_FILE: &str = "../test_vectors/noir/rom_shared/kat/rom_shared_proof_with_kec";
    witness_and_proof_test::<Keccak256>("rom_shared", ZeroKnowledge::No, PROOF_FILE);
    witness_and_proof_test::<Keccak256>("rom_shared", ZeroKnowledge::Yes, PROOF_FILE);
}

#[test]
fn rom_shared_proof_test_keccak256() {
    const PROOF_FILE: &str = "../test_vectors/noir/rom_shared/kat/rom_shared_proof_with_kec";
    proof_test::<Keccak256>("rom_shared", ZeroKnowledge::No, PROOF_FILE);
    proof_test::<Keccak256>("rom_shared", ZeroKnowledge::Yes, PROOF_FILE);
}

#[test]
#[ignore = "REP3 methods on shared values are not yet implemented"]
fn recursion_witness_and_proof_test_poseidon2sponge() {
    witness_and_proof_test::<Poseidon2Sponge>("recursion", ZeroKnowledge::No, "");
    witness_and_proof_test::<Poseidon2Sponge>("recursion", ZeroKnowledge::Yes, "");
}

/// Proves `name` in ZK with the masking values derived from `seed`, with the plain driver and
/// with REP3 on a secret-shared witness, and returns both proofs.
fn seeded_zk_proofs(name: &str, seed: [u8; 32]) -> (HonkProof<Fr>, HonkProof<Fr>) {
    use co_builder::prelude::{HonkRecursion, UltraCircuitBuilder};
    use co_noir_common::mpc::plain::PlainUltraHonkDriver;
    use co_ultrahonk::prelude::CoUltraHonk;

    let program_artifact = co_noir::program_artifact_from_reader(
        File::open(format!("../test_vectors/noir/{name}/kat/{name}.json")).unwrap(),
    )
    .unwrap();
    let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
    let witness = co_noir::witness_from_reader(
        File::open(format!("../test_vectors/noir/{name}/kat/{name}.gz")).unwrap(),
    )
    .unwrap();
    let crs_size = co_noir::compute_circuit_size::<Bn254G1>(&constraint_system).unwrap();
    let (prover_crs, verifier_crs) = CrsParser::<Bn254G1>::get_crs::<Bn254>(
        CRS_PATH_G1,
        CRS_PATH_G2,
        crs_size,
        ZeroKnowledge::Yes,
    )
    .unwrap()
    .split();
    let prover_crs = Arc::new(prover_crs);
    let vk = co_noir::generate_vk::<Bn254>(&constraint_system, prover_crs.clone(), verifier_crs)
        .unwrap();

    let mut driver = co_acvm::PlainAcvmSolver::new();
    let builder = UltraCircuitBuilder::<Bn254G1>::create_circuit(
        &constraint_system,
        0,
        witness.clone(),
        HonkRecursion::UltraHonk,
        &Default::default(),
        &mut driver,
    )
    .unwrap();
    let proving_key = co_builder::keys::proving_key::create_prover_instance::<
        Bn254G1,
        PlainUltraHonkDriver,
        _,
    >(0, builder, &mut driver)
    .unwrap();
    let (plain_proof, public_inputs) =
        CoUltraHonk::<PlainUltraHonkDriver, _, Poseidon2Sponge>::prove_with_seeded_zk_masking(
            proving_key,
            &prover_crs,
            &vk.inner_vk,
            seed,
        )
        .unwrap();
    assert!(UltraHonk::<_, Poseidon2Sponge>::verify(
        plain_proof.clone(),
        &public_inputs,
        &vk,
        ZeroKnowledge::Yes
    )
    .unwrap());

    let mut witness_shares: [Vec<Rep3Type<Fr>>; 3] = Default::default();
    for (index, value) in witness.into_iter().enumerate() {
        let shares = if constraint_system.public_inputs.contains(&(index as u32)) {
            std::array::from_fn(|_| Rep3Type::from(value))
        } else {
            share_field_element(value, &mut rand::thread_rng()).map(Rep3Type::from)
        };
        for (party, share) in witness_shares.iter_mut().zip(shares) {
            party.push(share);
        }
    }
    let threads: Vec<_> = izip!(LocalNetwork::new_3_parties(), witness_shares)
        .map(|(net, witness)| {
            let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
            let prover_crs = prover_crs.clone();
            let vk = vk.inner_vk.clone();
            std::thread::spawn(move || {
                let proving_key = co_noir::generate_proving_key_rep3(
                    &constraint_system,
                    witness,
                    &net,
                    &prover_crs,
                )
                .unwrap();
                Rep3CoUltraHonk::<_, Poseidon2Sponge>::prove_with_seeded_zk_masking(
                    &net,
                    proving_key,
                    &prover_crs,
                    &vk,
                    seed,
                )
                .unwrap()
                .0
            })
        })
        .collect();
    let rep3_proofs: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert!(rep3_proofs.iter().all(|proof| *proof == rep3_proofs[0]));
    (plain_proof, rep3_proofs[0].clone())
}

/// With the same (seeded) masking values, the ZK proofs of the plain driver and of REP3 on a
/// secret-shared witness are identical, so the REP3 prover computes exactly the plain ZK proof.
#[test]
fn seeded_zk_proofs_of_plain_driver_and_rep3_are_identical() {
    for name in ["poseidon", "rom_shared"] {
        let (plain, rep3) = seeded_zk_proofs(name, [1; 32]);
        assert_eq!(
            Poseidon2Sponge::to_buffer(plain.inner_as_ref()),
            Poseidon2Sponge::to_buffer(rep3.inner_as_ref()),
            "{name}"
        );
        // Other masking values give another valid proof.
        let (other, _) = seeded_zk_proofs(name, [2; 32]);
        assert_ne!(plain, other, "{name}");
    }
}

// Circuits and witnesses of the recursion examples (the `kat` witnesses of `recursion` and
// `recursion_zk` in `test_vectors/noir` do not satisfy their circuits).
const RECURSION_EXAMPLES: &str = "../co-noir/co-noir/examples/test_vectors/recursion";
const RECURSION_ZK_EXAMPLES: &str = "../co-noir/co-noir/examples/test_vectors/recursion_zk";

/// The REP3 driver can evaluate the recursive verifier on secret-shared values. Without the
/// opt-in, a recursion circuit with secret-shared recursion inputs must still be rejected, before
/// the verifier runs.
#[test]
fn shared_recursion_inputs_are_rejected_by_default() {
    for (name, dir) in [
        ("recursion", RECURSION_EXAMPLES),
        ("recursion_zk", RECURSION_ZK_EXAMPLES),
    ] {
        let program_artifact = co_noir::program_artifact_from_reader(
            File::open(format!("{dir}/{name}.json")).unwrap(),
        )
        .unwrap();
        let constraint_system = co_noir::get_constraint_system_from_artifact(&program_artifact);
        let witness =
            co_noir::witness_from_reader(File::open(format!("{dir}/{name}.gz")).unwrap()).unwrap();
        let public_inputs = &constraint_system.public_inputs;
        let mut witness_shares: [Vec<Rep3Type<Fr>>; 3] = Default::default();
        for (index, value) in witness.into_iter().enumerate() {
            let shares = if public_inputs.contains(&(index as u32)) {
                std::array::from_fn(|_| Rep3Type::from(value))
            } else {
                share_field_element(value, &mut rand::thread_rng()).map(Rep3Type::from)
            };
            for (party, share) in witness_shares.iter_mut().zip(shares) {
                party.push(share);
            }
        }
        let threads: Vec<_> = izip!(LocalNetwork::new_3_parties(), witness_shares)
            .map(|(net, witness)| {
                let constraint_system =
                    co_noir::get_constraint_system_from_artifact(&program_artifact);
                std::thread::spawn(move || {
                    co_noir::generate_proving_key_rep3(
                        &constraint_system,
                        witness,
                        &net,
                        &Default::default(),
                    )
                    .map(|_| ())
                })
            })
            .collect();
        for thread in threads {
            let error = thread.join().unwrap().unwrap_err();
            assert!(
                error.to_string().contains("secret-shared inputs"),
                "{name}: {error}"
            );
        }
    }
}

#[test]
#[ignore = "Test is too slow for the pipeline"]
fn recursion_proof_test_poseidon2sponge() {
    // The inner proof is secret-shared, so all parties must agree to open it.
    let reveal = RecursionInputVisibility::RevealToParticipants;
    for has_zk in [ZeroKnowledge::No, ZeroKnowledge::Yes] {
        proof_test_with_visibility::<Poseidon2Sponge>(
            "recursion",
            RECURSION_EXAMPLES,
            has_zk,
            "",
            reveal,
        );
    }
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
    // The inner proof is secret-shared, so all parties must agree to open it.
    let reveal = RecursionInputVisibility::RevealToParticipants;
    for has_zk in [ZeroKnowledge::No, ZeroKnowledge::Yes] {
        proof_test_with_visibility::<Poseidon2Sponge>(
            "recursion_zk",
            RECURSION_ZK_EXAMPLES,
            has_zk,
            "",
            reveal,
        );
    }
}

/// A [`Network`] that counts the messages a party sends.
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

    fn get_connection_stats(&self) -> ConnectionStats {
        self.inner.get_connection_stats()
    }
}

/// Builds the REP3 proving key with the given lookup read-count batch size, proves, and returns
/// the proof together with the messages party 0 sent during key generation.
fn prove_rep3_with_lookup_batch_size(name: &str, batch_size: Option<usize>) -> (Vec<u8>, usize) {
    use co_acvm::{Rep3AcvmSolver, Rep3AcvmType};
    use co_builder::{
        keys::proving_key::create_prover_instance,
        prelude::{HonkRecursion, Rep3CoBuilder},
    };
    use co_noir_common::crs::ProverCrs;
    use mpc_core::protocols::rep3::{conversion::A2BType, id::PartyID};
    let artifact = co_noir::program_artifact_from_reader(
        File::open(format!("../test_vectors/noir/{name}/kat/{name}.json")).unwrap(),
    )
    .unwrap();
    let constraint_system = co_noir::get_constraint_system_from_artifact(&artifact);
    let witness = co_noir::witness_from_reader(
        File::open(format!("../test_vectors/noir/{name}/kat/{name}.gz")).unwrap(),
    )
    .unwrap();
    let mut shares: [Vec<Rep3AcvmType<Fr>>; 3] = Default::default();
    for (index, value) in witness.into_iter().enumerate() {
        let value: [Rep3AcvmType<Fr>; 3] =
            if constraint_system.public_inputs.contains(&(index as u32)) {
                std::array::from_fn(|_| Rep3AcvmType::from(value))
            } else {
                share_field_element(value, &mut rand::thread_rng()).map(Rep3AcvmType::from)
            };
        for (shares, value) in shares.iter_mut().zip(value) {
            shares.push(value);
        }
    }
    let crs_size = co_noir::compute_circuit_size::<Bn254G1>(&constraint_system).unwrap();
    let prover_crs = Arc::new(
        CrsParser::<Bn254G1>::get_crs_g1(CRS_PATH_G1, crs_size, ZeroKnowledge::No).unwrap(),
    );
    let verifier_crs = CrsParser::<Bn254G1>::get_crs_g2::<Bn254>(CRS_PATH_G2).unwrap();
    let threads: Vec<_> = izip!(LocalNetwork::new_3_parties(), shares)
        .map(|(inner, witness)| {
            let prover_crs = prover_crs.clone();
            let constraint_system = co_noir::get_constraint_system_from_artifact(&artifact);
            std::thread::spawn(move || {
                let net = CountingNetwork {
                    inner,
                    sent: AtomicUsize::new(0),
                };
                let mut driver = Rep3AcvmSolver::new(&net, A2BType::default()).unwrap();
                driver.set_lookup_read_count_batch_size(batch_size);
                let before = net.sent.load(Ordering::SeqCst);
                let builder = Rep3CoBuilder::create_circuit(
                    &constraint_system,
                    0,
                    witness,
                    HonkRecursion::UltraHonk,
                    &ProverCrs::default(),
                    &mut driver,
                )
                .unwrap();
                let id = PartyID::try_from(net.id()).unwrap();
                let pk = create_prover_instance(id, builder, &mut driver).unwrap();
                let sent = net.sent.load(Ordering::SeqCst) - before;
                let vk: VerifyingKey<Bn254> = pk.create_vk(&prover_crs, verifier_crs).unwrap();
                let (proof, _) = Rep3CoUltraHonk::<_, Poseidon2Sponge>::prove(
                    &net,
                    pk,
                    &prover_crs,
                    ZeroKnowledge::No,
                    &vk.inner_vk,
                )
                .unwrap();
                (Poseidon2Sponge::to_buffer(proof.inner_as_ref()), sent)
            })
        })
        .collect();
    let mut results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    let (proof, sent) = results.remove(0);
    for (other, _) in results {
        assert_eq!(other, proof);
    }
    (proof, sent)
}

/// The plain driver's non-ZK proof of a circuit for its known-answer witness.
fn plain_proof(name: &str) -> Vec<u8> {
    use co_acvm::PlainAcvmSolver;
    use co_builder::prelude::{HonkRecursion, UltraCircuitBuilder};
    use co_noir_common::crs::ProverCrs;

    let constraint_system = co_noir::constraint_system_from_reader(
        File::open(format!("../test_vectors/noir/{name}/kat/{name}.json")).unwrap(),
    )
    .unwrap();
    let witness = co_noir::witness_from_reader(
        File::open(format!("../test_vectors/noir/{name}/kat/{name}.gz")).unwrap(),
    )
    .unwrap();
    let mut driver = PlainAcvmSolver::new();
    let builder = UltraCircuitBuilder::<Bn254G1>::create_circuit(
        &constraint_system,
        0,
        witness,
        HonkRecursion::UltraHonk,
        &ProverCrs::default(),
        &mut driver,
    )
    .unwrap();
    let crs_size = builder.compute_dyadic_size();
    let (prover_crs, verifier_crs) = CrsParser::<Bn254G1>::get_crs::<Bn254>(
        CRS_PATH_G1,
        CRS_PATH_G2,
        crs_size,
        ZeroKnowledge::No,
    )
    .unwrap()
    .split();
    let (proving_key, verifying_key) = builder
        .create_keys::<Bn254>(prover_crs.into(), verifier_crs, &mut driver)
        .unwrap();
    let (proof, _) = UltraHonk::<_, Poseidon2Sponge>::prove(
        proving_key,
        ZeroKnowledge::No,
        &verifying_key.inner_vk,
    )
    .unwrap();
    Poseidon2Sponge::to_buffer(proof.inner_as_ref())
}

/// The non-ZK proof of a circuit with lookups at shared indices is the plain driver's proof for
/// every lookup read-count batch size, and batching saves messages in key generation.
#[test]
fn lookup_read_count_batches_preserve_shared_proof() {
    let name = "blackbox_and";
    let expected = plain_proof(name);

    let mut messages = Vec::new();
    for batch_size in [Some(1), Some(3), Some(7), None, Some(0)] {
        let (proof, sent) = prove_rep3_with_lookup_batch_size(name, batch_size);
        assert_eq!(proof, expected, "lookup batch size {batch_size:?}");
        messages.push(sent);
    }
    // One gate per batch takes the most messages; all gates in one batch the fewest.
    assert!(messages[3] < messages[0], "{messages:?}");
}

/// With shared inputs, REP3 key generation computes the lookup values of the SHA-256 compression
/// gadget with one garbled circuit per compression and still gives the plain driver's proof byte
/// for byte, i.e. every read the gadget makes gets exactly the value of the plain lookup.
#[test]
fn sha256_compression_shared_proof_matches_plain() {
    use co_acvm::mpc::DEFAULT_LOOKUP_READ_COUNT_BATCH;

    let name = "bb_sha256_compression";
    let (proof, _) = prove_rep3_with_lookup_batch_size(name, Some(DEFAULT_LOOKUP_READ_COUNT_BATCH));
    assert_eq!(proof, plain_proof(name));
}

/// The precomputed reads of a SHA-256 compression are returned in the compression gadget's order,
/// whatever key the read passes, and without communication; a read of another table than the next
/// precomputed one is an error. Precomputing all 369 reads sends at most as many messages as two
/// reads with their own garbled circuits.
#[test]
fn sha256_precomputed_reads_follow_the_gadget_order() {
    use ark_ff::Field;
    use co_acvm::{mpc::NoirWitnessExtensionProtocol, Rep3AcvmSolver, Rep3AcvmType};
    use mpc_core::protocols::rep3::{
        combine_field_elements, conversion::A2BType, share_field_elements,
        yao::circuits::SHA256Table, Rep3PrimeFieldShare,
    };
    use rand::Rng;

    let mut rng = rand::thread_rng();
    let inputs: [u32; 24] = rng.r#gen();
    let shares = share_field_elements(&inputs.map(Fr::from), &mut rng);
    let threads: Vec<_> = izip!(LocalNetwork::new_3_parties(), shares)
        .map(|(inner, shares)| {
            std::thread::spawn(move || {
                let net = CountingNetwork {
                    inner,
                    sent: AtomicUsize::new(0),
                };
                let sent = || net.sent.load(Ordering::SeqCst);
                let mut driver = Rep3AcvmSolver::<Fr, _>::new(&net, A2BType::default()).unwrap();
                let shares = shares
                    .into_iter()
                    .map(Rep3AcvmType::Shared)
                    .collect::<Vec<_>>();
                let majority_input_read = |driver: &mut Rep3AcvmSolver<Fr, _>| {
                    // The key is not used for a precomputed read.
                    let zero = Rep3PrimeFieldShare::zero_share();
                    let (sparse, _, key_slices, _) = driver
                        .slice_and_get_sparse_table_with_rotation_values(
                            zero,
                            zero,
                            &[1 << 11, 1 << 11, 1 << 10],
                            &[2, 2, 0],
                            64,
                            16,
                        )
                        .unwrap();
                    sparse
                        .into_iter()
                        .chain(key_slices)
                        .map(|x| match x {
                            Rep3AcvmType::Shared(x) => x,
                            Rep3AcvmType::Public(_) => panic!("expected shared values"),
                        })
                        .collect::<Vec<_>>()
                };

                let start = sent();
                driver
                    .precompute_sha256_compression(
                        &std::array::from_fn(|i| shares[i].clone()),
                        &std::array::from_fn(|i| shares[8 + i].clone()),
                    )
                    .unwrap();
                let precomputation = sent() - start;
                // The first read is the majority sparse form of state[1].
                let start = sent();
                let values = majority_input_read(&mut driver);
                assert_eq!(sent(), start);
                // The next one is the majority sparse form of state[2], not a normalization.
                let zero = Rep3PrimeFieldShare::zero_share();
                let result = driver.slice_and_get_sparse_normalization_values(
                    zero,
                    zero,
                    &[28 * 28; 16],
                    28,
                    160,
                    &SHA256Table::Choose,
                );
                assert!(result.is_err());
                // The remaining reads are dropped; a read runs its own garbled circuit again.
                let start = sent();
                majority_input_read(&mut driver);
                let one_read = sent() - start;
                assert!(
                    precomputation <= 2 * one_read,
                    "{precomputation} messages for all reads, {one_read} for one read"
                );
                values
            })
        })
        .collect();
    let outputs: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    let opened = combine_field_elements(&outputs[0], &outputs[1], &outputs[2]);

    let key = u64::from(inputs[1]);
    let slices = [key & 0x7ff, (key >> 11) & 0x7ff, key >> 22];
    let sparse = slices.map(|slice| {
        (0..11)
            .map(|t| Fr::from((slice >> t) & 1) * Fr::from(16u64).pow([t]))
            .sum::<Fr>()
    });
    assert_eq!(opened[..3], sparse);
    assert_eq!(opened[3..], slices.map(Fr::from));
}

/// Runs the REP3 witness extension of a test vector and returns the opened witness and the number
/// of messages party 0 sent.
fn rep3_witness_extension(name: &str, level_scheduling: bool) -> (Vec<Fr>, usize) {
    let artifact = co_noir::program_artifact_from_reader(
        File::open(format!("../test_vectors/noir/{name}/kat/{name}.json")).unwrap(),
    )
    .unwrap();
    let inputs = noir_types::partially_read_abi_bn254(
        File::open(format!("../test_vectors/noir/{name}/Prover.toml")).unwrap(),
        &artifact.abi,
        &artifact.bytecode.functions[0].public_inputs().indices(),
    )
    .unwrap();
    let shares = co_noir::split_input_rep3(inputs);
    let threads: Vec<_> = izip!(LocalNetwork::new_3_parties(), shares)
        .map(|(inner, share)| {
            let artifact = artifact.clone();
            std::thread::spawn(move || {
                let net = CountingNetwork {
                    inner,
                    sent: AtomicUsize::new(0),
                };
                let (witness, _) = co_noir::execute_circuit_rep3_with_level_scheduling(
                    share,
                    artifact,
                    &net,
                    level_scheduling,
                )
                .unwrap();
                (witness, net.sent.load(Ordering::SeqCst))
            })
        })
        .collect();
    let mut results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    let (c, _) = results.pop().unwrap();
    let (b, _) = results.pop().unwrap();
    let (a, sent) = results.pop().unwrap();
    let witness = izip!(a, b, c)
        .map(|shares| match shares {
            (Rep3Type::Public(a), Rep3Type::Public(_), Rep3Type::Public(_)) => a,
            (Rep3Type::Shared(a), Rep3Type::Shared(b), Rep3Type::Shared(c)) => {
                mpc_core::protocols::rep3::combine_field_element(a, b, c)
            }
            _ => panic!("parties disagree on which values are shared"),
        })
        .collect();
    (witness, sent)
}

/// Level scheduling gives the known-answer witness and computes the independent multiplications of
/// shared values together, so the witness extension sends fewer messages.
#[test]
fn level_scheduling_gives_the_same_witness_with_fewer_messages() {
    let name = "poseidon";
    let expected = co_noir::witness_from_reader(
        File::open(format!("../test_vectors/noir/{name}/kat/{name}.gz")).unwrap(),
    )
    .unwrap();
    let (sequential, sequential_messages) = rep3_witness_extension(name, false);
    let (scheduled, scheduled_messages) = rep3_witness_extension(name, true);
    assert_eq!(sequential, expected);
    assert_eq!(scheduled, expected);
    assert!(
        scheduled_messages < sequential_messages,
        "{scheduled_messages} vs {sequential_messages} messages"
    );
}

/// The REP3 driver computes independent products of shared values in one message per party, split
/// where a message would exceed the default network frame.
#[test]
fn rep3_solve_mul_terms_chunks_at_the_frame_length() {
    use co_acvm::{mpc::NoirWitnessExtensionProtocol, Rep3AcvmSolver, Rep3AcvmType};
    use co_noir_common::CoUtils;
    use mpc_core::protocols::rep3::{
        combine_field_elements, conversion::A2BType, share_field_elements,
    };

    let len = CoUtils::max_mul_many_len::<Fr>() + 2;
    let lhs: Vec<Fr> = (0..len as u64).map(Fr::from).collect();
    let rhs: Vec<Fr> = (0..len as u64).map(|i| Fr::from(i + 3)).collect();
    let c = Fr::from(5u64);
    let mut rng = rand::thread_rng();
    let lhs_shares = share_field_elements(&lhs, &mut rng);
    let rhs_shares = share_field_elements(&rhs, &mut rng);
    let threads: Vec<_> = izip!(LocalNetwork::new_3_parties(), lhs_shares, rhs_shares)
        .map(|(inner, lhs, rhs)| {
            std::thread::spawn(move || {
                let net = CountingNetwork {
                    inner,
                    sent: AtomicUsize::new(0),
                };
                let mut driver = Rep3AcvmSolver::<Fr, _>::new(&net, A2BType::default()).unwrap();
                let mut terms: Vec<_> = izip!(lhs, rhs)
                    .map(|(l, r)| (c, Rep3AcvmType::Shared(l), Rep3AcvmType::Shared(r)))
                    .collect();
                // A product with a public factor needs no communication.
                terms.push((c, Rep3AcvmType::Public(Fr::from(2u64)), terms[0].2.clone()));
                let start = net.sent.load(Ordering::SeqCst);
                let products = driver.solve_mul_terms(terms).unwrap();
                let sent = net.sent.load(Ordering::SeqCst) - start;
                let products: Vec<_> = products
                    .into_iter()
                    .map(|p| match p {
                        Rep3AcvmType::Shared(p) => p,
                        Rep3AcvmType::Public(_) => panic!("expected shared products"),
                    })
                    .collect();
                (products, sent)
            })
        })
        .collect();
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    for (_, sent) in &results {
        assert_eq!(*sent, 2);
    }
    let products = combine_field_elements(&results[0].0, &results[1].0, &results[2].0);
    for (i, product) in products[..len].iter().enumerate() {
        assert_eq!(*product, c * lhs[i] * rhs[i]);
    }
    assert_eq!(products[len], c * Fr::from(2u64) * rhs[0]);
}

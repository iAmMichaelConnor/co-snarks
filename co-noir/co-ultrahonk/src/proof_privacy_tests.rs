use super::*;
use ark_bn254::G1Projective;
use bytes::Bytes;
use co_noir_common::{keys::proof_privacy::ProofPrivacy, transcript::Poseidon2Sponge};

struct NoTraffic;
impl Network for NoTraffic {
    fn id(&self) -> usize {
        0
    }
    fn send(&self, _: usize, _: Bytes) -> eyre::Result<()> {
        panic!("policy guard sent network data")
    }
    fn recv(&self, _: usize) -> eyre::Result<Bytes> {
        panic!("policy guard received network data")
    }
    fn get_connection_stats(&self) -> mpc_net::ConnectionStats {
        ().get_connection_stats()
    }
}
fn key<T: NoirUltraHonkProver<G1Projective>>() -> ProvingKey<T, G1Projective> {
    // Deliberately invalid other fields ensure rejection precedes actual proving.
    ProvingKey {
        proof_privacy: ProofPrivacy::PrivateRecursion,
        ..Default::default()
    }
}
fn vk() -> VerifyingKeyBarretenberg<G1Projective> {
    VerifyingKeyBarretenberg {
        log_circuit_size: 0,
        num_public_inputs: 0,
        pub_inputs_offset: 0,
        commitments: Default::default(),
    }
}
fn privacy_error<T>(result: eyre::Result<T>) {
    let error = result.err().expect("private non-ZK mode was accepted");
    assert!(
        error
            .to_string()
            .contains("Private recursion requires a zero-knowledge outer proof"),
        "{error}"
    );
}

#[test]
fn all_co_prover_entries_reject_private_disclosure_before_traffic() {
    let crs = ProverCrs::default();
    let vk = vk();
    privacy_error(Rep3CoUltraHonk::<_, Poseidon2Sponge>::prove(
        &NoTraffic,
        key(),
        &crs,
        ZeroKnowledge::No,
        &vk,
    ));
    privacy_error(ShamirCoUltraHonk::<_, Poseidon2Sponge>::prove(
        &NoTraffic,
        3,
        1,
        key(),
        &crs,
        ZeroKnowledge::No,
        &vk,
    ));
    privacy_error(
        CoUltraHonk::<PlainUltraHonkDriver, _, Poseidon2Sponge>::prove(
            key(),
            &crs,
            ZeroKnowledge::No,
            &vk,
        ),
    );
    let seed = SeededZkBlinding::from_u64(42);
    privacy_error(
        Rep3CoUltraHonk::<_, Poseidon2Sponge>::prove_with_seeded_zk_blinding(
            &NoTraffic,
            key(),
            &crs,
            ZeroKnowledge::Yes,
            &vk,
            &seed,
        ),
    );
    privacy_error(
        CoUltraHonk::<PlainUltraHonkDriver, _, Poseidon2Sponge>::prove_with_seeded_zk_blinding(
            key(),
            &crs,
            ZeroKnowledge::Yes,
            &vk,
            &seed,
        ),
    );
    for (zk, seeded) in [(ZeroKnowledge::No, None), (ZeroKnowledge::Yes, Some(&seed))] {
        privacy_error(
            CoUltraHonk::<PlainUltraHonkDriver, _, Poseidon2Sponge>::prove_inner(
                &NoTraffic,
                &mut Default::default(),
                key(),
                &crs,
                zk,
                &vk,
                seeded,
            )
            .map_err(Into::into),
        );
    }
}

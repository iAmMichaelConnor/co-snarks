use super::*;
use ark_bn254::{Bn254, Fr, G1Projective};
use co_acvm::{Rep3AcvmSolver, Rep3AcvmType};
use co_noir_common::{
    crs::parse::CrsParser, mpc::rep3::Rep3UltraHonkDriver, transcript::Poseidon2Sponge,
    types::ZeroKnowledge,
};
use co_ultrahonk::prelude::{Rep3CoUltraHonk, UltraHonk};
use mpc_core::protocols::rep3::{conversion::A2BType, id::PartyID, share_field_elements};
use mpc_net::{Network, local::LocalNetwork};

pub(crate) fn prove_shared_builder<'a>(
    net: &LocalNetwork,
    mut builder: GenericUltraCircuitBuilder<G1Projective, Rep3AcvmSolver<'a, Fr, LocalNetwork>>,
    driver: &mut Rep3AcvmSolver<'a, Fr, LocalNetwork>,
) -> (bool, Vec<ark_bn254::G1Affine>) {
    builder.add_default_to_public_inputs();
    builder.finalize_circuit(driver).unwrap();
    let size = builder.compute_dyadic_size();
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../co-noir-common/src/crs");
    let (crs, g2) = CrsParser::<G1Projective>::get_crs::<Bn254>(
        dir.join("bn254_g1.dat"),
        dir.join("bn254_g2.dat"),
        size,
        ZeroKnowledge::No,
    )
    .unwrap()
    .split();
    let pk =
        crate::keys::proving_key::create_prover_instance::<G1Projective, Rep3UltraHonkDriver, _>(
            PartyID::try_from(net.id()).unwrap(),
            builder,
            driver,
        )
        .unwrap();
    let vk: co_noir_common::keys::verification_key::VerifyingKey<Bn254> =
        pk.create_vk(&crs, g2).unwrap();
    let commits = vk.inner_vk.commitments.iter().copied().collect();
    let (proof, inputs) = Rep3CoUltraHonk::<_, Poseidon2Sponge>::prove(
        net,
        pk,
        &crs,
        ZeroKnowledge::No,
        &vk.inner_vk,
    )
    .unwrap();
    (
        UltraHonk::<G1Projective, Poseidon2Sponge>::verify(proof, &inputs, &vk, ZeroKnowledge::No)
            .unwrap(),
        commits,
    )
}
#[test]
fn shared_carry_range_constraints_cover_all_five_chunks() {
    for (lo, hi, low_bits, high_bits, public_hi, expected) in [
        (
            (BigUint::one() << 68) - 1u32,
            (BigUint::one() << 67) + 1u32,
            68,
            68,
            false,
            true,
        ),
        (
            (BigUint::one() << 67) + 1u32,
            (BigUint::one() << 56) - 1u32,
            68,
            56,
            true,
            true,
        ),
        (
            BigUint::one() << 68,
            BigUint::from(1u32),
            68,
            68,
            false,
            false,
        ),
        (
            BigUint::from(1u32),
            BigUint::one() << 68,
            68,
            68,
            false,
            false,
        ),
        (
            BigUint::from(1u32),
            BigUint::one() << 56,
            68,
            56,
            false,
            false,
        ),
    ] {
        let values = [Fr::from(lo), Fr::from(hi)];
        let shares = share_field_elements(&values, &mut rand::thread_rng());
        let workers: Vec<_> = LocalNetwork::new_3_parties()
            .into_iter()
            .zip(shares)
            .map(|(net, shares)| {
                std::thread::spawn(move || {
                    let mut driver =
                        Rep3AcvmSolver::<Fr, _>::new(&net, A2BType::default()).unwrap();
                    let mut builder = GenericUltraCircuitBuilder::<G1Projective, _>::new_minimal(0);
                    let low = builder.add_variable(Rep3AcvmType::Shared(shares[0]));
                    let high = builder.add_variable(if public_hi {
                        Rep3AcvmType::Public(values[1])
                    } else {
                        Rep3AcvmType::Shared(shares[1])
                    });
                    builder
                        .range_constrain_two_limbs(low, high, low_bits, high_bits, &mut driver)
                        .unwrap();
                    assert_eq!(
                        prove_shared_builder(&net, builder, &mut driver).0,
                        expected,
                        "actual proof enforces both carry ranges"
                    );
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
    }
}

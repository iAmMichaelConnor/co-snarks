use super::{ByteArray, FieldCT};
use crate::{prelude::GenericUltraCircuitBuilder, transcript_ct::Bn254G1};
use ark_bn254::{Bn254, Fr};
use ark_ff::{One, PrimeField, Zero};
use co_acvm::{PlainAcvmSolver, Rep3AcvmSolver, Rep3AcvmType, mpc::NoirWitnessExtensionProtocol};
use co_noir_common::{crs::parse::CrsParser, transcript::Poseidon2Sponge, types::ZeroKnowledge};
use co_ultrahonk::prelude::UltraHonk;
use mpc_core::protocols::rep3::{conversion::A2BType, share_field_elements};
use mpc_net::local::LocalNetwork;
use num_bigint::BigUint;
use rand::{SeedableRng, rngs::StdRng};

type PlainBuilder = GenericUltraCircuitBuilder<Bn254G1, PlainAcvmSolver<Fr>>;

fn verify_builder(mut builder: PlainBuilder, driver: &mut PlainAcvmSolver<Fr>) -> bool {
    if !builder.circuit_finalized {
        builder.add_default_to_public_inputs();
        builder.finalize_circuit(driver).unwrap();
    }
    let crs_dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../co-noir-common/src/crs");
    let crs = CrsParser::<Bn254G1>::get_crs::<Bn254>(
        crs_dir.join("bn254_g1.dat"),
        crs_dir.join("bn254_g2.dat"),
        builder.compute_dyadic_size(),
        ZeroKnowledge::No,
    )
    .unwrap();
    let (prover, verifier) = crs.split();
    let (pk, vk) = builder
        .create_keys::<Bn254>(prover.into(), verifier, driver)
        .unwrap();
    let (proof, inputs) =
        UltraHonk::<_, Poseidon2Sponge>::prove(pk, ZeroKnowledge::No, &vk.inner_vk).unwrap();
    UltraHonk::<_, Poseidon2Sponge>::verify(proof, &inputs, &vk, ZeroKnowledge::No).unwrap()
}

fn construct<T: NoirWitnessExtensionProtocol<Fr>>(
    values: &[T::AcvmType],
    builder: &mut GenericUltraCircuitBuilder<Bn254G1, T>,
    driver: &mut T,
) {
    for value in values {
        let input = FieldCT::from_witness(value.clone(), builder);
        for width in [127, 128] {
            input.split_unique(width, builder, driver).unwrap();
        }
        ByteArray::from_field_ct(&input, 32, builder, driver).unwrap();
    }
}

#[test]
fn shared_recursive_slices_and_bytes_satisfy_full_constraints() {
    let values = vec![
        Fr::zero(),
        Fr::one(),
        -Fr::one(),
        Fr::from((BigUint::one() << 136usize) + 255u32),
    ];
    let shares = share_field_elements(&values, &mut StdRng::seed_from_u64(0x736c696365));
    let threads: Vec<_> = LocalNetwork::new_3_parties()
        .into_iter()
        .zip(shares)
        .map(|(net, shares)| {
            std::thread::spawn(move || {
                let mut driver = Rep3AcvmSolver::<Fr, _>::new(&net, A2BType::default()).unwrap();
                let mut builder = GenericUltraCircuitBuilder::<Bn254G1, _>::new_minimal(0);
                let values: Vec<_> = shares.into_iter().map(Rep3AcvmType::Shared).collect();
                construct(&values, &mut builder, &mut driver);
                builder.add_default_to_public_inputs();
                builder.finalize_circuit(&mut driver).unwrap();
                let witness: Vec<_> = builder
                    .variables
                    .iter()
                    .map(|v| driver.get_as_shared(v))
                    .collect();
                let blocks: Vec<_> = builder
                    .blocks
                    .get()
                    .into_iter()
                    .map(|b| (b.wires.clone(), b.selectors.clone()))
                    .collect();
                (
                    witness,
                    blocks,
                    builder.real_variable_index,
                    builder.real_variable_tags,
                )
            })
        })
        .collect();
    let outputs: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    let mut driver = PlainAcvmSolver::<Fr>::new();
    let mut builder = PlainBuilder::new_minimal(0);
    construct(&values, &mut builder, &mut driver);
    builder.add_default_to_public_inputs();
    builder.finalize_circuit(&mut driver).unwrap();
    let blocks: Vec<_> = builder
        .blocks
        .get()
        .into_iter()
        .map(|b| (b.wires.clone(), b.selectors.clone()))
        .collect();
    for output in &outputs {
        assert_eq!(output.1, blocks, "MPC constraint rows differ from Plain");
        assert_eq!(output.2, builder.real_variable_index);
        assert_eq!(output.3, builder.real_variable_tags);
        assert_eq!(output.0.len(), builder.variables.len());
    }
    // Reconstruct only inside the test referee, after all MPC execution. Prove
    // these actual MPC-generated witnesses against the identical full circuit.
    for i in 0..builder.variables.len() {
        for party in 0..3 {
            assert_eq!(outputs[party].0[i].b, outputs[(party + 2) % 3].0[i].a);
        }
        let value: Fr = outputs.iter().map(|o| o.0[i].a).sum();
        assert_eq!(value, builder.variables[i], "witness {i}");
        builder.variables[i] = value;
    }
    assert!(verify_builder(builder, &mut driver));
}

#[test]
fn full_width_bytes_reject_modular_aliases_with_coherent_witnesses() {
    let modulus: BigUint = Fr::MODULUS.into();
    for (integer, expected) in [
        (BigUint::zero(), true),
        (BigUint::one(), true),
        (&modulus - 1u32, true),
        (modulus.clone(), false),
        (&modulus + 1u32, false),
        ((BigUint::one() << 256usize) - 1u32, false),
    ] {
        let mut driver = PlainAcvmSolver::<Fr>::new();
        let mut builder = PlainBuilder::new_minimal(0);
        let input = FieldCT::from_witness(Fr::from(integer.clone()), &mut builder);
        let bytes: Vec<_> = (0..32)
            .map(|i| Fr::from((&integer >> ((31 - i) * 8)) & BigUint::from(255u32)))
            .collect();
        ByteArray::from_field_ct_with_bytes(&input, 32, bytes, &mut builder, &mut driver).unwrap();
        assert_eq!(
            verify_builder(builder, &mut driver),
            expected,
            "integer {integer}"
        );
    }
}

#[test]
fn plain_slice_order_and_byte_boundaries_match_integer_reference() {
    let mut driver = PlainAcvmSolver::<Fr>::new();
    let value = Fr::from((BigUint::one() << 128usize) + 255u32);
    assert_eq!(
        driver.slice(value, 128, 0, 254).unwrap(),
        [Fr::from(255u32), Fr::one()]
    );
    assert_eq!(
        driver.slice_many(&[value], 128, 0, 254).unwrap(),
        vec![[Fr::from(255u32), Fr::one()]]
    );
    for (value, bytes) in [
        (Fr::zero(), 0usize),
        (Fr::one(), 1),
        (Fr::from(255u32), 1),
        (Fr::one(), 32),
        (-Fr::one(), 32),
    ] {
        let mut builder = PlainBuilder::new_minimal(0);
        let array =
            ByteArray::from_field_ct(&FieldCT::from(value), bytes, &mut builder, &mut driver)
                .unwrap();
        let integer: BigUint = value.into();
        assert_eq!(array.values.len(), bytes);
        for (i, byte) in array.values.iter().enumerate() {
            let expected = Fr::from((&integer >> ((bytes - i - 1) * 8)) & BigUint::from(255u32));
            assert_eq!(byte.get_value(&builder, &mut driver), expected);
        }
    }
}

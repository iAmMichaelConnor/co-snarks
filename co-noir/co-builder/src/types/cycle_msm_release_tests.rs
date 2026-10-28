use super::*;
use ark_bn254::{Bn254, Fr};
use co_acvm::PlainAcvmSolver;
use co_noir_common::{crs::parse::CrsParser, transcript::Poseidon2Sponge, types::ZeroKnowledge};
use co_ultrahonk::prelude::UltraHonk;

type Curve = ark_bn254::G1Projective;
type Cycle = ark_grumpkin::Projective;
type Driver = PlainAcvmSolver<Fr>;
type Group = CycleGroupCT<Curve, Driver>;

fn verifies(mut builder: GenericUltraCircuitBuilder<Curve, Driver>, driver: &mut Driver) -> bool {
    for _ in 0..co_noir_common::constants::PAIRING_POINT_ACCUMULATOR_SIZE {
        builder.add_public_variable(Fr::zero());
    }
    builder.finalize_circuit(driver).unwrap();
    let size = builder.compute_dyadic_size();
    let crs = CrsParser::<Curve>::get_crs::<Bn254>(
        "../co-noir-common/src/crs/bn254_g1.dat",
        "../co-noir-common/src/crs/bn254_g2.dat",
        size,
        ZeroKnowledge::No,
    )
    .unwrap();
    let (prover_crs, verifier_crs) = crs.split();
    let (pk, vk) = builder
        .create_keys::<Bn254>(prover_crs.into(), verifier_crs, driver)
        .unwrap();
    let (proof, inputs) =
        UltraHonk::<_, Poseidon2Sponge>::prove(pk, ZeroKnowledge::No, &vk.inner_vk).unwrap();
    UltraHonk::<_, Poseidon2Sponge>::verify(proof, &inputs, &vk, ZeroKnowledge::No).unwrap()
}

// A circuit author can choose P = G0 - G1. With top scalar slice 1,
// the first Straus addition has equal operands and must be rejected.
#[test]
fn chosen_constant_point_cannot_use_a_degenerate_straus_addition() {
    let mut builder = GenericUltraCircuitBuilder::<Curve, Driver>::new_minimal(0);
    let mut driver = Driver::new();
    let offsets =
        generators::derive_generators::<Cycle>(Group::OFFSET_GENERATOR_DOMAIN_SEPARATOR, 2, 0);
    let point: Cycle = offsets[0].into_group() - offsets[1];
    let scalar = CycleScalarCT {
        lo: FieldCT::from_witness(Fr::zero(), &mut builder),
        hi: FieldCT::from_witness(Fr::from(BigUint::one() << 124usize), &mut builder),
    };
    let constant_scalar = CycleScalarCT {
        lo: FieldCT::from(Fr::from(7u64)),
        hi: FieldCT::default(),
    };
    let result = Group::batch_mul(
        vec![
            Group::from_group_element(point),
            Group::from_group_element(Cycle::generator()),
        ],
        vec![scalar, constant_scalar],
        &mut builder,
        &mut driver,
    )
    .unwrap();
    let expected = point * ark_grumpkin::Fr::from(BigUint::one() << 252usize)
        + Cycle::generator() * ark_grumpkin::Fr::from(7u64);
    assert_eq!(result.get_value(&builder, &mut driver).unwrap(), expected);
    assert!(
        !verifies(builder, &mut driver),
        "a chosen constant point must not bypass the x-coordinate collision check"
    );
}

// Arbitrary constants still work when the Straus additions are nondegenerate.
#[test]
fn arbitrary_constant_point_msm_matches_native_arithmetic() {
    let mut builder = GenericUltraCircuitBuilder::<Curve, Driver>::new_minimal(0);
    let mut driver = Driver::new();
    let point = Cycle::generator() * ark_grumpkin::Fr::from(17u64);
    let scalar = CycleScalarCT {
        lo: FieldCT::from_witness(Fr::from(42u64), &mut builder),
        hi: FieldCT::from_witness(Fr::zero(), &mut builder),
    };
    let result = Group::batch_mul(
        vec![Group::from_group_element(point)],
        vec![scalar],
        &mut builder,
        &mut driver,
    )
    .unwrap();
    assert_eq!(
        result.get_value(&builder, &mut driver).unwrap(),
        point * ark_grumpkin::Fr::from(42u64)
    );
    assert!(verifies(builder, &mut driver));
}

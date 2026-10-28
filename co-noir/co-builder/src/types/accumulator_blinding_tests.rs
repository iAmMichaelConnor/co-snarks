use super::*;
use ark_bn254::{Bn254, Fr, G1Projective};
use ark_ec::{AffineRepr, PrimeGroup};
use ark_ff::{Field, One, Zero};
use co_acvm::PlainAcvmSolver;
use co_noir_common::{crs::parse::CrsParser, transcript::Poseidon2Sponge, types::ZeroKnowledge};
use co_ultrahonk::prelude::UltraHonk;

#[test]
fn accumulator_blinding_preserves_pairing_with_zero_and_cancellation() {
    let crs_dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../co-noir-common/src/crs");
    let basis = CrsParser::<G1Projective>::get_crs::<Bn254>(
        crs_dir.join("bn254_g1.dat"),
        crs_dir.join("bn254_g2.dat"),
        2,
        ZeroKnowledge::No,
    )
    .unwrap()
    .split()
    .0;
    let mut reference_key = None;
    for (name, mask, scaling, invalid) in [
        ("zero additive mask", Fr::zero(), Fr::one(), false),
        ("infinity input", Fr::from(19u64), Fr::from(2u64), false),
        ("negative scaling", Fr::zero(), -Fr::one(), true),
        ("cancellation", -Fr::from(13u64), Fr::from(13u64), false),
        ("independent masks", Fr::from(17u64), Fr::from(31u64), false),
        ("invalid pairing", Fr::from(17u64), Fr::from(31u64), true),
        (
            "zero scaling cannot erase invalidity",
            Fr::from(17u64),
            Fr::zero(),
            true,
        ),
        (
            "zero scaling forbidden for valid pair",
            Fr::zero(),
            Fr::zero(),
            false,
        ),
    ] {
        let mut driver = PlainAcvmSolver::<Fr>::new();
        let mut builder = GenericUltraCircuitBuilder::<G1Projective, _>::new_minimal(0);
        let mut original0 = (basis.monomials[1].into_group()
            + if invalid {
                G1Projective::generator()
            } else {
                G1Projective::zero()
            })
        .into_affine();
        let mut original1 = (-basis.monomials[0].into_group()).into_affine();
        if name == "infinity input" {
            original0 = G1Projective::zero().into_affine();
            original1 = G1Projective::zero().into_affine();
        }
        let mut points = PairingPoints::new(
            BigGroup::from_witness::<G1Projective>(&original0, &mut driver, &mut builder).unwrap(),
            BigGroup::from_witness::<G1Projective>(&original1, &mut driver, &mut builder).unwrap(),
        );
        let scalar = FieldCT::from_witness(mask, &mut builder);
        let scaling_witness = FieldCT::from_witness(scaling, &mut builder);
        let inverse_witness =
            FieldCT::from_witness(scaling.inverse().unwrap_or_else(Fr::one), &mut builder);
        points
            .blind_with_scalars(
                &basis,
                &scalar,
                &scaling_witness,
                &inverse_witness,
                &mut builder,
                &mut driver,
            )
            .unwrap();
        let expected0 = (original0.mul_bigint(scaling.into_bigint())
            + basis.monomials[1].mul_bigint(mask.into_bigint()))
        .into_affine();
        let expected1 = (original1.mul_bigint(scaling.into_bigint())
            - basis.monomials[0].mul_bigint(mask.into_bigint()))
        .into_affine();
        points.set_public(&mut builder, &mut driver).unwrap();
        for (offset, expected) in [(0, expected0), (4, expected1)] {
            let outputs: Vec<_> = builder.public_inputs[offset..offset + 4]
                .iter()
                .map(|i| builder.get_variable(*i as usize))
                .collect();
            let x = BigUint::from(outputs[0].into_bigint())
                + (BigUint::from(outputs[1].into_bigint()) << 136);
            let y = BigUint::from(outputs[2].into_bigint())
                + (BigUint::from(outputs[3].into_bigint()) << 136);
            let (ex, ey) = expected
                .xy()
                .map(|(x, y)| {
                    (
                        BigUint::from(x.into_bigint()),
                        BigUint::from(y.into_bigint()),
                    )
                })
                .unwrap_or_default();
            assert_eq!((x, y), (ex, ey), "{name}: exact accumulator output");
        }
        builder.finalize_circuit(&mut driver).unwrap();
        let size = builder.compute_dyadic_size();
        let crs = CrsParser::<G1Projective>::get_crs::<Bn254>(
            crs_dir.join("bn254_g1.dat"),
            crs_dir.join("bn254_g2.dat"),
            size,
            ZeroKnowledge::No,
        )
        .unwrap();
        let (prover_crs, verifier_crs) = crs.split();
        let (pk, vk) = builder
            .create_keys::<Bn254>(prover_crs.into(), verifier_crs, &mut driver)
            .unwrap();
        let commitments = vk.inner_vk.commitments.iter().copied().collect::<Vec<_>>();
        if let Some(reference) = &reference_key {
            assert_eq!(
                &commitments, reference,
                "Blinding key must not depend on zero, cancellation or input values"
            );
        } else {
            reference_key = Some(commitments);
        }
        let (proof, public_inputs) =
            UltraHonk::<_, Poseidon2Sponge>::prove(pk, ZeroKnowledge::No, &vk.inner_vk).unwrap();
        let accepted =
            UltraHonk::<_, Poseidon2Sponge>::verify(proof, &public_inputs, &vk, ZeroKnowledge::No)
                .unwrap();
        assert_eq!(
            accepted,
            !invalid && !scaling.is_zero(),
            "{name}: constrained blinding preserves pairing validity"
        );
        eprintln!("accumulator blinding {name}: accepted={accepted}, circuit_size={size}");
    }
}

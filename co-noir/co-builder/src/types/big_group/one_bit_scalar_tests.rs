use super::*;
use ark_bn254::{Bn254, Fq, Fr, G1Projective};
use co_acvm::PlainAcvmSolver;
use co_noir_common::{crs::parse::CrsParser, transcript::Poseidon2Sponge, types::ZeroKnowledge};
use co_ultrahonk::prelude::UltraHonk;

/// Also run with --config profile.release.package.co-builder.overflow-checks=true:
/// this exercises the real scalar multiplication path with checked host arithmetic.
#[test]
fn one_bit_scalar_multiplication_satisfies_full_constraints() {
    let crs_dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../co-noir-common/src/crs");
    let mut reference_key = None;
    for scalar_value in [0u64, 1, 2] {
        let mut driver = PlainAcvmSolver::<Fr>::new();
        let mut builder = GenericUltraCircuitBuilder::<G1Projective, _>::new_minimal(0);
        // For the negative case skip only host witness assertions. There is no
        // ACIR/mock-proof construction here; all real witnesses and constraints
        // are retained, and the proof verifier must reject the out-of-range scalar.
        builder.is_write_vk_mode = scalar_value == 2;
        let scalar = FieldCT::from_witness(Fr::from(scalar_value), &mut builder);
        let mut point = BigGroup::from_witness::<G1Projective>(
            &ark_bn254::G1Affine::generator(),
            &mut driver,
            &mut builder,
        )
        .unwrap();
        let output = point
            .scalar_mul(&scalar, 1, &mut builder, &mut driver)
            .unwrap();
        assert_eq!(
            scalar.get_value(&builder, &mut driver),
            Fr::from(scalar_value)
        );
        if scalar_value < 2 {
            let expected = if scalar_value == 0 {
                (Fq::zero(), Fq::zero())
            } else {
                (Fq::one(), Fq::from(2u64))
            };
            assert_eq!(
                (
                    output.x.get_value_fq(&mut builder, &mut driver).unwrap(),
                    output.y.get_value_fq(&mut builder, &mut driver).unwrap(),
                ),
                expected,
                "one-bit multiplication returns infinity or the input generator"
            );
        }
        builder.add_default_to_public_inputs();
        builder.finalize_circuit(&mut driver).unwrap();
        let (crs, g2) = CrsParser::<G1Projective>::get_crs::<Bn254>(
            crs_dir.join("bn254_g1.dat"),
            crs_dir.join("bn254_g2.dat"),
            builder.compute_dyadic_size(),
            ZeroKnowledge::No,
        )
        .unwrap()
        .split();
        let (pk, vk) = builder
            .create_keys::<Bn254>(crs.into(), g2, &mut driver)
            .unwrap();
        let key_bytes = vk.inner_vk.to_buffer();
        if let Some(reference) = &reference_key {
            assert_eq!(&key_bytes, reference, "scalar values cannot change the key");
        } else {
            reference_key = Some(key_bytes);
        }
        let (proof, inputs) =
            UltraHonk::<_, Poseidon2Sponge>::prove(pk, ZeroKnowledge::No, &vk.inner_vk).unwrap();
        let accepted =
            UltraHonk::<_, Poseidon2Sponge>::verify(proof, &inputs, &vk, ZeroKnowledge::No)
                .unwrap();
        assert_eq!(accepted, scalar_value < 2, "one-bit scalar {scalar_value}");
    }
}

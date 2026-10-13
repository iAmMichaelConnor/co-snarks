use super::SharedPolynomial;
use crate::mpc::{NoirUltraHonkProver, plain::PlainUltraHonkDriver, rep3::Rep3UltraHonkDriver};
use ark_bn254::{Fr, G1Projective};
use ark_ff::UniformRand;
use rand::{SeedableRng, rngs::StdRng};

fn check<T: NoirUltraHonkProver<G1Projective>>(
    quotient: Vec<<T as NoirUltraHonkProver<G1Projective>>::ArithmeticShare>,
    root: Fr,
) {
    // Construct p=(X-root)*q, then recover q. This checks every coefficient,
    // including both sides of parallel chunk boundaries and partial blocks.
    let mut coefficients = vec![
        <T as NoirUltraHonkProver<G1Projective>>::ArithmeticShare::default();
        quotient.len() + 1
    ];
    for (i, value) in quotient.iter().enumerate() {
        coefficients[i] = T::sub(coefficients[i], T::mul_with_public(root, *value));
        coefficients[i + 1] = T::add(coefficients[i + 1], *value);
    }
    let mut p = SharedPolynomial::<T, G1Projective>::new(coefficients);
    p.factor_roots(&root);
    assert_eq!(p.coefficients, quotient);
}

#[test]
fn synthetic_division_preserves_polynomials_at_parallel_boundaries() {
    let mut rng = StdRng::seed_from_u64(0x51d1);
    for n in [1, 2, 31, 32767, 32768, 32769, 65537] {
        let values: Vec<Fr> = (0..n - 1).map(|_| Fr::rand(&mut rng)).collect();
        let shares = mpc_core::protocols::rep3::share_field_elements(&values, &mut rng);
        for root in [
            Fr::from(0u64),
            Fr::from(1u64),
            -Fr::from(1u64),
            Fr::rand(&mut rng),
        ] {
            check::<PlainUltraHonkDriver>(values.clone(), root);
            for party in &shares {
                check::<Rep3UltraHonkDriver>(party.clone(), root);
            }
        }
    }
}

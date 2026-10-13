use crate::co_decider::{co_decider_prover::CoDecider, types::ProverMemory};
use ark_bn254::{Fr, G1Projective};
use ark_ff::{Field, UniformRand};
use co_noir_common::{
    co_shplemini::{OpeningPair, ShpleminiOpeningClaim},
    mpc::plain::PlainUltraHonkDriver,
    polynomials::shared_polynomial::SharedPolynomial,
    transcript::Poseidon2Sponge,
    types::ZeroKnowledge,
};
use mpc_core::PlainState;
use mpc_net::local::LocalNetwork;
use rand::{SeedableRng, rngs::StdRng};
type Poly = SharedPolynomial<PlainUltraHonkDriver, G1Projective>;
fn eval(p: &[Fr], x: Fr) -> Fr {
    p.iter().rev().fold(Fr::from(0u64), |acc, c| acc * x + c)
}

#[test]
fn combined_quotient_matches_opening_equations_and_libra_weights() {
    let net = LocalNetwork::new(1).pop().unwrap();
    let mut state = PlainState { rng: None };
    let mut rng = StdRng::seed_from_u64(0x5a11);
    for has_zk in [false, true] {
        let memory = ProverMemory {
            polys: Default::default(),
            gemini_masking_poly: None,
            relation_parameters: Default::default(),
            alphas: Default::default(),
            gate_challenges: vec![],
        };
        let mut decider = CoDecider::<PlainUltraHonkDriver, G1Projective, Poseidon2Sponge, _>::new(
            &net,
            &mut state,
            memory,
            ZeroKnowledge::from(has_zk),
            None,
        );
        let nu = Fr::from(7u64);
        let z = Fr::from(31u64);
        let x = Fr::from(37u64);
        let q: Vec<Fr> = (0..32).map(|_| Fr::rand(&mut rng)).collect();
        let mut expected = eval(&q, x);
        let mut weight = Fr::from(1u64);
        let mut positives = vec![];
        let mut claims = vec![];
        for (i, len) in [32, 16, 8, 1].into_iter().enumerate() {
            let p: Vec<Fr> = (0..len).map(|_| Fr::rand(&mut rng)).collect();
            let r = -Fr::from(2 + i as u64);
            let neg = eval(&p, r);
            let fold = i != 0;
            if fold {
                let pos = eval(&p, -r);
                positives.push(pos);
                expected -= weight * (eval(&p, x) - pos) / (z + r);
                weight *= nu;
            }
            expected -= weight * (eval(&p, x) - neg) / (z - r);
            weight *= nu;
            claims.push(ShpleminiOpeningClaim {
                polynomial: Poly::new(p),
                opening_pair: OpeningPair {
                    challenge: r,
                    evaluation: neg,
                },
                gemini_fold: fold,
            });
        }
        let libra = if has_zk {
            weight = nu.pow([56]);
            Some(
                (0..4)
                    .map(|i| {
                        let p: Vec<Fr> = (0..8).map(|_| Fr::rand(&mut rng)).collect();
                        let r = Fr::from(11u64 + i);
                        let value = eval(&p, r);
                        expected -= weight * (eval(&p, x) - value) / (z - r);
                        weight *= nu;
                        ShpleminiOpeningClaim {
                            polynomial: Poly::new(p),
                            opening_pair: OpeningPair {
                                challenge: r,
                                evaluation: value,
                            },
                            gemini_fold: false,
                        }
                    })
                    .collect(),
            )
        } else {
            None
        };
        let got = decider.compute_partially_evaluated_batched_quotient(
            28,
            claims,
            Poly::new(q),
            nu,
            z,
            &positives,
            libra,
        );
        assert_eq!(eval(&got.polynomial.coefficients, x), expected);
    }
}

#[test]
fn retained_folds_match_multilinear_evaluation_and_virtual_rounds() {
    let net = LocalNetwork::new(1).pop().unwrap();
    let mut state = PlainState { rng: None };
    let mut rng = StdRng::seed_from_u64(0xf01d);
    for log_n in [2usize, 3, 13, 14] {
        let memory = ProverMemory {
            polys: Default::default(),
            gemini_masking_poly: None,
            relation_parameters: Default::default(),
            alphas: Default::default(),
            gate_challenges: vec![],
        };
        let mut decider = CoDecider::<PlainUltraHonkDriver, G1Projective, Poseidon2Sponge, _>::new(
            &net,
            &mut state,
            memory,
            ZeroKnowledge::No,
            None,
        );
        let values: Vec<Fr> = (0..1 << log_n).map(|_| Fr::rand(&mut rng)).collect();
        let challenges: Vec<Fr> = (0..28).map(|_| Fr::rand(&mut rng)).collect();
        let expected = Poly::new(values.clone()).evaluate_mle(&challenges[..log_n]);
        let folds = decider.compute_fold_polynomials(log_n, &challenges, Poly::new(values.clone()));
        assert_eq!(folds.len(), 27);
        assert_eq!(folds[log_n - 1].coefficients, vec![expected]);
        let mut tail = expected;
        for i in log_n..27 {
            tail *= Fr::from(1u64) - challenges[i];
            assert_eq!(folds[i].coefficients, vec![tail]);
        }
        for l in 0..log_n - 1 {
            let source = if l == 0 {
                values.as_slice()
            } else {
                folds[l - 1].coefficients.as_slice()
            };
            let even: Vec<_> = source.iter().step_by(2).copied().collect();
            let odd: Vec<_> = source.iter().skip(1).step_by(2).copied().collect();
            for x in [Fr::from(0u64), Fr::from(3u64), Fr::rand(&mut rng)] {
                assert_eq!(
                    eval(&folds[l].coefficients, x),
                    (Fr::from(1u64) - challenges[l]) * eval(&even, x)
                        + challenges[l] * eval(&odd, x)
                );
            }
        }
    }
}

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

fn empty_memory() -> ProverMemory<PlainUltraHonkDriver, G1Projective> {
    ProverMemory {
        polys: Default::default(),
        gemini_masking_poly: None,
        relation_parameters: Default::default(),
        alphas: Default::default(),
        gate_challenges: vec![],
    }
}

/// G(X) = Q(X) − ∑ⱼ νʲ⋅(fⱼ(X) − vⱼ)/(z − xⱼ), with Gemini folds opened at both ±xⱼ and the Libra claims
/// weighted from ν^(2⋅virtual_log_n) on, checked against an evaluation at a random point.
#[test]
fn partially_evaluated_batched_quotient_matches_opening_equations() {
    let net = LocalNetwork::new(1).pop().unwrap();
    let mut state = PlainState { rng: None };
    let mut rng = StdRng::seed_from_u64(0x5a11);
    let virtual_log_n = 28;
    for has_zk in [ZeroKnowledge::No, ZeroKnowledge::Yes] {
        let mut decider = CoDecider::<PlainUltraHonkDriver, G1Projective, Poseidon2Sponge, _>::new(
            &net,
            &mut state,
            empty_memory(),
            has_zk,
            Default::default(),
        );
        let nu = Fr::rand(&mut rng);
        let z = Fr::rand(&mut rng);
        let x = Fr::rand(&mut rng);
        let q: Vec<Fr> = (0..32).map(|_| Fr::rand(&mut rng)).collect();
        let mut expected = eval(&q, x);
        let mut weight = Fr::from(1u64);
        let mut positive_evaluations = vec![];
        let mut claims = vec![];
        for (i, len) in [32, 16, 8, 1].into_iter().enumerate() {
            let p: Vec<Fr> = (0..len).map(|_| Fr::rand(&mut rng)).collect();
            let r = Fr::rand(&mut rng);
            let negative_evaluation = eval(&p, r);
            let gemini_fold = i != 0;
            if gemini_fold {
                let positive_evaluation = eval(&p, -r);
                positive_evaluations.push(positive_evaluation);
                expected -= weight * (eval(&p, x) - positive_evaluation) / (z + r);
                weight *= nu;
            }
            expected -= weight * (eval(&p, x) - negative_evaluation) / (z - r);
            weight *= nu;
            claims.push(ShpleminiOpeningClaim {
                polynomial: Poly::new(p),
                opening_pair: OpeningPair {
                    challenge: r,
                    evaluation: negative_evaluation,
                },
                gemini_fold,
            });
        }
        let libra_claims = (has_zk == ZeroKnowledge::Yes).then(|| {
            weight = nu.pow([2 * virtual_log_n as u64]);
            (0..4)
                .map(|_| {
                    let p: Vec<Fr> = (0..8).map(|_| Fr::rand(&mut rng)).collect();
                    let r = Fr::rand(&mut rng);
                    let evaluation = eval(&p, r);
                    expected -= weight * (eval(&p, x) - evaluation) / (z - r);
                    weight *= nu;
                    ShpleminiOpeningClaim {
                        polynomial: Poly::new(p),
                        opening_pair: OpeningPair {
                            challenge: r,
                            evaluation,
                        },
                        gemini_fold: false,
                    }
                })
                .collect()
        });
        let claim = decider.compute_partially_evaluated_batched_quotient(
            virtual_log_n,
            claims,
            Poly::new(q),
            nu,
            z,
            &positive_evaluations,
            libra_claims,
        );
        assert_eq!(eval(&claim.polynomial.coefficients, x), expected);
        assert_eq!(claim.opening_pair.challenge, z);
    }
}

/// Each fold Aₗ₊₁ = (1 − uₗ)⋅even(Aₗ) + uₗ⋅odd(Aₗ); the last real fold is the multilinear evaluation and the
/// virtual folds scale it by ∏(1 − uₖ).
#[test]
fn fold_polynomials_match_multilinear_folding() {
    let net = LocalNetwork::new(1).pop().unwrap();
    let mut state = PlainState { rng: None };
    let mut rng = StdRng::seed_from_u64(0xf01d);
    let virtual_log_n = 28;
    // 13 and 14 put the first folds above the parallel threshold.
    for log_n in [2usize, 3, 13, 14] {
        let mut decider = CoDecider::<PlainUltraHonkDriver, G1Projective, Poseidon2Sponge, _>::new(
            &net,
            &mut state,
            empty_memory(),
            ZeroKnowledge::No,
            Default::default(),
        );
        let values: Vec<Fr> = (0..1 << log_n).map(|_| Fr::rand(&mut rng)).collect();
        let challenges: Vec<Fr> = (0..virtual_log_n).map(|_| Fr::rand(&mut rng)).collect();
        let expected = Poly::new(values.clone()).evaluate_mle(&challenges[..log_n]);
        let folds = decider.compute_fold_polynomials(log_n, &challenges, Poly::new(values.clone()));
        assert_eq!(folds.len(), virtual_log_n - 1);
        assert_eq!(folds[log_n - 1].coefficients, vec![expected]);
        let mut tail = expected;
        for (fold, challenge) in folds.iter().zip(&challenges).skip(log_n) {
            tail *= Fr::from(1u64) - challenge;
            assert_eq!(fold.coefficients, vec![tail]);
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

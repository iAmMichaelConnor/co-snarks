use super::{ProverUnivariatesBatch, Relation, logderiv_lookup_relation::*};
use ark_bn254::{Fr, G1Projective};
use ark_ff::{Field, UniformRand};
use co_noir_common::{
    constants::MAX_PARTIAL_RELATION_LENGTH,
    mpc::{NoirUltraHonkProver, rep3::Rep3UltraHonkDriver, shamir::ShamirUltraHonkDriver},
    types::RelationParameters,
};
use mpc_core::{
    MpcState,
    protocols::{
        rep3::{self, Rep3State, conversion::A2BType},
        shamir::{self, ShamirPreprocessing},
    },
};
use mpc_net::{Network, local::LocalNetwork};
use rand::{SeedableRng, rngs::StdRng};

// Evaluate the three published relation equations directly, independently of
// the production intermediate vectors and of either sharing protocol.
fn oracle(
    input: &ProverUnivariatesBatch<co_noir_common::mpc::plain::PlainUltraHonkDriver, G1Projective>,
    scale: &[Fr],
    beta: Fr,
    gamma: Fr,
) -> Vec<Fr> {
    let mut result = vec![Fr::from(9u64); 13];
    for (i, scaling_factor) in scale.iter().enumerate() {
        let w = &input.witness;
        let p = &input.precomputed;
        let s = &input.shifted_witness;
        let read = w.w_l()[i]
            + p.q_r()[i] * s.w_l()[i]
            + gamma
            + beta * (w.w_r()[i] + p.q_m()[i] * s.w_r()[i])
            + beta.square() * (w.w_o()[i] + p.q_c()[i] * s.w_o()[i])
            + beta.pow([3]) * p.q_o()[i];
        let write = p.table_1()[i]
            + gamma
            + beta * p.table_2()[i]
            + beta.square() * p.table_3()[i]
            + beta.pow([3]) * p.table_4()[i];
        let tag = w.lookup_read_tags()[i];
        let inv = w.lookup_inverses()[i];
        let q = p.q_lookup()[i];
        let col = i % MAX_PARTIAL_RELATION_LENGTH;
        if col < 5 {
            result[col] += (write * read * inv - (q + tag - q * tag)) * scaling_factor;
            result[5 + col] += q * write * inv - w.lookup_read_counts()[i] * read * inv;
        }
        if col < 3 {
            result[10 + col] += (tag.square() - tag) * scaling_factor;
        }
    }
    result
}

fn run<T: NoirUltraHonkProver<G1Projective>, N: Network>(
    net: N,
    mut state: T::State,
    input: ProverUnivariatesBatch<T, G1Projective>,
    scales: Vec<Fr>,
    expected: Vec<Fr>,
) {
    let mut acc = LogDerivLookupRelationAcc::<T, G1Projective>::default();
    let nine = T::promote_to_trivial_share(state.id(), Fr::from(9u64));
    acc.r0.evaluations.fill(nine);
    acc.r1.evaluations.fill(nine);
    acc.r2.evaluations.fill(nine);
    let params = RelationParameters {
        beta: Fr::from(7u64),
        gamma: Fr::from(11u64),
        ..Default::default()
    };
    <LogDerivLookupRelation as Relation<T, G1Projective>>::accumulate(
        &net, &mut state, &mut acc, &input, &params, &scales,
    )
    .unwrap();
    let output: Vec<_> = acc
        .r0
        .evaluations
        .into_iter()
        .chain(acc.r1.evaluations)
        .chain(acc.r2.evaluations)
        .collect();
    assert_eq!(T::open_many(&output, &net, &mut state).unwrap(), expected);
    // A subsequent multiplication detects inconsistent mask/preprocessing cursors.
    let x = input.witness.w_l();
    let squared = T::mul_many(x, x, &net, &mut state).unwrap();
    let clear = T::open_many(x, &net, &mut state).unwrap();
    assert_eq!(
        T::open_many(&squared, &net, &mut state).unwrap(),
        clear.iter().map(|x| x.square()).collect::<Vec<_>>()
    );
}

#[test]
fn lookup_folding_matches_equations_for_rep3_and_shamir() {
    for edges in [1, 3, 130, 9362, 9363] {
        for zero_scale in [false, true] {
            let n = edges * MAX_PARTIAL_RELATION_LENGTH;
            let mut rng = StdRng::seed_from_u64(0x100c + edges as u64);
            let mut clear = ProverUnivariatesBatch::<
                co_noir_common::mpc::plain::PlainUltraHonkDriver,
                G1Projective,
            >::new();
            for v in clear
                .witness
                .iter_mut()
                .chain(clear.shifted_witness.iter_mut())
            {
                *v = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            }
            for v in clear.precomputed.iter_mut() {
                *v = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            }
            // Includes non-Boolean tags, as occur at univariate evaluation points.
            for (i, v) in clear.witness.lookup_read_tags_mut().iter_mut().enumerate() {
                *v = Fr::from((i % 3) as u64);
            }
            let scales: Vec<_> = (0..n)
                .map(|i| {
                    if zero_scale || i % 3 == 0 {
                        Fr::from(0u64)
                    } else {
                        Fr::rand(&mut rng)
                    }
                })
                .collect();
            let expected = oracle(&clear, &scales, Fr::from(7u64), Fr::from(11u64));
            let mut rep: Vec<_> = (0..3)
                .map(|_| ProverUnivariatesBatch::<Rep3UltraHonkDriver, G1Projective>::new())
                .collect();
            for (column, values) in clear
                .witness
                .iter()
                .chain(clear.shifted_witness.iter())
                .enumerate()
            {
                let a = rep3::share_field_elements(values, &mut rng);
                for (i, av) in a.into_iter().enumerate() {
                    let target = &mut rep[i];
                    *target
                        .witness
                        .iter_mut()
                        .chain(target.shifted_witness.iter_mut())
                        .nth(column)
                        .unwrap() = av;
                }
            }
            for x in &mut rep {
                x.precomputed = clear.precomputed.clone();
            }

            let handles: Vec<_> = LocalNetwork::new_3_parties()
                .into_iter()
                .zip(rep)
                .map(|(net, input)| {
                    let scales = scales.clone();
                    let expected = expected.clone();
                    std::thread::spawn(move || {
                        let state = Rep3State::new(&net, A2BType::default()).unwrap();
                        run::<Rep3UltraHonkDriver, _>(net, state, input, scales, expected);
                    })
                })
                .collect();
            for h in handles {
                h.join().unwrap();
            }
            // Exercise degree reduction at t=1 and t=2 on both sides of
            // the public-size threshold; the inputs are actually secret shared.
            for threshold in [1, 2] {
                let parties = 2 * threshold + 1;
                let mut sham: Vec<_> = (0..parties)
                    .map(|_| ProverUnivariatesBatch::<ShamirUltraHonkDriver, G1Projective>::new())
                    .collect();
                for (column, values) in clear
                    .witness
                    .iter()
                    .chain(clear.shifted_witness.iter())
                    .enumerate()
                {
                    for (target, values) in sham.iter_mut().zip(shamir::share_field_elements(
                        values, threshold, parties, &mut rng,
                    )) {
                        *target
                            .witness
                            .iter_mut()
                            .chain(target.shifted_witness.iter_mut())
                            .nth(column)
                            .unwrap() = values;
                    }
                }
                for target in &mut sham {
                    target.precomputed = clear.precomputed.clone();
                }
                let handles: Vec<_> = LocalNetwork::new(parties)
                    .into_iter()
                    .zip(sham)
                    .map(|(net, input)| {
                        let scales = scales.clone();
                        let expected = expected.clone();
                        std::thread::spawn(move || {
                            let state =
                                ShamirPreprocessing::new(parties, threshold, n * 4 + 32, &net)
                                    .unwrap()
                                    .into();
                            run::<ShamirUltraHonkDriver, _>(net, state, input, scales, expected);
                        })
                    })
                    .collect();
                for h in handles {
                    h.join().unwrap();
                }
            }
        }
    }
}

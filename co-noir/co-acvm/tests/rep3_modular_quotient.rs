//! Check production private quotient adapters against an unbounded integer oracle.
use ark_bn254::{Fq, Fr, G1Projective};
use ark_ff::{One, PrimeField, Zero};
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_acvm::{Rep3AcvmSolver, Rep3AcvmType};
use mpc_core::protocols::rep3::{self, conversion::A2BType};
use mpc_net::local::LocalNetwork;
use num_bigint::BigUint;
use rand::{SeedableRng, rngs::StdRng};

fn raw(values: &[Fr; 4]) -> BigUint {
    values
        .iter()
        .enumerate()
        .fold(BigUint::zero(), |s, (i, x)| {
            s + (BigUint::from(x.into_bigint()) << (68 * i))
        })
}
fn raw_limbs(x: &BigUint) -> [Fr; 4] {
    let mask = (BigUint::one() << 68usize) - BigUint::one();
    std::array::from_fn(|i| Fr::from((x >> (68 * i)) & &mask))
}
fn power(bit: usize) -> [Fr; 4] {
    let mut result = [Fr::zero(); 4];
    let i = (bit / 68).min(3);
    result[i] = Fr::from(BigUint::one() << (bit - i * 68));
    assert_eq!(raw(&result), BigUint::one() << bit);
    result
}
fn lazy_limbs(x: &BigUint) -> [Fr; 4] {
    let mut result = raw_limbs(x);
    result[3] = Fr::from(x >> 204usize);
    assert_eq!(raw(&result), *x);
    result
}
#[test]
fn modular_quotient_matches_unbounded_integer_oracle_with_real_parties() {
    let p = BigUint::from(Fq::MODULUS);
    let max = [Fr::from(-1i64); 4];
    // Each case is an arbitrary product sum plus arbitrary raw additions.
    type ProductSum = (Vec<[Fr; 4]>, Vec<[Fr; 4]>, Vec<[Fr; 4]>);
    let mut cases: Vec<ProductSum> = vec![
        (vec![], vec![], vec![]),
        (vec![], vec![], vec![raw_limbs(&(&p - 1u32))]),
        (vec![], vec![], vec![raw_limbs(&p)]),
        (vec![], vec![], vec![max]),
        (vec![raw_limbs(&p)], vec![power(272)], vec![]),
        (
            vec![raw_limbs(&p)],
            vec![raw_limbs(&((BigUint::one() << 272usize) - 1u32))],
            vec![raw_limbs(&(&p - 1u32))],
        ),
        (vec![power(300)], vec![power(300)], vec![]),
        (vec![power(400)], vec![power(400)], vec![]),
        (vec![max, max], vec![max, max], vec![max, max]),
    ];
    for b in [
        (BigUint::one() << 412usize) - 1u32,
        BigUint::one() << 412usize,
        (BigUint::one() << 412usize) + 1u32,
    ] {
        cases.push((
            vec![lazy_limbs(&(&p << 100usize))],
            vec![lazy_limbs(&b)],
            vec![],
        ));
    }
    let mut rng = StdRng::seed_from_u64(0x512F0);
    for (a, b, c) in cases {
        let expected = a
            .iter()
            .zip(&b)
            .fold(BigUint::zero(), |s, (a, b)| s + raw(a) * raw(b))
            + c.iter().fold(BigUint::zero(), |s, c| s + raw(c));
        let input: Vec<_> = a.iter().chain(&b).chain(&c).flatten().copied().collect();
        for mixed in [false, true] {
            let shares = rep3::share_field_elements(&input, &mut rng);
            let workers: Vec<_> = LocalNetwork::new_3_parties()
                .into_iter()
                .zip(shares)
                .enumerate()
                .map(|(party, (net, shares))| {
                    let expected = expected.clone();
                    let p = p.clone();
                    let a_len = a.len();
                    let input = input.clone();
                    std::thread::spawn(move || {
                        let mut driver =
                            Rep3AcvmSolver::<Fr, _>::new(&net, A2BType::default()).unwrap();
                        let values: Vec<_> = shares
                            .iter()
                            .enumerate()
                            .map(|(i, v)| {
                                if mixed && i % 3 == 1 {
                                    Rep3AcvmType::Public(input[i])
                                } else {
                                    Rep3AcvmType::Shared(*v)
                                }
                            })
                            .collect();
                        let rows: Vec<[Rep3AcvmType<Fr>; 4]> = values
                            .chunks_exact(4)
                            .map(|c| c.to_vec().try_into().unwrap())
                            .collect();
                        let begin = std::time::Instant::now();
                        let (q, r) = driver
                            .madd_div_mod_many_acvm_limbs::<G1Projective>(
                                &rows[..a_len],
                                &rows[a_len..2 * a_len],
                                &rows[2 * a_len..],
                            )
                            .unwrap();
                        if party == 0 {
                            eprintln!(
                                "whole adapter bits={} mixed={} elapsed={:?}",
                                expected.bits(),
                                mixed,
                                begin.elapsed()
                            );
                        }
                        let q: Vec<_> = q.iter().map(|v| driver.get_as_shared(v)).collect();
                        assert_eq!(driver.open_many(&q).unwrap(), raw_limbs(&(&expected / &p)));
                        assert_eq!(
                            driver.open_many_other::<G1Projective>(&[r]).unwrap(),
                            vec![Fq::from(&expected % &p)]
                        );
                    })
                })
                .collect();
            for worker in workers {
                worker.join().unwrap();
            }
        }
    }
}

//! Exercise the actual private quotient/remainder protocol with every input bit
//! available; raw non-native adapter limbs alone cannot fill a 1024-bit ring.
use ark_bn254::{Fq, Fr};
use ark_ff::{One, PrimeField, Zero};
use mpc_core::protocols::rep3::{Rep3State, arithmetic, conversion::A2BType};
use mpc_core::protocols::rep3_ring::{
    ring::{int_ring::IntRing2k, ring_impl::RingElement},
    share_ring_element, yao,
};
use mpc_core::uint::{U512, U1024, UintBackend};
use mpc_net::{ConnectionStats, Network, bytes::Bytes, local::LocalNetwork};

struct PanicNetwork;
impl Network for PanicNetwork {
    fn id(&self) -> usize {
        panic!("Invalid public configuration must not access the network")
    }
    fn send(&self, _: usize, _: Bytes) -> eyre::Result<()> {
        panic!("Unexpected send")
    }
    fn recv(&self, _: usize) -> eyre::Result<Bytes> {
        panic!("Unexpected receive")
    }
    fn get_connection_stats(&self) -> ConnectionStats {
        panic!("Unexpected network access")
    }
}
use num_bigint::BigUint;
use rand::{SeedableRng, distributions::Standard, prelude::Distribution, rngs::StdRng};

fn check<T: IntRing2k + UintBackend>()
where
    Standard: Distribution<T>,
{
    let q = BigUint::from(Fq::MODULUS);
    let max = (BigUint::one() << T::K) - BigUint::one();
    let mut cases: Vec<(BigUint, BigUint)> = vec![
        BigUint::zero(),
        BigUint::one(),
        &q - BigUint::one(),
        q.clone(),
        &q + BigUint::one(),
        BigUint::one() << (T::K - 1),
        (&max / &q) * &q,
        max.clone(),
    ]
    .into_iter()
    .map(|value| (q.clone(), value))
    .collect();
    for divisor in [BigUint::one(), BigUint::one() << 253] {
        cases.push((divisor.clone(), max.clone()));
        cases.push((divisor, BigUint::one() << (T::K - 1)));
    }
    let large_divisor: BigUint = (BigUint::one() << 512usize) - BigUint::one();
    cases.push((large_divisor.clone(), large_divisor.clone()));
    for _ in 0..3 {
        // Repeat with fresh sharing/garbling masks to exercise the old
        // mask-dependent noncanonical decode failure.
        cases.push((large_divisor.clone(), &large_divisor - BigUint::one()));
    }
    cases.push((large_divisor.clone(), q.clone()));
    cases.push((large_divisor.clone(), &q + BigUint::one()));
    // Also exercise high quotient bits with a small remainder. The generic
    // wrapper returns only the low254 remainder bits, reduced into Fq; this
    // differs from full integer remainder semantics for these large divisors.
    cases.push((
        large_divisor.clone(),
        ((&max / &large_divisor) - BigUint::one()) * &large_divisor + 7u32,
    ));
    let mut rng = StdRng::seed_from_u64(0x000D_1512_1024);
    let shares: Vec<_> = cases
        .iter()
        .map(|(_, x)| {
            share_ring_element(
                RingElement(T::from_limbs_truncating(&x.to_u64_digits())),
                &mut rng,
            )
        })
        .collect();
    let workers: Vec<_> = LocalNetwork::new_3_parties()
        .into_iter()
        .enumerate()
        .map(|(party, net)| {
            let shares: Vec<_> = shares.iter().map(|s| s[party]).collect();
            let cases = cases.clone();
            std::thread::spawn(move || {
                let mut state = Rep3State::new(&net, A2BType::default()).unwrap();
                let mask = (BigUint::one() << 68) - BigUint::one();
                for (input, (q, value)) in shares.into_iter().zip(cases) {
                    let divisor = U512::from_limbs_truncating(&q.to_u64_digits());
                    let (quotient, remainder) =
                        yao::ring_div_by_public_to_fr_limbs_and_fq::<T, _, Fr, Fq>(
                            input, 68, &divisor, 4, &net, &mut state,
                        )
                        .unwrap();
                    let quotient = arithmetic::open_vec(&quotient, &net).unwrap();
                    let remainder = arithmetic::open_vec(&[remainder], &net).unwrap();
                    let expected = &value / &q;
                    let expected_limbs: Vec<_> = (0..4)
                        .map(|i| Fr::from((&expected >> (68 * i)) & &mask))
                        .collect();
                    assert_eq!(quotient, expected_limbs, "{}-bit numerator quotient", T::K);
                    assert_eq!(
                        remainder,
                        vec![Fq::from(
                            (&value % &q) & ((BigUint::one() << 254usize) - BigUint::one())
                        )],
                        "{}-bit numerator remainder",
                        T::K
                    );
                }
                for limb_size in [
                    0,
                    Fr::MODULUS_BIT_SIZE as usize,
                    Fr::MODULUS_BIT_SIZE as usize + 1,
                ] {
                    assert!(
                        yao::ring_div_by_public_to_fr_limbs_and_fq_many::<U512, _, Fr, Fq>(
                            &[],
                            limb_size,
                            &U512::from(1u64),
                            4,
                            &PanicNetwork,
                            &mut state,
                        )
                        .is_err(),
                        "Reject noncanonical quotient widths before communication"
                    );
                }
                for divisor in [U512::from(0u64), U512::from(256u64)] {
                    assert!(
                        yao::ring_div_by_public_to_fr_limbs_and_fq_many::<u8, _, Fr, Fq>(
                            &[],
                            68,
                            &divisor,
                            4,
                            &PanicNetwork,
                            &mut state,
                        )
                        .is_err(),
                        "Reject zero or truncated public divisors before communication"
                    );
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
}

#[test]
fn private_division_uses_all_512_input_bits() {
    check::<U512>();
}

#[test]
fn private_division_uses_all_1024_input_bits() {
    check::<U1024>();
}

//! Robustness regression: the REP3 driver's non-native (bigfield) limb
//! reconstruction `acvm_type_limbs_to_other_acvm_type` must FAIL CLEANLY
//! (return `Err`) — not panic — when any input limb is secret-shared.
//!
//! Background: plain `recursion` (HONK_IDENTIFIER=0) proving under REP3 drives
//! this operation on secret-shared limbs during circuit build, which used to
//! hit an `unimplemented!` and abort the whole party with a panic. Shared
//! non-native field reconstruction is a cross-field switch on shared data that
//! REP3 does not implement (and Shamir declares infeasible); the correct
//! behaviour for a reachable-but-unsupported path is a graceful error, so the
//! caller (co-noir) surfaces it as a normal failure rather than crashing. The
//! ZK recursion flavour (`recursion_zk`) does not exercise this path and is
//! unaffected.
//!
//! This test runs the REAL three-party REP3 driver over a LocalNetwork (the
//! `eyre::bail!` fires before any communication, so no proving is involved) and
//! checks both directions: the fully-public case still succeeds and reconstructs
//! correctly, and the secret-shared case returns a clear `Err`.

use ark_bn254::{Fq, Fr, G1Projective};
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_acvm::{Rep3AcvmSolver, Rep3AcvmType};
use itertools::izip;
use mpc_core::protocols::rep3::conversion::A2BType;
use mpc_core::protocols::rep3::share_field_elements;
use mpc_net::local::LocalNetwork;
use rand::{SeedableRng, rngs::StdRng};
use std::sync::mpsc;

// The bigfield layout co-builder actually uses (big_field.rs callers): four
// 68-bit limbs.
const NUM_LIMBS: usize = 4;
const LIMB_BITS: usize = 68;

#[test]
fn rep3_acvm_type_limbs_to_other_acvm_type_shared_errs_not_panics() {
    // One field value to secret-share, used as the (single) shared limb.
    let mut rng = StdRng::seed_from_u64(0xB16F1E1D);
    let shares = share_field_elements(&[Fr::from(7u64)], &mut rng);

    let nets0 = LocalNetwork::new_3_parties();
    let nets1 = LocalNetwork::new_3_parties();
    let (txs, rxs): (Vec<_>, Vec<_>) = (0..3).map(|_| mpsc::channel()).unzip();

    for (net0, net1, my_shares, tx) in izip!(nets0, nets1, shares, txs) {
        std::thread::spawn(move || {
            let mut driver =
                Rep3AcvmSolver::<Fr, _>::new(&net0, &net1, A2BType::default()).unwrap();

            // ---- positive control: fully-public limbs still reconstruct.
            // value = 5 + 0*2^68 + 0*2^136 + 0*2^204 = 5 in the base field Fq.
            let public_limbs: [Rep3AcvmType<Fr>; NUM_LIMBS] = [
                Rep3AcvmType::Public(Fr::from(5u64)),
                Rep3AcvmType::Public(Fr::from(0u64)),
                Rep3AcvmType::Public(Fr::from(0u64)),
                Rep3AcvmType::Public(Fr::from(0u64)),
            ];
            let public_res = driver
                .acvm_type_limbs_to_other_acvm_type::<NUM_LIMBS, LIMB_BITS, G1Projective>(
                    &public_limbs,
                )
                .expect("public bigfield reconstruction must still succeed");
            match public_res {
                Rep3AcvmType::Public(v) => {
                    assert_eq!(v, Fq::from(5u64), "public reconstruction value mismatch")
                }
                Rep3AcvmType::Shared(_) => panic!("public inputs must yield a public output"),
            }

            // ---- the regression: one shared limb, rest public. This MUST
            // return Err (and, crucially, MUST NOT panic — a panic here would
            // unwind the thread and fail the join below).
            let mut shared_limbs = public_limbs;
            shared_limbs[0] = Rep3AcvmType::Shared(my_shares[0]);
            let shared_res = driver
                .acvm_type_limbs_to_other_acvm_type::<NUM_LIMBS, LIMB_BITS, G1Projective>(
                    &shared_limbs,
                );

            let msg = match shared_res {
                Ok(_) => panic!("shared bigfield reconstruction must not succeed under REP3"),
                Err(e) => e.to_string(),
            };
            tx.send(msg).unwrap();
        });
    }

    // Every party must have produced a clear, descriptive error (not a panic).
    for rx in rxs {
        let msg = rx
            .recv()
            .expect("a party thread panicked instead of returning Err");
        assert!(
            msg.contains("not supported under REP3 MPC"),
            "error should explain the unsupported shared bigfield case; got: {msg}"
        );
        assert!(
            msg.contains("recursion_zk"),
            "error should point operators at the working ZK recursion flavour; got: {msg}"
        );
    }
}

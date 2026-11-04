//! Driver-level tests that run single `Rep3AcvmSolver` operations on three parties and compare
//! the reconstructed results with the plain driver.

use ark_bn254::Fr;
use co_acvm::{mpc::NoirWitnessExtensionProtocol, PlainAcvmSolver, Rep3AcvmSolver, Rep3AcvmType};
use itertools::izip;
use mpc_core::protocols::rep3::{
    combine_field_element, conversion::A2BType, share_field_element, share_field_elements,
};
use mpc_net::local::LocalNetwork;
use num_bigint::BigUint;
use num_traits::One;
use rand::thread_rng;

type Rep3Driver<'a> = Rep3AcvmSolver<'a, Fr, LocalNetwork>;

/// An operand of a driver test: either public to all parties or secret-shared.
#[derive(Clone, Copy, Debug)]
enum Input {
    Public(Fr),
    Shared(Fr),
}

impl Input {
    /// Splits the input into one `Rep3AcvmType` per party.
    fn to_parties(self) -> [Rep3AcvmType<Fr>; 3] {
        match self {
            Input::Public(x) => [x.into(), x.into(), x.into()],
            Input::Shared(x) => share_field_element(x, &mut thread_rng()).map(Rep3AcvmType::from),
        }
    }
}

/// Opens the three parties' outputs. Public outputs must agree.
fn open(values: [Rep3AcvmType<Fr>; 3]) -> Fr {
    match values {
        [Rep3AcvmType::Public(a), Rep3AcvmType::Public(b), Rep3AcvmType::Public(c)] => {
            assert!(a == b && b == c, "public outputs differ between parties");
            a
        }
        [Rep3AcvmType::Shared(a), Rep3AcvmType::Shared(b), Rep3AcvmType::Shared(c)] => {
            combine_field_element::<Fr>(a, b, c)
        }
        _ => panic!("parties disagree on whether the output is shared"),
    }
}

/// Runs `op` on a fresh `Rep3AcvmSolver` for each of the three parties. `inputs[i]` is the list
/// of operands party `i` receives.
fn run_rep3<I, O>(
    inputs: [I; 3],
    op: impl Fn(&mut Rep3Driver<'_>, I) -> O + Send + Sync + Copy + 'static,
) -> [O; 3]
where
    I: Send + 'static,
    O: Send + 'static,
{
    let threads: Vec<_> = izip!(LocalNetwork::new_3_parties(), inputs)
        .map(|(net, input)| {
            std::thread::spawn(move || {
                let mut driver = Rep3Driver::new(&net, A2BType::default()).unwrap();
                op(&mut driver, input)
            })
        })
        .collect();
    threads
        .into_iter()
        .map(|t| t.join().unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap_or_else(|_| unreachable!())
}

/// All four public/shared combinations of the operands `a` and `b`.
fn binary_cases(a: Fr, b: Fr) -> [(Input, Input); 4] {
    [
        (Input::Public(a), Input::Public(b)),
        (Input::Public(a), Input::Shared(b)),
        (Input::Shared(a), Input::Public(b)),
        (Input::Shared(a), Input::Shared(b)),
    ]
}

fn comparison_operands() -> Vec<(Fr, Fr)> {
    let big = -Fr::from(1u64);
    vec![
        (Fr::from(5u64), Fr::from(5u64)),
        (Fr::from(4u64), Fr::from(5u64)),
        (Fr::from(5u64), Fr::from(4u64)),
        (Fr::from(0u64), Fr::from(0u64)),
        (big, big),
        (big, Fr::from(0u64)),
        (Fr::from(0u64), big),
    ]
}

#[test]
fn rep3_gt_and_lt_match_plain() {
    let mut plain = PlainAcvmSolver::<Fr>::new();
    for (a, b) in comparison_operands() {
        for (lhs, rhs) in binary_cases(a, b) {
            let expected_gt = plain.gt(a, b).unwrap();
            let expected_lt = plain.lt(a, b).unwrap();
            let inputs = izip!(lhs.to_parties(), rhs.to_parties())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap_or_else(|_| unreachable!());
            let outputs = run_rep3(inputs, |driver, (lhs, rhs)| {
                let gt = driver.gt(lhs.clone(), rhs.clone()).unwrap();
                let lt = driver.lt(lhs, rhs).unwrap();
                (gt, lt)
            });
            let [o0, o1, o2] = outputs;
            assert_eq!(
                open([o0.0, o1.0, o2.0]),
                expected_gt,
                "gt({lhs:?}, {rhs:?})"
            );
            assert_eq!(
                open([o0.1, o1.1, o2.1]),
                expected_lt,
                "lt({lhs:?}, {rhs:?})"
            );
            assert_eq!(expected_gt, Fr::from(a > b));
            assert_eq!(expected_lt, Fr::from(a < b));
        }
    }
}

#[test]
fn rep3_and_plain_slice_return_lo_then_hi() {
    let values = [
        Fr::from(0u64),
        Fr::from((BigUint::one() << 128) + BigUint::from(255u64)),
        -Fr::from(1u64),
    ];
    let (msb, lsb, bitsize) = (128u8, 0u8, 254usize);
    let expected: Vec<[Fr; 2]> = values
        .iter()
        .map(|value| {
            let x: BigUint = (*value).into();
            let lo = &x & ((BigUint::one() << msb) - BigUint::one());
            let hi = &x >> msb;
            [Fr::from(lo), Fr::from(hi)]
        })
        .collect();

    let mut plain = PlainAcvmSolver::<Fr>::new();
    for (value, expected) in values.iter().zip(&expected) {
        assert_eq!(&plain.slice(*value, msb, lsb, bitsize).unwrap(), expected);
    }
    assert_eq!(
        plain.slice_many(&values, msb, lsb, bitsize).unwrap(),
        expected
    );

    let shares = share_field_elements(&values, &mut thread_rng());
    let outputs = run_rep3(shares, move |driver, shares| {
        let single: Vec<_> = shares
            .iter()
            .map(|x| driver.slice(*x, msb, lsb, bitsize).unwrap())
            .collect();
        let many = driver.slice_many(&shares, msb, lsb, bitsize).unwrap();
        (single, many)
    });
    let open_slices = |per_party: [&Vec<[_; 2]>; 3]| -> Vec<[Fr; 2]> {
        (0..values.len())
            .map(|i| {
                [0, 1].map(|part| {
                    combine_field_element(
                        per_party[0][i][part],
                        per_party[1][i][part],
                        per_party[2][i][part],
                    )
                })
            })
            .collect()
    };
    let [p0, p1, p2] = &outputs;
    assert_eq!(open_slices([&p0.0, &p1.0, &p2.0]), expected);
    assert_eq!(open_slices([&p0.1, &p1.1, &p2.1]), expected);
}

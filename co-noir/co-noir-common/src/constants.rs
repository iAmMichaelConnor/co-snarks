use crate::{
    mpc::{NoirUltraHonkProver, plain::PlainUltraHonkDriver},
    polynomials::entities::{
        PRECOMPUTED_ENTITIES_SIZE, ProverWitnessEntities, WITNESS_ENTITIES_SIZE,
    },
    types::Bn254G1,
};

/// The log of the max circuit size assumed in order to achieve constant sized Honk proofs
/// AZTEC TODO(<https://github.com/AztecProtocol/barretenberg/issues/1046>): Remove the need for const sized proofs
pub const CONST_PROOF_SIZE_LOG_N: usize = 25;
// For ZK Flavors: the number of the commitments required by Libra and SmallSubgroupIPA.
pub const NUM_LIBRA_COMMITMENTS: usize = 3;
// Number of SmallSubgroupIPA evaluations transmitted on the wire: G(r), A(g*r), A(r), Q(r).
pub const NUM_SMALL_IPA_EVALUATIONS: usize = 4;
// Total number of SmallSubgroupIPA opening claims batched into Shplonk. On top of the 4 transmitted
// evaluations, this includes the untransmitted boundary opening A(1) = 0 (in transcript order the
// claims are G(r), A(g*r), A(r), A(1), Q(r)).
pub const NUM_SMALL_IPA_OPENING_CLAIMS: usize = NUM_SMALL_IPA_EVALUATIONS + 1;

// The number of rows reserved at the top of the trace for row-disabling / ZK masking. Row 0 is the
// zero row (for shifts), rows {1, 2, 3} hold the ZK masking values (zeros for non-ZK flavors),
// lagrange_first sits at row TRACE_OFFSET, and the trace content starts at row
// TRACE_OFFSET + NUM_ZERO_ROWS.
pub const TRACE_OFFSET: usize =
    crate::polynomials::polynomial::NUM_DISABLED_ROWS_IN_SUMCHECK as usize;

pub const SHIFTED_WITNESS_ENTITIES_SIZE: usize = 5;

pub const MAX_PARTIAL_RELATION_LENGTH: usize = 7;
pub const BATCHED_RELATION_PARTIAL_LENGTH: usize = MAX_PARTIAL_RELATION_LENGTH + 1;
pub const BATCHED_RELATION_PARTIAL_LENGTH_ZK: usize = BATCHED_RELATION_PARTIAL_LENGTH + 1;

pub const NUM_ALL_ENTITIES: usize =
    WITNESS_ENTITIES_SIZE + PRECOMPUTED_ENTITIES_SIZE + SHIFTED_WITNESS_ENTITIES_SIZE;

pub const PUBLIC_INPUTS_SIZE: usize = 8;

pub const NUM_ZERO_ROWS: usize = 1;
const NUM_FRS_FR: usize = 1;
const NUM_FRS_COMM: usize = 4;

pub const ULTRA_VERIFICATION_KEY_LENGTH: usize = PRECOMPUTED_ENTITIES_SIZE * 4 + 3;

pub const ULTRA_PROOF_LENGTH_WITHOUT_PUB_INPUTS: usize =
    OINK_PROOF_LENGTH_WITHOUT_PUB_INPUTS + DECIDER_PROOF_LENGTH;

pub const OINK_PROOF_LENGTH_WITHOUT_PUB_INPUTS_ZK: usize =
    OINK_PROOF_LENGTH_WITHOUT_PUB_INPUTS + NUM_FRS_COMM;

pub const ULTRA_PROOF_LENGTH_WITHOUT_PUB_INPUTS_ZK: usize =
    OINK_PROOF_LENGTH_WITHOUT_PUB_INPUTS_ZK + DECIDER_PROOF_LENGTH_ZK;

pub const DECIDER_PROOF_LENGTH: usize = /* 2. virtual_log_n sumcheck univariates */
    (CONST_PROOF_SIZE_LOG_N * BATCHED_RELATION_PARTIAL_LENGTH ) +
            /* 3. NUM_ALL_ENTITIES sumcheck evaluations */ (NUM_ALL_ENTITIES ) +
            /* 4. virtual_log_n - 1 Gemini Fold commitments */ ((CONST_PROOF_SIZE_LOG_N - 1) * NUM_FRS_COMM) +
            /* 5. virtual_log_n Gemini a evaluations */ (CONST_PROOF_SIZE_LOG_N ) +
            /* 6. Shplonk Q commitment */ (NUM_FRS_COMM) +
            /* 7. KZG W commitment */ (NUM_FRS_COMM);

pub const DECIDER_PROOF_LENGTH_ZK: usize =
    /* 2. Libra concatenation commitment*/
    (NUM_FRS_COMM) +
               /* 3. Libra sum */ (NUM_FRS_FR) +
                /* 4. virtual_log_n sumcheck univariates */
(CONST_PROOF_SIZE_LOG_N * BATCHED_RELATION_PARTIAL_LENGTH_ZK ) +
               /* 5. NUM_ALL_ENTITIES sumcheck evaluations plus Gemini masking evaluation */
               (NUM_ALL_ENTITIES + NUM_FRS_FR) +
                /* 6. Libra claimed evaluation */ (NUM_FRS_FR) +
               /* 7. Libra grand sum commitment */ (NUM_FRS_COMM) +
               /* 8. Libra quotient commitment */ (NUM_FRS_COMM) +
               /* 11. virtual_log_n - 1 Gemini Fold commitments */
               ((CONST_PROOF_SIZE_LOG_N - 1) * NUM_FRS_COMM) +
               /* 12. virtual_log_n Gemini a evaluations */
               (CONST_PROOF_SIZE_LOG_N * NUM_FRS_FR) +
               /* 13. NUM_SMALL_IPA_EVALUATIONS libra evals */ (NUM_SMALL_IPA_EVALUATIONS * NUM_FRS_FR) +
               /* 14. Shplonk Q commitment */ (NUM_FRS_COMM) +
               /* 15. KZG W commitment */ (NUM_FRS_COMM);

pub const OINK_PROOF_LENGTH_WITHOUT_PUB_INPUTS: usize = WITNESS_ENTITIES_SIZE * 4;

// Target invariants at bb v5-next (mirrors bb's static_asserts): the proof-with-pairing-points
// sizes accepted in-contract are 410 (non-ZK) / 458 (ZK) frs, and the VK is 115 frs. A change in
// any component constant above must fail here loudly rather than silently drift the proof format.
const _: () = assert!(ULTRA_PROOF_LENGTH_WITHOUT_PUB_INPUTS + PUBLIC_INPUTS_SIZE == 410);
const _: () = assert!(ULTRA_PROOF_LENGTH_WITHOUT_PUB_INPUTS_ZK + PUBLIC_INPUTS_SIZE == 458);
const _: () = assert!(ULTRA_VERIFICATION_KEY_LENGTH == 115);
// Further format-defining constants pinned at their bb v5-next values: each of these moved (or was
// explicitly reviewed) in the 20260324→20260708 sync. Any component change must fail loudly here.
const _: () = assert!(NUM_ALL_ENTITIES == 41);
const _: () = assert!(TRACE_OFFSET == 4);
const _: () = assert!(CONST_PROOF_SIZE_LOG_N == 25);
const _: () = assert!(NUM_LIBRA_COMMITMENTS == 3);
const _: () = assert!(NUM_SMALL_IPA_EVALUATIONS == 4);
const _: () = assert!(NUM_SMALL_IPA_OPENING_CLAIMS == 5);

pub const MOCK_PROOF_DYADIC_SIZE: usize = 1 << 6;

pub const NUM_WIRES: usize = 4;
pub const NUM_SELECTORS: usize = 14;

// Arbitrarily large constant (> size of the BN254 srs) used to ensure that the evaluations on the hypercube of the
// permutation argument polynomials (sigmas, ids) are unique, e.g. id[i][j] == id[m][n] iff (i == m && j == n)
pub const PERMUTATION_ARGUMENT_VALUE_SEPARATOR: u32 = 1 << 28;

pub const PAIRING_POINT_ACCUMULATOR_SIZE: u32 = 8;

pub const PUBLIC_INPUT_WIRE_INDEX: usize = ProverWitnessEntities::<
    <PlainUltraHonkDriver as NoirUltraHonkProver<Bn254G1>>::ArithmeticShare,
>::W_R;

#![warn(clippy::iter_over_hash_type)]

pub mod co_decider;
pub mod co_oink;
pub(crate) mod co_ultra_prover;
pub mod prelude;
pub mod types_batch;

/// Coarse wall-clock phase timings for the prover, enabled with
/// `CO_NOIR_PHASE_TIMINGS=1`. Output goes to stderr only; it never touches the
/// transcript or the proof bytes.
///
/// Emission is shared workspace-wide (see `co_noir_common::phase_timing`) so
/// every phase line — prover, proving-key construction, plaindriver — is written
/// the same way: one atomic write per line, which matters because the bench has
/// all three MPC parties appending to a single log file.
pub(crate) use co_noir_common::phase_timing::{phase_timing, phase_timing_secs};

// The log of the max circuit size assumed in order to achieve constant sized Honk proofs
// AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/1046): Remove the need for const sized proofs
pub(crate) const CONST_PROOF_SIZE_LOG_N: usize = ultrahonk::CONST_PROOF_SIZE_LOG_N;

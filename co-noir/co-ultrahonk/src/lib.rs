#![warn(clippy::iter_over_hash_type)]

pub mod co_decider;
pub mod co_oink;
pub(crate) mod co_ultra_prover;
pub mod prelude;
pub mod types_batch;

/// Coarse wall-clock phase timings for the prover, enabled with
/// `CO_NOIR_PHASE_TIMINGS=1`. Output goes to stderr only; it never touches the
/// transcript or the proof bytes.
pub(crate) fn phase_timings_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var("CO_NOIR_PHASE_TIMINGS").as_deref() == Ok("1"))
}

/// Print one phase-timing line (stderr) if `CO_NOIR_PHASE_TIMINGS=1`.
pub(crate) fn phase_timing(name: &str, start: std::time::Instant) {
    if phase_timings_enabled() {
        eprintln!(
            "[phase-timing] {name}: {:.6}s",
            start.elapsed().as_secs_f64()
        );
    }
}

/// Print one phase-timing line (stderr) for a pre-accumulated duration if
/// `CO_NOIR_PHASE_TIMINGS=1`. Used for sub-phases that are accumulated across
/// loop iterations (e.g. per-sumcheck-round work) and reported once.
pub(crate) fn phase_timing_secs(name: &str, secs: f64) {
    if phase_timings_enabled() {
        eprintln!("[phase-timing] {name}: {secs:.6}s");
    }
}

// The log of the max circuit size assumed in order to achieve constant sized Honk proofs
// AZTEC TODO(https://github.com/AztecProtocol/barretenberg/issues/1046): Remove the need for const sized proofs
pub(crate) const CONST_PROOF_SIZE_LOG_N: usize = ultrahonk::CONST_PROOF_SIZE_LOG_N;

//! Coarse wall-clock phase timings, enabled with `CO_NOIR_PHASE_TIMINGS=1`.
//!
//! Lives here because every layer that reports timings — the prover
//! (`co-ultrahonk`), proving-key construction (`co-builder`) and the CLI
//! binaries — depends on this crate, while `co-builder` itself depends on
//! `co-ultrahonk`, so neither of those two can host it for the other.
//!
//! Output is stderr only and gated on the env var: it never touches the
//! transcript, the proving key or the proof bytes.

/// Whether `CO_NOIR_PHASE_TIMINGS=1` was set. Read once.
pub fn phase_timings_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var("CO_NOIR_PHASE_TIMINGS").as_deref() == Ok("1"))
}

/// Print one phase-timing line for the time elapsed since `start`.
pub fn phase_timing(name: &str, start: std::time::Instant) {
    if phase_timings_enabled() {
        write_phase_timing_line(name, start.elapsed().as_secs_f64());
    }
}

/// Print one phase-timing line for a pre-accumulated duration. Used for
/// sub-phases summed across loop iterations (per-sumcheck-round work, the
/// per-trace-block wire and selector passes) and reported once.
pub fn phase_timing_secs(name: &str, secs: f64) {
    if phase_timings_enabled() {
        write_phase_timing_line(name, secs);
    }
}

/// Emit one line as a SINGLE `write` of a pre-formatted string.
///
/// The bench runs all three MPC parties as separate processes appending to one
/// shared log file. `eprintln!` formats incrementally and can issue several
/// writes per line, so two parties finishing a phase at the same moment
/// interleaved mid-token and produced lines like
/// `[phase-timing] 0.pkgen/alloc_copy_cycles000: 2180.s`, which broke the
/// bench's JSON extraction (observed 2026-07-29). One `write_all` of a complete
/// line is an atomic append on a regular file, so lines from different parties
/// can no longer splice into each other.
fn write_phase_timing_line(name: &str, secs: f64) {
    use std::io::Write as _;
    let line = format!("[phase-timing] {name}: {secs:.6}s\n");
    let stderr = std::io::stderr();
    let mut lock = stderr.lock();
    let _ = lock.write_all(line.as_bytes());
    let _ = lock.flush();
}

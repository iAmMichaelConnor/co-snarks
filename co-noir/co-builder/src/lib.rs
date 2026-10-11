#![warn(clippy::iter_over_hash_type)]

use noir_types::ProgramArtifact;

use crate::prelude::AcirFormat;

pub(crate) mod acir_format;
pub(crate) mod honk_verifier;
pub mod keys;
pub mod prelude;
pub mod transcript_ct;
pub mod types;
pub(crate) mod ultra_builder;

/// Coarse wall-clock phase timings for proving-key construction, enabled with
/// `CO_NOIR_PHASE_TIMINGS=1`. Re-exported from `co_noir_common` so the
/// proving-key phases share one emitter (and one output format) with the
/// prover-side timings in `co-ultrahonk`: a single run yields both halves of the
/// pipeline, and the bench can attribute each phase to setup or per-proof work.
pub use co_noir_common::phase_timing::{phase_timing, phase_timing_secs, phase_timings_enabled};

pub fn get_constraint_system_from_artifact(
    program_artifact: &ProgramArtifact,
) -> AcirFormat<ark_bn254::Fr> {
    let circuit = program_artifact.bytecode.functions[0].to_owned();
    AcirFormat::circuit_serde_to_acir_format(circuit)
}

pub fn constraint_system_from_reader(
    reader: impl std::io::Read,
) -> eyre::Result<AcirFormat<ark_bn254::Fr>> {
    let program_artifact = noir_types::program_artifact_from_reader(reader)?;
    Ok(get_constraint_system_from_artifact(&program_artifact))
}

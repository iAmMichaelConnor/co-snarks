use crate::crs::ProverCrs;
use crate::keys::types::ActiveRegionData;
use crate::polynomials::polynomial::Polynomials;
use ark_ec::CurveGroup;
use std::sync::Arc;

#[derive(Default)]
pub struct PlainProvingKey<P: CurveGroup> {
    pub proof_privacy: crate::keys::proof_privacy::ProofPrivacy,
    pub crs: Arc<ProverCrs<P>>,
    pub circuit_size: u32,
    pub public_inputs: Vec<P::ScalarField>,
    pub num_public_inputs: u32,
    pub pub_inputs_offset: u32,
    pub polynomials: Polynomials<P::ScalarField>,
    pub memory_read_records: Vec<u32>,
    pub memory_write_records: Vec<u32>,
    /// Absolute trace rows whose fourth wire receives a ROM LogUp inverse.
    pub rom_logup_records: Vec<u32>,
    pub final_active_wire_idx: usize,
    pub active_region_data: ActiveRegionData,
}

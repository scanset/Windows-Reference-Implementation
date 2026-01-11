//! Attestation builder
//!
//! Builds CUI-free attestation results for network transport.
//!
//! ## Hash Architecture
//!
//! The `content_hash` and `evidence_hash` are pre-computed in the execution engine
//! and passed through via `ScanResult`. This ensures hash consistency across all
//! output formats.

use common::results::{AttestationResult, CheckInput, ResultBuilder};
use contract_kit::execution_api::ScanResult;

use super::OutputError;
use crate::output::combine_scan_hashes;

/// Build a unified AttestationResult containing all check attestations in a single envelope
///
/// ## Hash Handling
///
/// Uses pre-computed hashes from `ScanResult` rather than recomputing them.
/// This ensures the attestation's hashes match those in full results and
/// assessor packages for the same scan.
pub fn build_attestation(scan_results: &[ScanResult]) -> Result<AttestationResult, OutputError> {
    if scan_results.is_empty() {
        return Err(OutputError::Build(
            "At least one scan result is required".to_string(),
        ));
    }

    let result_builder = ResultBuilder::from_system("esp-agent");

    // Convert all scan results to CheckInput
    let checks: Vec<CheckInput> = scan_results
        .iter()
        .map(|scan_result| {
            CheckInput::new(
                &scan_result.outcome.policy_id,
                &scan_result.outcome.platform,
                scan_result.outcome.criticality,
                scan_result.outcome.control_mappings.clone(),
                scan_result.outcome.outcome,
            )
        })
        .collect();

    // Get pre-computed hashes from scan results
    let (content_hash, evidence_hash) = combine_scan_hashes(scan_results)?;

    result_builder
        .build_attestation(checks, content_hash, evidence_hash)
        .map_err(|e| e.into())
}

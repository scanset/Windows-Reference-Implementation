//! Full result builder
//!
//! Builds complete results with findings and evidence.
//!
//! ## Hash Architecture
//!
//! The `content_hash` and `evidence_hash` are pre-computed in the execution engine
//! and passed through via `ScanResult`. This ensures hash consistency across all
//! output formats.

use common::results::{Evidence, FullResult, PolicyInput, ResultBuilder};
use contract_kit::execution_api::ScanResult;

use super::OutputError;
use crate::output::combine_scan_hashes;

/// Build a unified FullResult containing all policy results in a single envelope
///
/// ## Hash Handling
///
/// Uses pre-computed hashes from `ScanResult` rather than recomputing them.
/// This ensures the full result's hashes match those in attestations and
/// assessor packages for the same scan.
pub fn build_full_result(scan_results: &[ScanResult]) -> Result<FullResult, OutputError> {
    if scan_results.is_empty() {
        return Err(OutputError::Build(
            "At least one scan result is required".to_string(),
        ));
    }

    let result_builder = ResultBuilder::from_system("esp-agent");

    // Convert all scan results to PolicyInput
    let policies: Vec<PolicyInput> = scan_results
        .iter()
        .map(|scan_result| {
            let evidence: Evidence = scan_result.evidence.clone().unwrap_or_default();

            PolicyInput::new(
                &scan_result.outcome.policy_id,
                &scan_result.outcome.platform,
                scan_result.outcome.criticality,
                scan_result.outcome.control_mappings.clone(),
                scan_result.outcome.outcome,
            )
            .with_findings(scan_result.findings.clone())
            .with_evidence(evidence)
        })
        .collect();

    // Get pre-computed hashes from scan results
    let (content_hash, evidence_hash) = combine_scan_hashes(scan_results)?;

    result_builder
        .build_full_result(policies, content_hash, evidence_hash)
        .map_err(|e| e.into())
}

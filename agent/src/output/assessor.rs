//! Assessor package builder
//!
//! Builds complete assessor packages with full reproducibility information.
//! This format includes exact commands and inputs used during collection,
//! allowing assessors to verify and reproduce the scan.
//!
//! ## Hash Architecture
//!
//! The `content_hash` and `evidence_hash` are pre-computed in the execution engine
//! and passed through via `ScanResult`. This ensures hash consistency across all
//! output formats.
#[allow(unused_imports)]
use common::results::{
    builder::AssessorInput, AgentInfo, AssessorPackage, Criticality, Evidence, HostInfo,
    ResultBuilder,
};
use contract_kit::execution_api::ScanResult;

use super::OutputError;
use crate::output::combine_scan_hashes;

/// Build a unified AssessorPackage containing all policy results with full reproducibility info
///
/// ## Hash Handling
///
/// Uses pre-computed hashes from `ScanResult` rather than recomputing them.
/// This ensures the assessor package's hashes match those in attestations and
/// full results for the same scan.
pub fn build_assessor_package(scan_results: &[ScanResult]) -> Result<AssessorPackage, OutputError> {
    if scan_results.is_empty() {
        return Err(OutputError::Build(
            "At least one scan result is required".to_string(),
        ));
    }

    let agent = AgentInfo::with_defaults("esp-agent");
    let host = HostInfo::from_system();
    let result_builder = ResultBuilder::new(agent, host);

    // Convert all scan results to AssessorInput
    let policies: Vec<AssessorInput> = scan_results
        .iter()
        .map(|scan_result| {
            let evidence = scan_result.evidence.clone().unwrap_or_default();
            let weight = criticality_to_weight(scan_result.outcome.criticality);

            AssessorInput::new(
                &scan_result.outcome.policy_id,
                &scan_result.outcome.platform,
                scan_result.outcome.criticality,
                scan_result.outcome.control_mappings.clone(),
                scan_result.outcome.outcome,
            )
            .with_weight(weight)
            .with_findings(scan_result.findings.clone())
            .with_evidence(evidence)
        })
        .collect();

    // Get pre-computed hashes from scan results
    let (content_hash, evidence_hash) = combine_scan_hashes(scan_results)?;

    result_builder
        .build_assessor_package(policies, content_hash, evidence_hash)
        .map_err(|e| OutputError::Build(e.to_string()))
}

/// Convert criticality to default weight
fn criticality_to_weight(criticality: Criticality) -> f32 {
    match criticality {
        Criticality::Critical => 1.0,
        Criticality::High => 0.8,
        Criticality::Medium => 0.5,
        Criticality::Low => 0.3,
        Criticality::Info => 0.1,
    }
}

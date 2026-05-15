//! Assessor package builder
//!
//! Builds complete assessor packages with full reproducibility information.
//! This format includes exact commands and inputs used during collection,
//! allowing assessors to verify and reproduce the scan.
//!
//! ## Hash Architecture
//!
//! The `replay_hash` is pre-computed in the execution engine and passed through
//! via `ScanResult`. This ensures hash consistency across all output formats.
//! The replay hash captures intent + contract + outcome rolled up through the
//! CRI tree — excluding volatile evidence values for stable deduplication.
//!
//! ## Identity Status
//!
//! As of schema v1.2.0, assessor packages include an `identity_status` field.
//! The Agent SDK always provides `IdentityStatus::disabled` since it does
//! not perform PKI bootstrap.

use crate::contract_kit::execution_api::ScanResult;
use common::results::{
    builder::AssessorInput, AgentInfo, AssessorPackage, Criticality, HostInfo, IdentityStatus,
    ResultBuilder,
};

use super::OutputError;
use crate::output::combine_replay_hashes;

/// Build a unified AssessorPackage containing all policy results with full reproducibility info
///
/// ## Hash Handling
///
/// Uses the pre-computed `replay_hash` from `ScanResult` rather than recomputing.
/// This ensures the assessor package's hash matches those in attestations and full
/// results for the same scan.
pub fn build_assessor_package(
    scan_results: &[ScanResult],
    identity_status: IdentityStatus,
) -> Result<AssessorPackage, OutputError> {
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
            .with_metadata(scan_result.metadata.clone())
            .with_findings(scan_result.findings.clone())
            .with_evidence(evidence)
        })
        .collect();

    // Get pre-computed replay hash from scan results
    let replay_hash = combine_replay_hashes(scan_results)?;

    result_builder
        .build_assessor_package(policies, replay_hash, identity_status)
        .map_err(|e| OutputError::Build(e.to_string()))
}

/// Convert criticality to default weight
fn criticality_to_weight(criticality: Criticality) -> f32 {
    criticality.default_weight()
}

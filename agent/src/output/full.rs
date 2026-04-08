//! Full result builder
//!
//! Builds complete results with findings and evidence.
//!
//! ## Hash Architecture
//!
//! The `replay_hash` is pre-computed in the execution engine and passed through
//! via `ScanResult`. This ensures hash consistency across all output formats.
//!
//! ## Identity Status
//!
//! As of schema v1.2.0, full results include an `identity_status` field.
//! The Agent SDK always provides `IdentityStatus::disabled` since it does
//! not perform PKI bootstrap.

use common::results::{Evidence, FullResult, IdentityStatus, PolicyInput, ResultBuilder};
use crate::contract_kit::execution_api::ScanResult;

use super::OutputError;
use crate::output::combine_replay_hashes;

/// Build a unified FullResult containing all policy results in a single envelope
///
/// ## Hash Handling
///
/// Uses the pre-computed `replay_hash` from `ScanResult` rather than recomputing.
/// This ensures the full result's hash matches those in attestations and assessor
/// packages for the same scan.
pub fn build_full_result(
    scan_results: &[ScanResult],
    identity_status: IdentityStatus,
) -> Result<FullResult, OutputError> {
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

    // Get pre-computed replay hash from scan results
    let replay_hash = combine_replay_hashes(scan_results)?;

    result_builder
        .build_full_result(policies, replay_hash, identity_status)
        .map_err(|e| e.into())
}

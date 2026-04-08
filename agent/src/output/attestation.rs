//! Attestation builder
//!
//! Builds CUI-free attestation results for network transport.
//!
//! ## Hash Architecture
//!
//! The `replay_hash` is pre-computed in the execution engine and passed through
//! via `ScanResult`. This ensures hash consistency across all output formats.
//!
//! ## Identity Status
//!
//! As of schema v1.2.0, attestations include an `identity_status` field.
//! The Agent SDK always provides `IdentityStatus::disabled` since it does
//! not perform PKI bootstrap.

use common::results::{AttestationResult, CheckInput, IdentityStatus, ResultBuilder};
use crate::contract_kit::execution_api::ScanResult;

use super::OutputError;
use crate::output::combine_replay_hashes;

/// Build a unified AttestationResult containing all check attestations in a single envelope
///
/// ## Hash Handling
///
/// Uses the pre-computed `replay_hash` from `ScanResult` rather than recomputing.
/// This ensures the attestation's hash matches those in full results and assessor
/// packages for the same scan.
pub fn build_attestation(
    scan_results: &[ScanResult],
    identity_status: IdentityStatus,
) -> Result<AttestationResult, OutputError> {
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

    // Get pre-computed replay hash from scan results
    let replay_hash = combine_replay_hashes(scan_results)?;

    result_builder
        .build_attestation(checks, replay_hash, identity_status)
        .map_err(|e| e.into())
}

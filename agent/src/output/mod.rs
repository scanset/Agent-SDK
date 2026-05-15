//! Output generation module.
//!
//! v2.0.0 of the ESP engine collapsed the previous `full` / `attestation` /
//! `summary` output formats into a single signed `AssessorPackage`
//! envelope. There is now exactly one output shape — every scan produces
//! an `AssessorPackage` (signed if a backend is available, unsigned with
//! a warning otherwise) plus the human-readable console rendering.
//!
//! ## Hash Architecture
//!
//! The `replay_hash` is pre-computed in the execution engine and passed
//! through unchanged via `ScanResult`. Output construction never recomputes
//! the hash — it threads the engine's value into the envelope so the
//! replay hash in the JSON is the same one the engine validated.
//!
//! ## Identity Status
//!
//! The Agent SDK does not perform PKI bootstrap. All results carry
//! `IdentityStatus::disabled` with the signing backend's ephemeral key ID
//! as the signer identifier (or a hostname-derived fallback when no
//! backend is available).

mod assessor;
mod console;

pub use assessor::build_assessor_package;
pub use console::{print_progress_result, print_results};

use crate::contract_kit::execution_api::ScanResult;
use crate::signing::{self, SigningBackend};
use common::results::{generate_unsigned_signer_id, IdentityStatus};

/// Build the single output envelope (signed AssessorPackage) and return it
/// as pretty-printed JSON.
pub fn build_output(scan_results: &[ScanResult]) -> Result<String, OutputError> {
    let backend = create_signing_backend();
    let identity_status = build_identity_status(backend.as_deref());

    let mut result = build_assessor_package(scan_results, identity_status)?;
    sign_if_available(&mut result.envelope, backend.as_deref());
    serde_json::to_string_pretty(&result).map_err(|e| OutputError::Serialization(e.to_string()))
}

/// Create the signing backend, logging any errors. `None` here is a
/// soft-failure mode — the envelope still serializes, just without a
/// signature.
fn create_signing_backend() -> Option<Box<dyn SigningBackend>> {
    match signing::create_backend() {
        Ok(backend) => Some(backend),
        Err(e) => {
            log::warn!(
                "Failed to create signing backend: {}. Results will be unsigned.",
                e
            );
            None
        }
    }
}

/// Build an `IdentityStatus` for the SDK. Always `disabled` since the SDK
/// does not perform PKI bootstrap; `signer_id` comes from the backend's
/// ephemeral key fingerprint when available, or a hostname-based fallback
/// when not.
fn build_identity_status(backend: Option<&dyn SigningBackend>) -> IdentityStatus {
    let signer_id = backend.and_then(|b| b.signer_id().ok()).unwrap_or_else(|| {
        let hostname = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .unwrap_or_else(|_| "unknown".to_string());
        generate_unsigned_signer_id(&hostname, "sdk")
    });
    IdentityStatus::disabled(signer_id)
}

/// Sign an envelope if a backend is available. Warnings are logged inside
/// `try_sign_envelope`; failure here never aborts the run.
fn sign_if_available(
    envelope: &mut common::results::ResultEnvelope,
    backend: Option<&dyn SigningBackend>,
) {
    if let Some(backend) = backend {
        let _ = signing::try_sign_envelope(envelope, backend);
    }
}

// ============================================================================
// Hash Helpers
// ============================================================================

/// Combine replay hashes from multiple scan results. For a single result,
/// returns the hash directly. For multiple, sorts and hashes the
/// concatenation so the rollup is deterministic across scan ordering.
pub(crate) fn combine_replay_hashes(scan_results: &[ScanResult]) -> Result<String, OutputError> {
    if scan_results.is_empty() {
        return Err(OutputError::Build(
            "At least one scan result is required".to_string(),
        ));
    }

    if scan_results.len() == 1 {
        let result = scan_results
            .first()
            .ok_or_else(|| OutputError::Build("Empty scan results".to_string()))?;
        return Ok(result.replay_hash.clone());
    }

    combine_hashes_sorted(scan_results.iter().map(|r| &r.replay_hash))
}

fn combine_hashes_sorted<'a, I>(hashes: I) -> Result<String, OutputError>
where
    I: Iterator<Item = &'a String>,
{
    use common::results::crypto::sha256_hash;

    let mut sorted: Vec<&String> = hashes.collect();
    sorted.sort();

    let mut combined = Vec::new();
    for hash in sorted {
        combined.extend_from_slice(hash.as_bytes());
        combined.push(b'|');
    }

    let digest = sha256_hash(&combined)
        .map_err(|e| OutputError::Build(format!("Failed to combine hashes: {}", e)))?;

    use std::fmt::Write;
    let hex = digest.iter().fold(String::with_capacity(64), |mut acc, b| {
        let _ = write!(acc, "{:02x}", b);
        acc
    });
    Ok(format!("sha256:{}", hex))
}

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug)]
pub enum OutputError {
    Build(String),
    Serialization(String),
}

impl std::fmt::Display for OutputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputError::Build(msg) => write!(f, "Failed to build output: {}", msg),
            OutputError::Serialization(msg) => write!(f, "Failed to serialize output: {}", msg),
        }
    }
}

impl std::error::Error for OutputError {}

impl From<common::results::ResultError> for OutputError {
    fn from(e: common::results::ResultError) -> Self {
        OutputError::Build(e.to_string())
    }
}

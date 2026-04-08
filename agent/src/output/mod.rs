//! Output generation module
//!
//! Provides builders for different output formats:
//! - Full results with evidence (signed)
//! - Attestations (CUI-free, signed)
//! - Summary (minimal, unsigned)
//! - Assessor package (full reproducibility, signed)
//! - Console (human-readable)
//!
//! ## Hash Architecture
//!
//! All output formats use the pre-computed `replay_hash` from `ScanResult`. The hash
//! is computed ONCE in `ExecutionEngine::execute()` via the `ReplayManifest` and
//! passed through unchanged. This ensures hash consistency across all output formats.
//!
//! ```text
//! ExecutionEngine::execute()
//!     └── ReplayManifest { intent + contract + outcome per CTN }
//!             └── replay_hash = SHA256(canonical manifest)
//!                     └── ScanResult { replay_hash }
//!                             ├── build_attestation()      → uses same hash
//!                             ├── build_full_result()      → uses same hash
//!                             └── build_assessor_package() → uses same hash
//! ```
//!
//! ## Identity Status
//!
//! As of schema v1.2.0, all results include an `identity_status` field.
//! The Agent SDK does not perform PKI bootstrap, so all results use
//! `IdentityStatus::disabled` with the signing backend's ephemeral key ID
//! as the signer identifier.

mod assessor;
mod attestation;
mod console;
mod full;
mod summary;

pub use assessor::build_assessor_package;
pub use attestation::build_attestation;
pub use console::{print_progress_result, print_results};
pub use full::build_full_result;
pub use summary::build_summary;

use crate::config::OutputFormat;
use crate::signing::{self, SigningBackend};
use common::results::{IdentityStatus, generate_unsigned_signer_id};
use crate::contract_kit::execution_api::ScanResult;

/// Build output in the specified format
///
/// Results with envelopes (Full, Attestation, Assessor) are automatically signed.
/// If signing fails, the result is returned unsigned with a warning logged.
pub fn build_output(
    scan_results: &[ScanResult],
    format: OutputFormat,
) -> Result<String, OutputError> {
    // Create signing backend once (reused for identity status and signing)
    let backend = create_signing_backend();

    // Derive identity status from the backend (Agent SDK has no PKI)
    let identity_status = build_identity_status(backend.as_deref());

    let json = match format {
        OutputFormat::Full => {
            let mut result = build_full_result(scan_results, identity_status)?;
            sign_if_available(&mut result.envelope, backend.as_deref());
            serde_json::to_string_pretty(&result)
                .map_err(|e| OutputError::Serialization(e.to_string()))?
        }
        OutputFormat::Attestation => {
            let mut result = build_attestation(scan_results, identity_status)?;
            sign_if_available(&mut result.envelope, backend.as_deref());
            serde_json::to_string_pretty(&result)
                .map_err(|e| OutputError::Serialization(e.to_string()))?
        }
        OutputFormat::Summary => {
            // Summary format has no envelope — not signed, no identity status
            let result = build_summary(scan_results);
            serde_json::to_string_pretty(&result)
                .map_err(|e| OutputError::Serialization(e.to_string()))?
        }
        OutputFormat::Assessor => {
            let mut result = build_assessor_package(scan_results, identity_status)?;
            sign_if_available(&mut result.envelope, backend.as_deref());
            serde_json::to_string_pretty(&result)
                .map_err(|e| OutputError::Serialization(e.to_string()))?
        }
    };
    Ok(json)
}

/// Create the signing backend, logging any errors
///
/// Returns `None` if backend creation fails (graceful degradation).
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

/// Build an `IdentityStatus` for the Agent SDK
///
/// The SDK does not perform PKI bootstrap, so identity is always `disabled`.
/// The signer ID is derived from the signing backend's ephemeral key fingerprint
/// when available, or a hostname-based fallback otherwise.
fn build_identity_status(backend: Option<&dyn SigningBackend>) -> IdentityStatus {
    let signer_id = backend
        .and_then(|b| b.signer_id().ok())
        .unwrap_or_else(|| {
            let hostname = std::env::var("HOSTNAME")
                .or_else(|_| std::env::var("COMPUTERNAME"))
                .unwrap_or_else(|_| "unknown".to_string());
            generate_unsigned_signer_id(&hostname, "sdk")
        });
    IdentityStatus::disabled(signer_id)
}

/// Sign an envelope if a backend is available
///
/// Logs a warning if signing fails but does not return an error.
fn sign_if_available(
    envelope: &mut common::results::ResultEnvelope,
    backend: Option<&dyn SigningBackend>,
) {
    if let Some(backend) = backend {
        if !signing::try_sign_envelope(envelope, backend) {
            // Warning already logged by try_sign_envelope
        }
    }
}

// ============================================================================
// Hash Helpers
// ============================================================================

/// Combine replay hashes from multiple scan results
///
/// For a single scan result, returns the replay hash directly.
/// For multiple scan results, combines them deterministically by
/// sorting and hashing the concatenation.
///
/// ## Returns
///
/// A single `replay_hash` string to pass to result builders.
pub(crate) fn combine_replay_hashes(scan_results: &[ScanResult]) -> Result<String, OutputError> {
    if scan_results.is_empty() {
        return Err(OutputError::Build(
            "At least one scan result is required".to_string(),
        ));
    }

    // Single result: use hash directly
    if scan_results.len() == 1 {
        let result = scan_results
            .first()
            .ok_or_else(|| OutputError::Build("Empty scan results".to_string()))?;
        return Ok(result.replay_hash.clone());
    }

    // Multiple results: combine hashes deterministically
    combine_hashes_sorted(scan_results.iter().map(|r| &r.replay_hash))
}

/// Combine multiple hashes into one (sorted for determinism)
fn combine_hashes_sorted<'a, I>(hashes: I) -> Result<String, OutputError>
where
    I: Iterator<Item = &'a String>,
{
    use common::results::crypto::sha256_hash;

    let mut sorted: Vec<&String> = hashes.collect();
    sorted.sort();

    // Concatenate all hashes with separator
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

/// Errors that can occur during output generation
#[derive(Debug)]
pub enum OutputError {
    /// Failed to build result
    Build(String),
    /// Failed to serialize result
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

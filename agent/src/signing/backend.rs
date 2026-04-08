//! Signing backend trait
//!
//! Defines the interface for cryptographic signing backends.
//! Implementations include TPM (Windows) and software ECDSA P-256.

use common::results::SignatureBlock;
use sha2::{Digest, Sha256};

use super::types::SigningResult;

/// Trait for signing backends
///
/// Implementations must be thread-safe (`Send + Sync`) to support
/// concurrent signing operations.
///
/// # Example
///
/// ```ignore
/// let backend = create_backend()?;
/// let signature = backend.sign_envelope_hash("sha256:abc123...")?;
/// ```
pub trait SigningBackend: Send + Sync {
    /// Sign the envelope replay hash
    ///
    /// Creates a signature over `SHA256(replay_hash)`.
    ///
    /// # Arguments
    ///
    /// * `replay_hash` - The envelope's replay hash (e.g., "sha256:abc...")
    ///
    /// # Returns
    ///
    /// A `SignatureBlock` ready to be attached to the envelope.
    fn sign_envelope_hash(&self, replay_hash: &str) -> SigningResult<SignatureBlock>;

    /// Get the algorithm identifier
    ///
    /// Returns the algorithm string used in `SignatureBlock.algorithm`.
    ///
    /// # Values
    ///
    /// - `"tpm-ecdsa-p256"` - TPM-backed ECDSA
    /// - `"ecdsa-p256"` - Software ECDSA
    fn algorithm(&self) -> &str;

    /// Check if the backend is operational
    ///
    /// Returns `true` if the backend can perform signing operations.
    #[allow(dead_code)]
    fn is_available(&self) -> bool;

    /// Get the signer ID
    ///
    /// Returns the signer identifier derived from the public key.
    /// Format: `"{backend}:sha256:{fingerprint}"`
    #[allow(dead_code)]
    fn signer_id(&self) -> SigningResult<String>;

    /// Get the key ID
    ///
    /// Returns the key identifier for external lookup/audit.
    /// Format: `"{backend}:ephemeral:{key_name}"`
    #[allow(dead_code)]
    fn key_id(&self) -> &str;

    /// Export the public key as Base64
    ///
    /// Returns the public key encoded as Base64 for inclusion
    /// in the signature block.
    #[allow(dead_code)]
    fn export_public_key_base64(&self) -> SigningResult<String>;
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Compute the data to be signed from the envelope replay hash
///
/// Returns `SHA256(replay_hash)` as bytes.
pub fn compute_signed_data(replay_hash: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(replay_hash.as_bytes());

    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Compute a fingerprint from a public key
///
/// Returns the first 16 hex characters of SHA256(public_key_bytes).
pub fn compute_key_fingerprint(public_key_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_key_bytes);
    let result = hasher.finalize();

    // Take first 8 bytes (16 hex chars) for fingerprint - safe because SHA256 always returns 32 bytes
    hex::encode(result.get(..8).unwrap_or(&result[..]))
}

// ============================================================================
// Tests
// ============================================================================

#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_signed_data_deterministic() {
        let replay_hash = "sha256:abc123def456";

        let result1 = compute_signed_data(replay_hash);
        let result2 = compute_signed_data(replay_hash);

        assert_eq!(result1, result2);
        assert_eq!(result1.len(), 32);
    }

    #[test]
    fn test_compute_signed_data_different_inputs() {
        let result1 = compute_signed_data("sha256:aaa");
        let result2 = compute_signed_data("sha256:bbb");

        assert_ne!(result1, result2);
    }

    #[test]
    fn test_compute_key_fingerprint() {
        let key_bytes = b"test public key bytes";
        let fingerprint = compute_key_fingerprint(key_bytes);

        // Should be 16 hex chars (8 bytes)
        assert_eq!(fingerprint.len(), 16);

        // Should be deterministic
        let fingerprint2 = compute_key_fingerprint(key_bytes);
        assert_eq!(fingerprint, fingerprint2);
    }
}

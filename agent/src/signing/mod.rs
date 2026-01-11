//! Signing module
//!
//! Provides cryptographic signing for ESP scan results.
//! Signatures are embedded in the result envelope and cover
//! the `content_hash` and `evidence_hash` fields.
//!
//! ## Architecture
//!
//! ```text
//! ResultEnvelope
//!   ├── content_hash    ─┐
//!   ├── evidence_hash   ─┼─► signed_data = SHA256(content_hash || evidence_hash)
//!   │                    │
//!   └── signature ◄──────┘
//! ```
//!
//! ## Backends
//!
//! - **TPM (Windows)**: Hardware-backed ECDSA P-256 keys
//! - **Software**: Cross-platform ECDSA P-256 (FIPS 140-3 compliant)
//!
//! ## Usage
//!
//! ```ignore
//! use signing::{create_backend, sign_envelope};
//!
//! // Create the best available backend
//! let backend = create_backend()?;
//!
//! // Sign an envelope in place
//! sign_envelope(&mut result.envelope, backend.as_ref())?;
//! ```

mod backend;
mod backends;
mod types;

pub use backend::SigningBackend;
pub use backends::SoftwareBackend;
pub use types::SigningResult;

#[cfg(windows)]
pub use backends::TpmBackend;

use common::results::ResultEnvelope;

/// Create the best available signing backend for the current platform
///
/// On Windows, attempts to use TPM first, falling back to software.
/// On other platforms, uses software backend.
///
/// # Returns
///
/// A boxed signing backend ready for use.
///
/// # Errors
///
/// Returns `SigningError::BackendUnavailable` if no backend can be created.
pub fn create_backend() -> SigningResult<Box<dyn SigningBackend>> {
    #[cfg(windows)]
    {
        if TpmBackend::is_tpm_available() {
            match TpmBackend::new() {
                Ok(backend) => {
                    log::info!("Using TPM signing backend");
                    return Ok(Box::new(backend));
                }
                Err(e) => {
                    log::warn!("TPM unavailable ({}), falling back to software signing", e);
                }
            }
        } else {
            log::info!("TPM not available, using software signing backend");
        }
    }

    #[cfg(not(windows))]
    {
        log::info!("Using software signing backend (non-Windows platform)");
    }

    Ok(Box::new(SoftwareBackend::new()?))
}

/// Sign an envelope in place
///
/// Computes a signature over the envelope's `content_hash` and `evidence_hash`,
/// then sets `envelope.signature` to the resulting `SignatureBlock`.
///
/// # Arguments
///
/// * `envelope` - The result envelope to sign (modified in place)
/// * `backend` - The signing backend to use
///
/// # Example
///
/// ```ignore
/// let backend = create_backend()?;
/// let mut result = build_full_result(&scan_results)?;
/// sign_envelope(&mut result.envelope, backend.as_ref())?;
/// ```
pub fn sign_envelope(
    envelope: &mut ResultEnvelope,
    backend: &dyn SigningBackend,
) -> SigningResult<()> {
    let signature =
        backend.sign_envelope_hashes(&envelope.content_hash, &envelope.evidence_hash)?;
    envelope.signature = Some(signature);
    Ok(())
}

/// Try to sign an envelope, logging a warning on failure
///
/// This is a convenience function for graceful degradation.
/// If signing fails, the envelope remains unsigned and a warning is logged.
///
/// # Arguments
///
/// * `envelope` - The result envelope to sign (modified in place)
/// * `backend` - The signing backend to use
///
/// # Returns
///
/// `true` if signing succeeded, `false` if it failed.
pub fn try_sign_envelope(envelope: &mut ResultEnvelope, backend: &dyn SigningBackend) -> bool {
    match sign_envelope(envelope, backend) {
        Ok(()) => {
            log::debug!("Envelope signed successfully");
            true
        }
        Err(e) => {
            log::warn!("Failed to sign envelope: {}. Result will be unsigned.", e);
            false
        }
    }
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
    use common::results::{AgentInfo, HostInfo};

    fn create_test_envelope() -> ResultEnvelope {
        ResultEnvelope::new(
            AgentInfo::with_defaults("test-agent"),
            HostInfo::new("host-1", "testhost", "linux", "x86_64"),
        )
        .with_content_hash("sha256:8726504ca47412e0d8c0be36a1286a79")
        .with_evidence_hash("sha256:9fbea98350c00a9642fe91431619dd3a")
    }

    #[test]
    fn test_create_backend() {
        let backend = create_backend().expect("Failed to create backend");
        assert!(backend.is_available());
    }

    #[test]
    fn test_sign_envelope() {
        let backend = create_backend().expect("Failed to create backend");
        let mut envelope = create_test_envelope();

        assert!(envelope.signature.is_none());

        sign_envelope(&mut envelope, backend.as_ref()).expect("Signing failed");

        assert!(envelope.signature.is_some());

        let sig = envelope.signature.as_ref().unwrap();
        assert_eq!(sig.covers, vec!["content_hash", "evidence_hash"]);
        assert_eq!(sig.signer_type, "agent");
        assert!(!sig.signature.is_empty());
        assert!(!sig.public_key.is_empty());
    }

    #[test]
    fn test_try_sign_envelope_success() {
        let backend = create_backend().expect("Failed to create backend");
        let mut envelope = create_test_envelope();

        let result = try_sign_envelope(&mut envelope, backend.as_ref());

        assert!(result);
        assert!(envelope.signature.is_some());
    }

    #[test]
    fn test_signature_covers_correct_fields() {
        let backend = create_backend().expect("Failed to create backend");
        let mut envelope = create_test_envelope();

        sign_envelope(&mut envelope, backend.as_ref()).expect("Signing failed");

        let sig = envelope.signature.as_ref().unwrap();
        assert_eq!(sig.covers.len(), 2);
        assert!(sig.covers.contains(&"content_hash".to_string()));
        assert!(sig.covers.contains(&"evidence_hash".to_string()));
    }
}

//! Software signing backend
//!
//! Cross-platform ECDSA P-256 signing using the `p256` crate.
//! Generates ephemeral keys in memory for each backend instance.
//!
//! This backend is FIPS 140-3 compliant when using a FIPS-validated
//! implementation of P-256 ECDSA.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use common::results::SignatureBlock;
use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
use rand_core::OsRng;

use crate::signing::backend::{compute_key_fingerprint, compute_signed_data, SigningBackend};
use crate::signing::types::SigningResult;

/// Software-based ECDSA P-256 signing backend
///
/// Generates an ephemeral signing key on creation. The private key
/// exists only in memory for the lifetime of this struct.
///
/// # Security
///
/// - Keys are generated using OS-provided randomness (`OsRng`)
/// - Private key is never exported or persisted
/// - Suitable for development, testing, and non-TPM environments
///
/// # Example
///
/// ```ignore
/// let backend = SoftwareBackend::new()?;
/// let signature = backend.sign_envelope_hashes(content_hash, evidence_hash)?;
/// ```
pub struct SoftwareBackend {
    /// ECDSA P-256 signing key
    signing_key: SigningKey,

    /// Cached public key bytes (SEC1 uncompressed format)
    public_key_bytes: Vec<u8>,

    /// Key identifier
    key_id: String,

    /// Cached signer ID (derived from public key fingerprint)
    signer_id: String,
}

impl SoftwareBackend {
    /// Create a new software backend with an ephemeral signing key
    ///
    /// Generates a fresh ECDSA P-256 key pair using OS randomness.
    pub fn new() -> SigningResult<Self> {
        // Generate ephemeral signing key
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key: VerifyingKey = *signing_key.verifying_key();

        // Export public key in SEC1 uncompressed format
        let public_key_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();

        // Generate key ID
        let key_id = format!("software:ephemeral:{}", uuid::Uuid::new_v4());

        // Compute signer ID from public key fingerprint
        let fingerprint = compute_key_fingerprint(&public_key_bytes);
        let signer_id = format!("software:sha256:{}", fingerprint);

        Ok(Self {
            signing_key,
            public_key_bytes,
            key_id,
            signer_id,
        })
    }
}

impl SigningBackend for SoftwareBackend {
    fn sign_envelope_hashes(
        &self,
        content_hash: &str,
        evidence_hash: &str,
    ) -> SigningResult<SignatureBlock> {
        // Compute the data to sign: SHA256(content_hash || evidence_hash)
        let signed_data = compute_signed_data(content_hash, evidence_hash);

        // Sign with ECDSA P-256
        let signature: Signature = self.signing_key.sign(&signed_data);

        // Encode signature as Base64 (DER format)
        let signature_bytes = signature.to_der();
        let signature_b64 = BASE64.encode(signature_bytes.as_bytes());

        // Build the signature block
        Ok(SignatureBlock::new(
            &self.signer_id,
            self.algorithm(),
            BASE64.encode(&self.public_key_bytes),
            signature_b64,
            &self.key_id,
            SignatureBlock::standard_covers(),
        ))
    }

    fn algorithm(&self) -> &str {
        "ecdsa-p256"
    }

    fn is_available(&self) -> bool {
        true
    }

    fn signer_id(&self) -> SigningResult<String> {
        Ok(self.signer_id.clone())
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn export_public_key_base64(&self) -> SigningResult<String> {
        Ok(BASE64.encode(&self.public_key_bytes))
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
    use p256::ecdsa::{signature::Verifier, VerifyingKey};

    #[test]
    fn test_software_backend_creation() {
        let backend = SoftwareBackend::new().expect("Failed to create backend");

        assert!(backend.is_available());
        assert_eq!(backend.algorithm(), "ecdsa-p256");
        assert!(backend.key_id().starts_with("software:ephemeral:"));
        assert!(backend.signer_id().unwrap().starts_with("software:sha256:"));
    }

    #[test]
    fn test_software_backend_signing() {
        let backend = SoftwareBackend::new().expect("Failed to create backend");

        let content_hash = "sha256:8726504ca47412e0d8c0be36a1286a79";
        let evidence_hash = "sha256:9fbea98350c00a9642fe91431619dd3a";

        let sig_block = backend
            .sign_envelope_hashes(content_hash, evidence_hash)
            .expect("Signing failed");

        assert_eq!(sig_block.algorithm, "ecdsa-p256");
        assert_eq!(sig_block.signer_type, "agent");
        assert_eq!(sig_block.covers, vec!["content_hash", "evidence_hash"]);
        assert!(!sig_block.signature.is_empty());
        assert!(!sig_block.public_key.is_empty());
    }

    #[test]
    fn test_software_backend_signature_verification() {
        let backend = SoftwareBackend::new().expect("Failed to create backend");

        let content_hash = "sha256:8726504ca47412e0d8c0be36a1286a79";
        let evidence_hash = "sha256:9fbea98350c00a9642fe91431619dd3a";

        let sig_block = backend
            .sign_envelope_hashes(content_hash, evidence_hash)
            .expect("Signing failed");

        // Decode public key
        let public_key_bytes = BASE64
            .decode(&sig_block.public_key)
            .expect("Failed to decode public key");
        let verifying_key =
            VerifyingKey::from_sec1_bytes(&public_key_bytes).expect("Failed to parse public key");

        // Decode signature
        let signature_bytes = BASE64
            .decode(&sig_block.signature)
            .expect("Failed to decode signature");
        let signature = Signature::from_der(&signature_bytes).expect("Failed to parse signature");

        // Recompute signed data
        let signed_data = compute_signed_data(content_hash, evidence_hash);

        // Verify
        assert!(verifying_key.verify(&signed_data, &signature).is_ok());
    }

    #[test]
    fn test_different_backends_produce_different_keys() {
        let backend1 = SoftwareBackend::new().expect("Failed to create backend 1");
        let backend2 = SoftwareBackend::new().expect("Failed to create backend 2");

        assert_ne!(backend1.signer_id, backend2.signer_id);
        assert_ne!(backend1.key_id, backend2.key_id);
    }
}

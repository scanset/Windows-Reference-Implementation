//! Windows TPM signing backend
//!
//! Uses the Platform Crypto Provider to create ephemeral ECDSA P-256 keys
//! in the TPM for signing. Keys are non-exportable and automatically
//! deleted when the backend is dropped.
//!
//! # Safety
//!
//! The TPM handles are wrapped in a Mutex for thread safety.
//! The actual TPM operations are not thread-safe, so concurrent
//! signing operations will be serialized.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use common::results::SignatureBlock;
use std::sync::Mutex;
use uuid::Uuid;

use windows::core::PCWSTR;
use windows::Win32::Security::Cryptography::{
    NCryptCreatePersistedKey, NCryptDeleteKey, NCryptExportKey, NCryptFinalizeKey,
    NCryptFreeObject, NCryptOpenStorageProvider, NCryptSignHash, CERT_KEY_SPEC,
    MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_ECDSA_P256_ALGORITHM, NCRYPT_FLAGS, NCRYPT_HANDLE,
    NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE,
};

use crate::signing::backend::{compute_key_fingerprint, compute_signed_data, SigningBackend};
use crate::signing::types::{SigningError, SigningResult};

/// Inner state for TPM backend (not Send/Sync due to handles)
struct TpmBackendInner {
    provider: NCRYPT_PROV_HANDLE,
    key_handle: NCRYPT_KEY_HANDLE,
    #[allow(dead_code)]
    key_name: String,
    public_key_bytes: Vec<u8>,
    signer_id: String,
}

/// Windows TPM signing backend
///
/// Creates an ephemeral ECDSA P-256 key in the TPM on initialization.
/// The key persists for the lifetime of the backend and is deleted on drop.
///
/// # Security
///
/// - Private key never leaves the TPM
/// - Key is non-exportable
/// - Key is automatically deleted when backend is dropped
///
/// # Thread Safety
///
/// Wrapped in a Mutex to satisfy Send + Sync requirements.
/// Concurrent signing operations will be serialized.
pub struct TpmBackend {
    inner: Mutex<TpmBackendInner>,
    key_id: String,
}

impl TpmBackend {
    /// Create a new TPM backend with an ephemeral signing key
    ///
    /// Opens the Platform Crypto Provider and creates an ECDSA P-256 key.
    pub fn new() -> SigningResult<Self> {
        let mut provider = NCRYPT_PROV_HANDLE::default();

        // Open the Platform Crypto Provider (TPM)
        unsafe {
            NCryptOpenStorageProvider(&mut provider, MS_PLATFORM_CRYPTO_PROVIDER, 0).map_err(
                |e| SigningError::BackendUnavailable(format!("Failed to open TPM provider: {}", e)),
            )?;
        }

        let key_name = format!("ESP_EPHEMERAL_{}", Uuid::new_v4());
        let key_handle = Self::create_ephemeral_key(provider, &key_name)?;

        // Export public key
        let public_key_bytes = Self::export_public_key_raw(key_handle)?;

        // Compute signer ID from public key fingerprint
        let fingerprint = compute_key_fingerprint(&public_key_bytes);
        let signer_id = format!("tpm:sha256:{}", fingerprint);

        let key_id = format!("tpm:ephemeral:{}", key_name);

        Ok(Self {
            inner: Mutex::new(TpmBackendInner {
                provider,
                key_handle,
                key_name,
                public_key_bytes,
                signer_id,
            }),
            key_id,
        })
    }

    /// Check if TPM is available on this system
    pub fn is_tpm_available() -> bool {
        let mut provider = NCRYPT_PROV_HANDLE::default();

        let result =
            unsafe { NCryptOpenStorageProvider(&mut provider, MS_PLATFORM_CRYPTO_PROVIDER, 0) };

        if result.is_ok() {
            unsafe {
                let _ = NCryptFreeObject(NCRYPT_HANDLE(provider.0));
            }
            true
        } else {
            false
        }
    }

    /// Create an ephemeral ECDSA P-256 key in the TPM
    fn create_ephemeral_key(
        provider: NCRYPT_PROV_HANDLE,
        key_name: &str,
    ) -> SigningResult<NCRYPT_KEY_HANDLE> {
        let mut key_handle = NCRYPT_KEY_HANDLE::default();
        let key_name_wide: Vec<u16> = key_name.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            // Create ECDSA P-256 key in TPM
            NCryptCreatePersistedKey(
                provider,
                &mut key_handle,
                NCRYPT_ECDSA_P256_ALGORITHM,
                PCWSTR(key_name_wide.as_ptr()),
                CERT_KEY_SPEC(0),
                NCRYPT_FLAGS(0), // No export allowed - key stays in TPM
            )
            .map_err(|e| {
                SigningError::BackendUnavailable(format!("Failed to create TPM key: {}", e))
            })?;

            // Finalize the key (generates key material in TPM)
            NCryptFinalizeKey(key_handle, NCRYPT_FLAGS(0)).map_err(|e| {
                // Clean up on failure
                let _ = NCryptFreeObject(NCRYPT_HANDLE(key_handle.0));
                SigningError::BackendUnavailable(format!("Failed to finalize TPM key: {}", e))
            })?;
        }

        Ok(key_handle)
    }

    /// Export the public key in Windows ECCPUBLICBLOB format
    fn export_public_key_raw(key_handle: NCRYPT_KEY_HANDLE) -> SigningResult<Vec<u8>> {
        let blob_type: Vec<u16> = "ECCPUBLICBLOB"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            // Get required buffer size
            let mut size: u32 = 0;
            NCryptExportKey(
                key_handle,
                NCRYPT_KEY_HANDLE::default(),
                PCWSTR(blob_type.as_ptr()),
                None,
                None,
                &mut size,
                NCRYPT_FLAGS(0),
            )
            .map_err(|e| SigningError::KeyError(format!("Failed to get public key size: {}", e)))?;

            // Export the key
            let mut buffer = vec![0u8; size as usize];
            NCryptExportKey(
                key_handle,
                NCRYPT_KEY_HANDLE::default(),
                PCWSTR(blob_type.as_ptr()),
                None,
                Some(&mut buffer),
                &mut size,
                NCRYPT_FLAGS(0),
            )
            .map_err(|e| SigningError::KeyError(format!("Failed to export public key: {}", e)))?;

            buffer.truncate(size as usize);
            Ok(buffer)
        }
    }
}

impl SigningBackend for TpmBackend {
    fn sign_envelope_hashes(
        &self,
        content_hash: &str,
        evidence_hash: &str,
    ) -> SigningResult<SignatureBlock> {
        let inner = self
            .inner
            .lock()
            .map_err(|e| SigningError::SigningFailed(format!("Lock poisoned: {}", e)))?;

        // Compute the data to sign: SHA256(content_hash || evidence_hash)
        let signed_data = compute_signed_data(content_hash, evidence_hash);

        // Sign with TPM
        let signature_bytes = unsafe {
            // Get required signature buffer size
            let mut sig_size: u32 = 0;
            NCryptSignHash(
                inner.key_handle,
                None,
                &signed_data,
                None,
                &mut sig_size,
                NCRYPT_FLAGS(0),
            )
            .map_err(|e| {
                SigningError::SigningFailed(format!("Failed to get signature size: {}", e))
            })?;

            // Perform the signing
            let mut sig_buffer = vec![0u8; sig_size as usize];
            NCryptSignHash(
                inner.key_handle,
                None,
                &signed_data,
                Some(&mut sig_buffer),
                &mut sig_size,
                NCRYPT_FLAGS(0),
            )
            .map_err(|e| SigningError::SigningFailed(format!("TPM signing failed: {}", e)))?;

            sig_buffer.truncate(sig_size as usize);
            sig_buffer
        };

        // Build the signature block
        Ok(SignatureBlock::new(
            &inner.signer_id,
            self.algorithm(),
            BASE64.encode(&inner.public_key_bytes),
            BASE64.encode(signature_bytes),
            &self.key_id,
            SignatureBlock::standard_covers(),
        ))
    }

    fn algorithm(&self) -> &str {
        "tpm-ecdsa-p256"
    }

    fn is_available(&self) -> bool {
        self.inner.lock().is_ok()
    }

    fn signer_id(&self) -> SigningResult<String> {
        let inner = self
            .inner
            .lock()
            .map_err(|e| SigningError::SigningFailed(format!("Lock poisoned: {}", e)))?;
        Ok(inner.signer_id.clone())
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn export_public_key_base64(&self) -> SigningResult<String> {
        let inner = self
            .inner
            .lock()
            .map_err(|e| SigningError::SigningFailed(format!("Lock poisoned: {}", e)))?;
        Ok(BASE64.encode(&inner.public_key_bytes))
    }
}

impl Drop for TpmBackendInner {
    fn drop(&mut self) {
        unsafe {
            // Delete the ephemeral key from TPM
            if self.key_handle.0 != 0 {
                let _ = NCryptDeleteKey(self.key_handle, 0);
            }

            // Close the provider
            if self.provider.0 != 0 {
                let _ = NCryptFreeObject(NCRYPT_HANDLE(self.provider.0));
            }
        }
    }
}

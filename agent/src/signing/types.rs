//! Shared types for the signing module

use std::fmt;

/// Errors that can occur during signing operations
#[derive(Debug)]
#[allow(dead_code)]
pub enum SigningError {
    /// Signing backend not available (TPM not present, etc.)
    BackendUnavailable(String),

    /// Signing operation failed
    SigningFailed(String),

    /// Key generation or export failed
    KeyError(String),

    /// Hashing failed
    HashingFailed(String),
}

impl fmt::Display for SigningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BackendUnavailable(msg) => write!(f, "Signing backend unavailable: {}", msg),
            Self::SigningFailed(msg) => write!(f, "Signing failed: {}", msg),
            Self::KeyError(msg) => write!(f, "Key error: {}", msg),
            Self::HashingFailed(msg) => write!(f, "Hashing failed: {}", msg),
        }
    }
}

impl std::error::Error for SigningError {}

/// Result type for signing operations
pub type SigningResult<T> = Result<T, SigningError>;

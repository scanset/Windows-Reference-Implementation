//! Signing backends
//!
//! Platform-specific signing implementations.

pub mod software;

#[cfg(windows)]
pub mod tpm_windows;

pub use software::SoftwareBackend;

#[cfg(windows)]
pub use tpm_windows::TpmBackend;

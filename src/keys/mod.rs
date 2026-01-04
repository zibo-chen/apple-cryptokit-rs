pub mod shared_secret;
/// Key management module
///
/// This module provides management functions for various cryptographic keys, including:
/// - Symmetric keys (SymmetricKey)
/// - Shared secrets (SharedSecret)
/// - Key derivation functions
pub mod symmetric;

// Re-export commonly used types
pub use shared_secret::{SharedSecret, SharedSecretImpl};
pub use symmetric::{SymmetricKey, SymmetricKeySize};

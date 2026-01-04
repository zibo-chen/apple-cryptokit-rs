/// CryptoKit error type
#[derive(Debug, PartialEq, Clone)]
pub enum CryptoKitError {
    /// Invalid key
    InvalidKey,
    /// Invalid nonce
    InvalidNonce,
    /// Invalid input parameter
    InvalidInput(String),
    /// Encryption failed
    EncryptionFailed,
    /// Decryption failed
    DecryptionFailed,
    /// Signature generation failed
    SignatureFailed,
    /// Signature verification failed
    VerificationFailed,
    /// Signing operation failed
    SigningFailed,
    /// Key generation failed
    KeyGenerationFailed,
    /// Nonce generation failed
    NonceGenerationFailed,
    /// Key derivation failed
    DerivationFailed,
    /// Invalid data length
    InvalidLength,
    /// Swift FFI call error
    SwiftCallFailed,
}

impl std::fmt::Display for CryptoKitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoKitError::InvalidKey => write!(f, "Invalid key"),
            CryptoKitError::InvalidNonce => write!(f, "Invalid nonce"),
            CryptoKitError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            CryptoKitError::EncryptionFailed => write!(f, "Encryption failed"),
            CryptoKitError::DecryptionFailed => write!(f, "Decryption failed"),
            CryptoKitError::SignatureFailed => write!(f, "Signature generation failed"),
            CryptoKitError::VerificationFailed => write!(f, "Signature verification failed"),
            CryptoKitError::SigningFailed => write!(f, "Signing operation failed"),
            CryptoKitError::KeyGenerationFailed => write!(f, "Key generation failed"),
            CryptoKitError::NonceGenerationFailed => write!(f, "Nonce generation failed"),
            CryptoKitError::DerivationFailed => write!(f, "Key derivation failed"),
            CryptoKitError::InvalidLength => write!(f, "Invalid data length"),
            CryptoKitError::SwiftCallFailed => write!(f, "Swift FFI call failed"),
        }
    }
}

impl std::error::Error for CryptoKitError {}

/// Result type for this library
pub type Result<T> = std::result::Result<T, CryptoKitError>;

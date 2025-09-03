/// CryptoKit错误类型
#[derive(Debug, PartialEq, Clone)]
pub enum CryptoKitError {
    /// 无效的密钥
    InvalidKey,
    /// 无效的随机数/nonce
    InvalidNonce,
    /// 无效的输入参数
    InvalidInput(String),
    /// 加密失败
    EncryptionFailed,
    /// 解密失败
    DecryptionFailed,
    /// 签名生成失败
    SignatureFailed,
    /// 签名验证失败
    VerificationFailed,
    /// 签名操作失败
    SigningFailed,
    /// 密钥生成失败
    KeyGenerationFailed,
    /// Nonce生成失败
    NonceGenerationFailed,
    /// 密钥派生失败
    DerivationFailed,
    /// 数据长度错误
    InvalidLength,
    /// Swift FFI调用错误
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

/// 库的Result类型
pub type Result<T> = std::result::Result<T, CryptoKitError>;

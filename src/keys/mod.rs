pub mod shared_secret;
/// 密钥管理模块
///
/// 该模块提供各种密码学密钥的管理功能，包括：
/// - 对称密钥 (SymmetricKey)
/// - 共享密钥 (SharedSecret)
/// - 密钥派生功能
pub mod symmetric;

// Re-export commonly used types
pub use shared_secret::{SharedSecret, SharedSecretImpl};
pub use symmetric::{SymmetricKey, SymmetricKeySize};

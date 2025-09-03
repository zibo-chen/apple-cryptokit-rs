//! # 量子安全密码学
//!
//! 本模块提供抗量子攻击的密码学算法，包括：
//! - ML-KEM (Module Lattice Key Encapsulation Mechanism) - 量子安全的密钥封装机制
//! - X-Wing - 结合ML-KEM768和X25519的混合KEM
//! - ML-DSA (Module Lattice Digital Signature Algorithm) - 量子安全的数字签名算法
//!
//! 这些算法能够抵御量子计算机的攻击，为未来的安全需求提供保障。
//!
//! ## 示例
//!
//! ```rust,no_run
//! use apple_cryptokit::quantum::{MLKem768, XWingMLKem768X25519, KeyEncapsulationMechanism, KEMPrivateKey, KEMPublicKey};
//! use apple_cryptokit::Result;
//!
//! # fn main() -> Result<()> {
//! // 使用ML-KEM768进行密钥封装
//! let private_key = MLKem768::generate_private_key()?;
//! let public_key = private_key.public_key();
//!
//! let (ciphertext, shared_secret) = public_key.encapsulate()?;
//! let decapsulated_secret = private_key.decapsulate(&ciphertext)?;
//! assert_eq!(shared_secret, decapsulated_secret);
//!
//! // 使用X-Wing混合KEM
//! let xwing_private = XWingMLKem768X25519::generate_private_key()?;
//! let xwing_public = xwing_private.public_key();
//!
//! let (xwing_ciphertext, xwing_secret) = xwing_public.encapsulate()?;
//! let xwing_decapsulated = xwing_private.decapsulate(&xwing_ciphertext)?;
//! assert_eq!(xwing_secret, xwing_decapsulated);
//! # Ok(())
//! # }
//! ```

pub mod kem;
pub mod signature;

// 重新导出主要类型
pub use kem::{
    KEMPrivateKey, KEMPublicKey, KeyEncapsulationMechanism, MLKem768, MLKem768PrivateKey,
    MLKem768PublicKey, MLKem1024, MLKem1024PrivateKey, MLKem1024PublicKey, XWingMLKem768X25519,
    XWingMLKem768X25519PrivateKey, XWingMLKem768X25519PublicKey,
};

pub use signature::{
    DigitalSignatureAlgorithm, MLDsa65, MLDsa65PrivateKey, MLDsa65PublicKey, MLDsa87,
    MLDsa87PrivateKey, MLDsa87PublicKey, SignaturePrivateKey, SignaturePublicKey,
};

/// 量子安全算法的通用特征
pub trait QuantumSafe {
    /// 算法名称
    fn algorithm_name() -> &'static str;

    /// 安全级别（NIST级别）
    fn security_level() -> u8;

    /// 是否为后量子安全算法
    fn is_post_quantum() -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mlkem768_basic() {
        let private_key = MLKem768::generate_private_key().unwrap();
        let public_key = private_key.public_key();

        let (ciphertext, shared_secret1) = public_key.encapsulate().unwrap();
        let shared_secret2 = private_key.decapsulate(&ciphertext).unwrap();

        assert_eq!(shared_secret1, shared_secret2);
        assert_eq!(shared_secret1.len(), 32); // ML-KEM768 产生32字节的共享密钥
    }

    #[test]
    fn test_mlkem1024_basic() {
        let private_key = MLKem1024::generate_private_key().unwrap();
        let public_key = private_key.public_key();

        let (ciphertext, shared_secret1) = public_key.encapsulate().unwrap();
        let shared_secret2 = private_key.decapsulate(&ciphertext).unwrap();

        assert_eq!(shared_secret1, shared_secret2);
        assert_eq!(shared_secret1.len(), 32); // ML-KEM1024 也产生32字节的共享密钥
    }

    #[test]
    fn test_xwing_basic() {
        let private_key = XWingMLKem768X25519::generate_private_key().unwrap();
        let public_key = private_key.public_key();

        let (ciphertext, shared_secret1) = public_key.encapsulate().unwrap();
        let shared_secret2 = private_key.decapsulate(&ciphertext).unwrap();

        assert_eq!(shared_secret1, shared_secret2);
        assert_eq!(shared_secret1.len(), 32); // X-Wing 产生32字节的共享密钥
    }

    #[test]
    fn test_mldsa65_basic() {
        let private_key = MLDsa65::generate_private_key().unwrap();
        let public_key = private_key.public_key();

        let message = b"Hello, quantum-safe world!";
        let signature = private_key.sign(message).unwrap();

        assert!(public_key.verify(message, &signature).unwrap());

        // 验证错误的消息应该失败
        let wrong_message = b"Wrong message";
        assert!(!public_key.verify(wrong_message, &signature).unwrap());
    }

    #[test]
    fn test_mldsa87_basic() {
        let private_key = MLDsa87::generate_private_key().unwrap();
        let public_key = private_key.public_key();

        let message = b"Hello, ML-DSA87!";
        let signature = private_key.sign(message).unwrap();

        assert!(public_key.verify(message, &signature).unwrap());

        // 验证错误的消息应该失败
        let wrong_message = b"Wrong message";
        assert!(!public_key.verify(wrong_message, &signature).unwrap());
    }
}

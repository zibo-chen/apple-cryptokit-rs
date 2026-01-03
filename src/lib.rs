//! # Apple CryptoKit for Rust
//!
//! 这个crate为Rust提供了Apple CryptoKit的绑定，允许在macOS、iOS等苹果平台上
//! 使用经过优化的密码学算法。
//!
//! ## 功能特性
//!
//! - **哈希算法**: SHA256, SHA384, SHA512等
//! - **消息认证码**: HMAC-SHA256, HMAC-SHA384等
//! - **对称加密**: AES-GCM, ChaCha20-Poly1305
//! - **非对称加密**: 椭圆曲线密码学 (P256, P384, P521, Curve25519)
//! - **量子安全算法**: ML-KEM, X-Wing, ML-DSA (抗量子攻击)
//! - **密钥派生**: HKDF
//! - **密钥管理**: 对称密钥生成和管理
//!
//! ## 示例
//!
//! ### 传统密码学
//!
//! ```rust,no_run
//! use apple_cryptokit::hashing::{sha256_hash, SHA256, HashFunction};
//! use apple_cryptokit::symmetric::aes::{aes_gcm_encrypt, aes_gcm_decrypt};
//!
//! # fn main() -> apple_cryptokit::Result<()> {
//! // 哈希计算
//! let data = b"Hello, World!";
//! let hash = sha256_hash(data);
//! // 或者使用trait
//! let hash = SHA256::hash(data);
//!
//! // 对称加密
//! let key = b"0123456789abcdef0123456789abcdef"; // 32字节密钥
//! let nonce = b"cdef01234567"; // 12字节nonce
//! let plaintext = b"Secret message";
//!
//! let ciphertext = aes_gcm_encrypt(key, nonce, plaintext)?;
//! let decrypted = aes_gcm_decrypt(key, nonce, &ciphertext)?;
//! # Ok(())
//! # }
//! ```
//!
//! ### 量子安全密码学
//!
//! ```rust,no_run
//! use apple_cryptokit::quantum::{MLKem768, XWingMLKem768X25519, MLDsa65};
//! use apple_cryptokit::quantum::{KEMPrivateKey, KEMPublicKey, KeyEncapsulationMechanism};
//! use apple_cryptokit::quantum::{SignaturePrivateKey, SignaturePublicKey, DigitalSignatureAlgorithm};
//!
//! # fn main() -> apple_cryptokit::Result<()> {
//! // ML-KEM768 密钥封装
//! let private_key = MLKem768::generate_private_key()?;
//! let public_key = private_key.public_key();
//!
//! let (ciphertext, shared_secret) = public_key.encapsulate()?;
//! let decapsulated_secret = private_key.decapsulate(&ciphertext)?;
//! assert_eq!(shared_secret, decapsulated_secret);
//!
//! // X-Wing 混合KEM（结合ML-KEM768和X25519）
//! let xwing_private = XWingMLKem768X25519::generate_private_key()?;
//! let xwing_public = xwing_private.public_key();
//!
//! let (xwing_ciphertext, xwing_secret) = xwing_public.encapsulate()?;
//! let xwing_decapsulated = xwing_private.decapsulate(&xwing_ciphertext)?;
//! assert_eq!(xwing_secret, xwing_decapsulated);
//!
//! // ML-DSA65 数字签名
//! let sign_private = MLDsa65::generate_private_key()?;
//! let sign_public = sign_private.public_key();
//!
//! let message = b"Hello, post-quantum world!";
//! let signature = sign_private.sign(message)?;
//! let is_valid = sign_public.verify(message, &signature)?;
//! assert!(is_valid);
//! # Ok(())
//! # }
//! ```

pub mod asymmetric;
pub mod authentication;
pub mod error;
pub mod hashing;
pub mod key_derivation;
pub mod keys;
pub mod quantum;
pub mod symmetric;

// 重新导出常用类型和函数，方便使用
pub use error::{CryptoKitError, Result};

// 重新导出哈希相关
pub use hashing::{
    sha1_hash, sha256_hash, sha384_hash, sha512_hash, HashAlgorithm, HashBuilder, HashFunction,
    Sha256, Sha384, Sha512, SHA1, SHA256, SHA384, SHA512,
};

// 重新导出HMAC相关
pub use authentication::{hmac_sha1, hmac_sha256, hmac_sha384, hmac_sha512, HMAC};

// 重新导出对称加密
pub use symmetric::aes::{
    aes_gcm_decrypt, aes_gcm_decrypt_with_aad, aes_gcm_encrypt, aes_gcm_encrypt_with_aad,
    AESGCMNonce, AESKey, AESKeySize, AesGcm,
};
pub use symmetric::chacha::{
    chacha20poly1305_decrypt, chacha20poly1305_decrypt_with_aad, chacha20poly1305_encrypt,
    chacha20poly1305_encrypt_with_aad, ChaChaKey, ChaChaPoly, ChaChaPolyNonce,
};
pub use symmetric::{AuthenticatedCipher, Cipher};

// 重新导出密钥派生
pub use key_derivation::{
    hkdf_sha256_derive, hkdf_sha384_derive, hkdf_sha512_derive, KeyDerivationFunction,
};

// 重新导出密钥管理
pub use keys::{SymmetricKey, SymmetricKeySize};

// 重新导出量子安全算法
pub use quantum::{
    DigitalSignatureAlgorithm, KEMPrivateKey, KEMPublicKey, KeyEncapsulationMechanism, MLDsa65,
    MLDsa65PrivateKey, MLDsa65PublicKey, MLDsa87, MLDsa87PrivateKey, MLDsa87PublicKey, MLKem1024,
    MLKem1024PrivateKey, MLKem1024PublicKey, MLKem768, MLKem768PrivateKey, MLKem768PublicKey,
    QuantumSafe, SignaturePrivateKey, SignaturePublicKey, XWingMLKem768X25519,
    XWingMLKem768X25519PrivateKey, XWingMLKem768X25519PublicKey,
};

// @deprecated 使用 `hashing` 模块中的函数代替
extern "C" {
    #[link_name = "md5_hash"]
    fn swift_md5_hash(data: *const u8, length: i32, out_hash: *mut u8);
}

// @deprecated 使用 `hashing` 模块中的函数代替
// MD5哈希计算（不安全，仅用于兼容性）
pub fn md5_hash(data: &[u8]) -> Vec<u8> {
    unsafe {
        let mut output_hash = [0u8; 16];
        swift_md5_hash(data.as_ptr(), data.len() as i32, output_hash.as_mut_ptr());
        output_hash.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_basic() {
        let input = b"abc";
        let expected: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        let hash = sha256_hash(input);
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha256_trait() {
        let input = b"abc";
        let expected: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        let hash = SHA256::hash(input);
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha256_streaming() {
        let mut hasher = Sha256::new();
        hasher.update(b"a");
        hasher.update(b"b");
        hasher.update(b"c");
        let hash = hasher.finalize();

        let expected: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_aes_gcm_roundtrip() {
        let key = b"0123456789abcdef0123456789abcdef"; // 32-byte key
        let nonce = b"cdef01234567"; // 12-byte nonce
        let plaintext = b"Hello, World!";

        // 测试加密解密往返
        let ciphertext = aes_gcm_encrypt(key, nonce, plaintext).unwrap();
        assert!(ciphertext.len() > plaintext.len()); // 应该因为tag而更长

        let decrypted = aes_gcm_decrypt(key, nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha20poly1305_roundtrip() {
        let key = b"0123456789abcdef0123456789abcdef"; // 32-byte key
        let nonce = b"cdef01234567"; // 12-byte nonce
        let plaintext = b"Hello, ChaCha20Poly1305!";

        // 测试加密解密往返
        let ciphertext = chacha20poly1305_encrypt(key, nonce, plaintext).unwrap();
        assert!(ciphertext.len() > plaintext.len()); // 应该因为tag而更长

        let decrypted = chacha20poly1305_decrypt(key, nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_hmac_sha256() {
        let key = b"key";
        let message = b"message";
        let result = hmac_sha256(key, message).unwrap();
        assert_eq!(result.len(), 32); // SHA256输出32字节

        // 测试已知向量
        let key = b"Jefe";
        let message = b"what do ya want for nothing?";
        let result = hmac_sha256(key, message).unwrap();
        let expected: [u8; 32] = [
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
            0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
            0x64, 0xec, 0x38, 0x43,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_md5_compatibility() {
        let input = b"hello";
        let hash = md5_hash(input);
        // 预期的MD5哈希值 "hello"
        let expected: [u8; 16] = [
            0x5d, 0x41, 0x40, 0x2a, 0xbc, 0x4b, 0x2a, 0x76, 0xb9, 0x71, 0x9d, 0x91, 0x10, 0x17,
            0xc5, 0x92,
        ];
        assert_eq!(hash, expected);
    }
}

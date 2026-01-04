//! # Apple CryptoKit for Rust
//!
//! This crate provides Rust bindings to Apple's CryptoKit, enabling the use of optimized
//! cryptographic algorithms on macOS, iOS, and other Apple platforms.
//!
//! ## Features
//!
//! - **Hash Algorithms**: SHA256, SHA384, SHA512, etc.
//! - **Message Authentication Codes**: HMAC-SHA256, HMAC-SHA384, etc.
//! - **Symmetric Encryption**: AES-GCM, ChaCha20-Poly1305
//! - **Asymmetric Encryption**: Elliptic Curve Cryptography (P256, P384, P521, Curve25519)
//! - **Quantum-Safe Algorithms**: ML-KEM, X-Wing, ML-DSA (quantum-resistant)
//! - **Key Derivation**: HKDF
//! - **Key Management**: Symmetric key generation and management
//!
//! ## Examples
//!
//! ### Traditional Cryptography
//!
//! ```rust,no_run
//! use apple_cryptokit::hashing::{sha256_hash, SHA256, HashFunction};
//! use apple_cryptokit::symmetric::aes::{aes_gcm_encrypt, aes_gcm_decrypt};
//!
//! # fn main() -> apple_cryptokit::Result<()> {
//! // Hash computation
//! let data = b"Hello, World!";
//! let hash = sha256_hash(data);
//! // Or use the trait
//! let hash = SHA256::hash(data);
//!
//! // Symmetric encryption
//! let key = b"0123456789abcdef0123456789abcdef"; // 32-byte key
//! let nonce = b"cdef01234567"; // 12-byte nonce
//! let plaintext = b"Secret message";
//!
//! let ciphertext = aes_gcm_encrypt(key, nonce, plaintext)?;
//! let decrypted = aes_gcm_decrypt(key, nonce, &ciphertext)?;
//! # Ok(())
//! # }
//! ```
//!
//! ### Quantum-Safe Cryptography
//!
//! ```rust,no_run
//! use apple_cryptokit::quantum::{MLKem768, XWingMLKem768X25519, MLDsa65};
//! use apple_cryptokit::quantum::{KEMPrivateKey, KEMPublicKey, KeyEncapsulationMechanism};
//! use apple_cryptokit::quantum::{SignaturePrivateKey, SignaturePublicKey, DigitalSignatureAlgorithm};
//!
//! # fn main() -> apple_cryptokit::Result<()> {
//! // ML-KEM768 key encapsulation
//! let private_key = MLKem768::generate_private_key()?;
//! let public_key = private_key.public_key();
//!
//! let (ciphertext, shared_secret) = public_key.encapsulate()?;
//! let decapsulated_secret = private_key.decapsulate(&ciphertext)?;
//! assert_eq!(shared_secret, decapsulated_secret);
//!
//! // X-Wing hybrid KEM (combining ML-KEM768 and X25519)
//! let xwing_private = XWingMLKem768X25519::generate_private_key()?;
//! let xwing_public = xwing_private.public_key();
//!
//! let (xwing_ciphertext, xwing_secret) = xwing_public.encapsulate()?;
//! let xwing_decapsulated = xwing_private.decapsulate(&xwing_ciphertext)?;
//! assert_eq!(xwing_secret, xwing_decapsulated);
//!
//! // ML-DSA65 digital signature
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

// Re-export commonly used types and functions for convenience
pub use error::{CryptoKitError, Result};

// Re-export hash-related items
pub use hashing::{
    HashAlgorithm, HashBuilder, HashFunction, SHA1, SHA256, SHA384, SHA512, Sha256, Sha384, Sha512,
    sha1_hash, sha256_hash, sha384_hash, sha512_hash,
};

// Re-export HMAC-related items
pub use authentication::{HMAC, hmac_sha1, hmac_sha256, hmac_sha384, hmac_sha512};

// Re-export symmetric encryption items
pub use symmetric::aes::{
    AESGCMNonce, AESKey, AESKeySize, AesGcm, aes_gcm_decrypt, aes_gcm_decrypt_with_aad,
    aes_gcm_encrypt, aes_gcm_encrypt_with_aad,
};
pub use symmetric::chacha::{
    ChaChaKey, ChaChaPoly, ChaChaPolyNonce, chacha20poly1305_decrypt,
    chacha20poly1305_decrypt_with_aad, chacha20poly1305_encrypt, chacha20poly1305_encrypt_with_aad,
};
pub use symmetric::{AuthenticatedCipher, Cipher};

// Re-export key derivation items
pub use key_derivation::{
    KeyDerivationFunction, hkdf_sha256_derive, hkdf_sha384_derive, hkdf_sha512_derive,
};

// Re-export key management items
pub use keys::{SymmetricKey, SymmetricKeySize};

// Re-export quantum-safe algorithm items
pub use quantum::{
    DigitalSignatureAlgorithm, KEMPrivateKey, KEMPublicKey, KeyEncapsulationMechanism, MLDsa65,
    MLDsa65PrivateKey, MLDsa65PublicKey, MLDsa87, MLDsa87PrivateKey, MLDsa87PublicKey, MLKem768,
    MLKem768PrivateKey, MLKem768PublicKey, MLKem1024, MLKem1024PrivateKey, MLKem1024PublicKey,
    QuantumSafe, SignaturePrivateKey, SignaturePublicKey, XWingMLKem768X25519,
    XWingMLKem768X25519PrivateKey, XWingMLKem768X25519PublicKey,
};

// @deprecated Use functions from the `hashing` module instead
unsafe extern "C" {
    #[link_name = "md5_hash"]
    fn swift_md5_hash(data: *const u8, length: i32, out_hash: *mut u8);
}

// @deprecated Use functions from the `hashing` module instead
// MD5 hash computation (insecure, for compatibility only)
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

        // Test encryption and decryption round-trip
        let ciphertext = aes_gcm_encrypt(key, nonce, plaintext).unwrap();
        assert!(ciphertext.len() > plaintext.len()); // Should be longer due to tag

        let decrypted = aes_gcm_decrypt(key, nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha20poly1305_roundtrip() {
        let key = b"0123456789abcdef0123456789abcdef"; // 32-byte key
        let nonce = b"cdef01234567"; // 12-byte nonce  
        let plaintext = b"Hello, ChaCha20Poly1305!";

        // Test encryption and decryption round-trip
        let ciphertext = chacha20poly1305_encrypt(key, nonce, plaintext).unwrap();
        assert!(ciphertext.len() > plaintext.len()); // Should be longer due to tag

        let decrypted = chacha20poly1305_decrypt(key, nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_hmac_sha256() {
        let key = b"key";
        let message = b"message";
        let result = hmac_sha256(key, message).unwrap();
        assert_eq!(result.len(), 32); // SHA256 outputs 32 bytes

        // Test known vector
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
        // Expected MD5 hash for "hello"
        let expected: [u8; 16] = [
            0x5d, 0x41, 0x40, 0x2a, 0xbc, 0x4b, 0x2a, 0x76, 0xb9, 0x71, 0x9d, 0x91, 0x10, 0x17,
            0xc5, 0x92,
        ];
        assert_eq!(hash, expected);
    }
}

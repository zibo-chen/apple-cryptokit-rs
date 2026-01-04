//! # Quantum-Safe Cryptography
//!
//! This module provides quantum-resistant cryptographic algorithms, including:
//! - ML-KEM (Module Lattice Key Encapsulation Mechanism) - Quantum-safe key encapsulation mechanism
//! - X-Wing - Hybrid KEM combining ML-KEM768 and X25519
//! - ML-DSA (Module Lattice Digital Signature Algorithm) - Quantum-safe digital signature algorithm
//!
//! These algorithms can withstand attacks from quantum computers, providing security for future needs.
//!
//! ## Example
//!
//! ```rust,no_run
//! use apple_cryptokit::quantum::{MLKem768, XWingMLKem768X25519, KeyEncapsulationMechanism, KEMPrivateKey, KEMPublicKey};
//! use apple_cryptokit::Result;
//!
//! # fn main() -> Result<()> {
//! // Use ML-KEM768 for key encapsulation
//! let private_key = MLKem768::generate_private_key()?;
//! let public_key = private_key.public_key();
//!
//! let (ciphertext, shared_secret) = public_key.encapsulate()?;
//! let decapsulated_secret = private_key.decapsulate(&ciphertext)?;
//! assert_eq!(shared_secret, decapsulated_secret);
//!
//! // Use X-Wing hybrid KEM
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

// Re-export main types
pub use kem::{
    KEMPrivateKey, KEMPublicKey, KeyEncapsulationMechanism, MLKem1024, MLKem1024PrivateKey,
    MLKem1024PublicKey, MLKem768, MLKem768PrivateKey, MLKem768PublicKey, XWingMLKem768X25519,
    XWingMLKem768X25519PrivateKey, XWingMLKem768X25519PublicKey,
};

pub use signature::{
    DigitalSignatureAlgorithm, MLDsa65, MLDsa65PrivateKey, MLDsa65PublicKey, MLDsa87,
    MLDsa87PrivateKey, MLDsa87PublicKey, SignaturePrivateKey, SignaturePublicKey,
};

/// Generic trait for quantum-safe algorithms
pub trait QuantumSafe {
    /// Algorithm name
    fn algorithm_name() -> &'static str;

    /// Security level (NIST level)
    fn security_level() -> u8;

    /// Whether this is a post-quantum safe algorithm
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
        assert_eq!(shared_secret1.len(), 32); // ML-KEM768 produces 32-byte shared secret
    }

    #[test]
    fn test_mlkem1024_basic() {
        let private_key = MLKem1024::generate_private_key().unwrap();
        let public_key = private_key.public_key();

        let (ciphertext, shared_secret1) = public_key.encapsulate().unwrap();
        let shared_secret2 = private_key.decapsulate(&ciphertext).unwrap();

        assert_eq!(shared_secret1, shared_secret2);
        assert_eq!(shared_secret1.len(), 32); // ML-KEM1024 also produces 32-byte shared secret
    }

    #[test]
    fn test_xwing_basic() {
        let private_key = XWingMLKem768X25519::generate_private_key().unwrap();
        let public_key = private_key.public_key();

        let (ciphertext, shared_secret1) = public_key.encapsulate().unwrap();
        let shared_secret2 = private_key.decapsulate(&ciphertext).unwrap();

        assert_eq!(shared_secret1, shared_secret2);
        assert_eq!(shared_secret1.len(), 32); // X-Wing produces 32-byte shared secret
    }

    #[test]
    fn test_mldsa65_basic() {
        let private_key = MLDsa65::generate_private_key().unwrap();
        let public_key = private_key.public_key();

        let message = b"Hello, quantum-safe world!";
        let signature = private_key.sign(message).unwrap();

        assert!(public_key.verify(message, &signature).unwrap());

        // Verifying wrong message should fail
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

        // Verifying wrong message should fail
        let wrong_message = b"Wrong message";
        assert!(!public_key.verify(wrong_message, &signature).unwrap());
    }
}

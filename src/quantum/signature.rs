//! # Quantum-Safe Digital Signature Algorithms
//!
//! This module implements quantum-resistant digital signature algorithms, including:
//! - ML-DSA65: Lattice-based digital signature algorithm, security level 2
//! - ML-DSA87: Lattice-based digital signature algorithm, security level 3
//!
//! These algorithms provide quantum-safe digital signature capabilities.

use crate::quantum::QuantumSafe;
use crate::{CryptoKitError, Result};

/// Generic trait for digital signature algorithms
pub trait DigitalSignatureAlgorithm: QuantumSafe {
    type PrivateKey: SignaturePrivateKey;
    type PublicKey: SignaturePublicKey;

    /// Generate a new private key
    fn generate_private_key() -> Result<Self::PrivateKey>;
}

/// Generic trait for signature private keys
pub trait SignaturePrivateKey {
    type PublicKey: SignaturePublicKey;
    type Signature;

    /// Get the corresponding public key
    fn public_key(&self) -> Self::PublicKey;

    /// Sign a message
    fn sign(&self, message: &[u8]) -> Result<Self::Signature>;

    /// Serialize the private key to a byte array
    fn to_bytes(&self) -> Vec<u8>;

    /// Deserialize a private key from a byte array
    fn from_bytes(bytes: &[u8]) -> Result<Self>
    where
        Self: Sized;
}

/// Generic trait for signature public keys
pub trait SignaturePublicKey {
    type Signature;

    /// Verify a signature
    fn verify(&self, message: &[u8], signature: &Self::Signature) -> Result<bool>;

    /// Serialize the public key to a byte array
    fn to_bytes(&self) -> Vec<u8>;

    /// Deserialize a public key from a byte array
    fn from_bytes(bytes: &[u8]) -> Result<Self>
    where
        Self: Sized;
}

// ML-DSA65 Implementation

/// ML-DSA65 algorithm (Security Level 2)
pub struct MLDsa65;

impl QuantumSafe for MLDsa65 {
    fn algorithm_name() -> &'static str {
        "ML-DSA-65"
    }

    fn security_level() -> u8 {
        2 // NIST security level 2
    }
}

impl DigitalSignatureAlgorithm for MLDsa65 {
    type PrivateKey = MLDsa65PrivateKey;
    type PublicKey = MLDsa65PublicKey;

    fn generate_private_key() -> Result<Self::PrivateKey> {
        unsafe {
            let mut private_key_bytes = vec![0u8; MLDSA65_PRIVATE_KEY_SIZE];
            let mut public_key_bytes = vec![0u8; MLDSA65_PUBLIC_KEY_SIZE];

            let result = swift_mldsa65_generate_keypair(
                private_key_bytes.as_mut_ptr(),
                public_key_bytes.as_mut_ptr(),
            );

            if result != 0 {
                return Err(CryptoKitError::KeyGenerationFailed);
            }

            Ok(MLDsa65PrivateKey {
                bytes: private_key_bytes,
                public_key: MLDsa65PublicKey {
                    bytes: public_key_bytes,
                },
            })
        }
    }
}

/// ML-DSA65 private key
pub struct MLDsa65PrivateKey {
    bytes: Vec<u8>,
    public_key: MLDsa65PublicKey,
}

impl SignaturePrivateKey for MLDsa65PrivateKey {
    type PublicKey = MLDsa65PublicKey;
    type Signature = Vec<u8>;

    fn public_key(&self) -> Self::PublicKey {
        self.public_key.clone()
    }

    fn sign(&self, message: &[u8]) -> Result<Self::Signature> {
        unsafe {
            let mut signature = vec![0u8; MLDSA65_SIGNATURE_SIZE];
            let mut signature_len = MLDSA65_SIGNATURE_SIZE;

            let result = swift_mldsa65_sign(
                self.bytes.as_ptr(),
                message.as_ptr(),
                message.len(),
                signature.as_mut_ptr(),
                &mut signature_len,
            );

            if result != 0 {
                return Err(CryptoKitError::SigningFailed);
            }

            signature.truncate(signature_len);
            Ok(signature)
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != MLDSA65_PRIVATE_KEY_SIZE {
            return Err(CryptoKitError::InvalidInput(
                "Invalid private key length".to_string(),
            ));
        }

        // Derive public key from private key
        unsafe {
            let mut public_key_bytes = vec![0u8; MLDSA65_PUBLIC_KEY_SIZE];

            let result =
                swift_mldsa65_derive_public_key(bytes.as_ptr(), public_key_bytes.as_mut_ptr());

            if result != 0 {
                return Err(CryptoKitError::InvalidInput(
                    "Invalid private key".to_string(),
                ));
            }

            Ok(MLDsa65PrivateKey {
                bytes: bytes.to_vec(),
                public_key: MLDsa65PublicKey {
                    bytes: public_key_bytes,
                },
            })
        }
    }
}

/// ML-DSA65 public key
#[derive(Clone)]
pub struct MLDsa65PublicKey {
    bytes: Vec<u8>,
}

impl SignaturePublicKey for MLDsa65PublicKey {
    type Signature = Vec<u8>;

    fn verify(&self, message: &[u8], signature: &Self::Signature) -> Result<bool> {
        unsafe {
            let result = swift_mldsa65_verify(
                self.bytes.as_ptr(),
                message.as_ptr(),
                message.len(),
                signature.as_ptr(),
                signature.len(),
            );

            match result {
                0 => Ok(true),
                1 => Ok(false),
                _ => Err(CryptoKitError::VerificationFailed),
            }
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != MLDSA65_PUBLIC_KEY_SIZE {
            return Err(CryptoKitError::InvalidInput(
                "Invalid public key length".to_string(),
            ));
        }

        Ok(MLDsa65PublicKey {
            bytes: bytes.to_vec(),
        })
    }
}

// ML-DSA87 Implementation

/// ML-DSA87 algorithm (Security Level 3)
pub struct MLDsa87;

impl QuantumSafe for MLDsa87 {
    fn algorithm_name() -> &'static str {
        "ML-DSA-87"
    }

    fn security_level() -> u8 {
        3 // NIST security level 3
    }
}

impl DigitalSignatureAlgorithm for MLDsa87 {
    type PrivateKey = MLDsa87PrivateKey;
    type PublicKey = MLDsa87PublicKey;

    fn generate_private_key() -> Result<Self::PrivateKey> {
        unsafe {
            let mut private_key_bytes = vec![0u8; MLDSA87_PRIVATE_KEY_SIZE];
            let mut public_key_bytes = vec![0u8; MLDSA87_PUBLIC_KEY_SIZE];

            let result = swift_mldsa87_generate_keypair(
                private_key_bytes.as_mut_ptr(),
                public_key_bytes.as_mut_ptr(),
            );

            if result != 0 {
                return Err(CryptoKitError::KeyGenerationFailed);
            }

            Ok(MLDsa87PrivateKey {
                bytes: private_key_bytes,
                public_key: MLDsa87PublicKey {
                    bytes: public_key_bytes,
                },
            })
        }
    }
}

/// ML-DSA87 private key
pub struct MLDsa87PrivateKey {
    bytes: Vec<u8>,
    public_key: MLDsa87PublicKey,
}

impl SignaturePrivateKey for MLDsa87PrivateKey {
    type PublicKey = MLDsa87PublicKey;
    type Signature = Vec<u8>;

    fn public_key(&self) -> Self::PublicKey {
        self.public_key.clone()
    }

    fn sign(&self, message: &[u8]) -> Result<Self::Signature> {
        unsafe {
            let mut signature = vec![0u8; MLDSA87_SIGNATURE_SIZE];
            let mut signature_len = MLDSA87_SIGNATURE_SIZE;

            let result = swift_mldsa87_sign(
                self.bytes.as_ptr(),
                message.as_ptr(),
                message.len(),
                signature.as_mut_ptr(),
                &mut signature_len,
            );

            if result != 0 {
                return Err(CryptoKitError::SigningFailed);
            }

            signature.truncate(signature_len);
            Ok(signature)
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != MLDSA87_PRIVATE_KEY_SIZE {
            return Err(CryptoKitError::InvalidInput(
                "Invalid private key length".to_string(),
            ));
        }

        // Derive public key from private key
        unsafe {
            let mut public_key_bytes = vec![0u8; MLDSA87_PUBLIC_KEY_SIZE];

            let result =
                swift_mldsa87_derive_public_key(bytes.as_ptr(), public_key_bytes.as_mut_ptr());

            if result != 0 {
                return Err(CryptoKitError::InvalidInput(
                    "Invalid private key".to_string(),
                ));
            }

            Ok(MLDsa87PrivateKey {
                bytes: bytes.to_vec(),
                public_key: MLDsa87PublicKey {
                    bytes: public_key_bytes,
                },
            })
        }
    }
}

/// ML-DSA87 public key
#[derive(Clone)]
pub struct MLDsa87PublicKey {
    bytes: Vec<u8>,
}

impl SignaturePublicKey for MLDsa87PublicKey {
    type Signature = Vec<u8>;

    fn verify(&self, message: &[u8], signature: &Self::Signature) -> Result<bool> {
        unsafe {
            let result = swift_mldsa87_verify(
                self.bytes.as_ptr(),
                message.as_ptr(),
                message.len(),
                signature.as_ptr(),
                signature.len(),
            );

            match result {
                0 => Ok(true),
                1 => Ok(false),
                _ => Err(CryptoKitError::VerificationFailed),
            }
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != MLDSA87_PUBLIC_KEY_SIZE {
            return Err(CryptoKitError::InvalidInput(
                "Invalid public key length".to_string(),
            ));
        }

        Ok(MLDsa87PublicKey {
            bytes: bytes.to_vec(),
        })
    }
}

// Constant definitions - According to NIST standard
const MLDSA65_PUBLIC_KEY_SIZE: usize = 1952;
const MLDSA65_PRIVATE_KEY_SIZE: usize = 4032;
const MLDSA65_SIGNATURE_SIZE: usize = 3309; // Maximum signature length

const MLDSA87_PUBLIC_KEY_SIZE: usize = 2592;
const MLDSA87_PRIVATE_KEY_SIZE: usize = 4896;
const MLDSA87_SIGNATURE_SIZE: usize = 4627; // Maximum signature length

// Swift FFI declarations
extern "C" {
    // ML-DSA65
    fn swift_mldsa65_generate_keypair(private_key: *mut u8, public_key: *mut u8) -> i32;
    fn swift_mldsa65_sign(
        private_key: *const u8,
        message: *const u8,
        message_len: usize,
        signature: *mut u8,
        signature_len: *mut usize,
    ) -> i32;
    fn swift_mldsa65_verify(
        public_key: *const u8,
        message: *const u8,
        message_len: usize,
        signature: *const u8,
        signature_len: usize,
    ) -> i32;
    fn swift_mldsa65_derive_public_key(private_key: *const u8, public_key: *mut u8) -> i32;

    // ML-DSA87
    fn swift_mldsa87_generate_keypair(private_key: *mut u8, public_key: *mut u8) -> i32;
    fn swift_mldsa87_sign(
        private_key: *const u8,
        message: *const u8,
        message_len: usize,
        signature: *mut u8,
        signature_len: *mut usize,
    ) -> i32;
    fn swift_mldsa87_verify(
        public_key: *const u8,
        message: *const u8,
        message_len: usize,
        signature: *const u8,
        signature_len: usize,
    ) -> i32;
    fn swift_mldsa87_derive_public_key(private_key: *const u8, public_key: *mut u8) -> i32;
}

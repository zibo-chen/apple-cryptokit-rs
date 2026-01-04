//! # Key Encapsulation Mechanisms
//!
//! This module implements quantum-resistant key encapsulation mechanisms, including:
//! - ML-KEM768: Lattice-based key encapsulation mechanism, security level 1
//! - ML-KEM1024: Lattice-based key encapsulation mechanism, security level 3
//! - X-Wing: Hybrid KEM combining ML-KEM768 and X25519
//!
//! These algorithms provide quantum-safe key exchange capabilities.

use crate::quantum::QuantumSafe;
use crate::{CryptoKitError, Result};

/// Generic trait for key encapsulation mechanisms
pub trait KeyEncapsulationMechanism: QuantumSafe {
    type PrivateKey: KEMPrivateKey;
    type PublicKey: KEMPublicKey;

    /// Generate a new private key
    fn generate_private_key() -> Result<Self::PrivateKey>;
}

/// Generic trait for KEM private keys
pub trait KEMPrivateKey {
    type PublicKey: KEMPublicKey;
    type SharedSecret;

    /// Get the corresponding public key
    fn public_key(&self) -> Self::PublicKey;

    /// Decapsulate ciphertext to obtain the shared secret
    fn decapsulate(&self, ciphertext: &[u8]) -> Result<Self::SharedSecret>;

    /// Serialize the private key to a byte array
    fn to_bytes(&self) -> Vec<u8>;

    /// Deserialize a private key from a byte array
    fn from_bytes(bytes: &[u8]) -> Result<Self>
    where
        Self: Sized;
}

/// Generic trait for KEM public keys
pub trait KEMPublicKey {
    type SharedSecret;

    /// Encapsulate to generate ciphertext and shared secret
    fn encapsulate(&self) -> Result<(Vec<u8>, Self::SharedSecret)>;

    /// Serialize the public key to a byte array
    fn to_bytes(&self) -> Vec<u8>;

    /// Deserialize a public key from a byte array
    fn from_bytes(bytes: &[u8]) -> Result<Self>
    where
        Self: Sized;
}

// ML-KEM768 Implementation

/// ML-KEM768 algorithm (Security Level 1)
pub struct MLKem768;

impl QuantumSafe for MLKem768 {
    fn algorithm_name() -> &'static str {
        "ML-KEM-768"
    }

    fn security_level() -> u8 {
        1 // NIST security level 1
    }
}

impl KeyEncapsulationMechanism for MLKem768 {
    type PrivateKey = MLKem768PrivateKey;
    type PublicKey = MLKem768PublicKey;

    fn generate_private_key() -> Result<Self::PrivateKey> {
        unsafe {
            let mut private_key_bytes = vec![0u8; MLKEM768_PRIVATE_KEY_SIZE];
            let mut public_key_bytes = vec![0u8; MLKEM768_PUBLIC_KEY_SIZE];

            let result = swift_mlkem768_generate_keypair(
                private_key_bytes.as_mut_ptr(),
                public_key_bytes.as_mut_ptr(),
            );

            if result != 0 {
                return Err(CryptoKitError::KeyGenerationFailed);
            }

            Ok(MLKem768PrivateKey {
                bytes: private_key_bytes,
                public_key: MLKem768PublicKey {
                    bytes: public_key_bytes,
                },
            })
        }
    }
}

/// ML-KEM768 private key
pub struct MLKem768PrivateKey {
    bytes: Vec<u8>,
    public_key: MLKem768PublicKey,
}

impl KEMPrivateKey for MLKem768PrivateKey {
    type PublicKey = MLKem768PublicKey;
    type SharedSecret = [u8; 32];

    fn public_key(&self) -> Self::PublicKey {
        self.public_key.clone()
    }

    fn decapsulate(&self, ciphertext: &[u8]) -> Result<Self::SharedSecret> {
        if ciphertext.len() != MLKEM768_CIPHERTEXT_SIZE {
            return Err(CryptoKitError::InvalidInput(
                "Invalid ciphertext length".to_string(),
            ));
        }

        unsafe {
            let mut shared_secret = [0u8; 32];

            let result = swift_mlkem768_decapsulate(
                self.bytes.as_ptr(),
                ciphertext.as_ptr(),
                shared_secret.as_mut_ptr(),
            );

            if result != 0 {
                return Err(CryptoKitError::DecryptionFailed);
            }

            Ok(shared_secret)
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != MLKEM768_PRIVATE_KEY_SIZE {
            return Err(CryptoKitError::InvalidInput(
                "Invalid private key length".to_string(),
            ));
        }

        // Derive public key from private key
        unsafe {
            let mut public_key_bytes = vec![0u8; MLKEM768_PUBLIC_KEY_SIZE];

            let result =
                swift_mlkem768_derive_public_key(bytes.as_ptr(), public_key_bytes.as_mut_ptr());

            if result != 0 {
                return Err(CryptoKitError::InvalidInput(
                    "Invalid private key".to_string(),
                ));
            }

            Ok(MLKem768PrivateKey {
                bytes: bytes.to_vec(),
                public_key: MLKem768PublicKey {
                    bytes: public_key_bytes,
                },
            })
        }
    }
}

/// ML-KEM768 public key
#[derive(Clone)]
pub struct MLKem768PublicKey {
    bytes: Vec<u8>,
}

impl KEMPublicKey for MLKem768PublicKey {
    type SharedSecret = [u8; 32];

    fn encapsulate(&self) -> Result<(Vec<u8>, Self::SharedSecret)> {
        unsafe {
            let mut ciphertext = vec![0u8; MLKEM768_CIPHERTEXT_SIZE];
            let mut shared_secret = [0u8; 32];

            let result = swift_mlkem768_encapsulate(
                self.bytes.as_ptr(),
                ciphertext.as_mut_ptr(),
                shared_secret.as_mut_ptr(),
            );

            if result != 0 {
                return Err(CryptoKitError::EncryptionFailed);
            }

            Ok((ciphertext, shared_secret))
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != MLKEM768_PUBLIC_KEY_SIZE {
            return Err(CryptoKitError::InvalidInput(
                "Invalid public key length".to_string(),
            ));
        }

        Ok(MLKem768PublicKey {
            bytes: bytes.to_vec(),
        })
    }
}

// ML-KEM1024 Implementation

/// ML-KEM1024 algorithm (Security Level 3)
pub struct MLKem1024;

impl QuantumSafe for MLKem1024 {
    fn algorithm_name() -> &'static str {
        "ML-KEM-1024"
    }

    fn security_level() -> u8 {
        3 // NIST security level 3
    }
}

impl KeyEncapsulationMechanism for MLKem1024 {
    type PrivateKey = MLKem1024PrivateKey;
    type PublicKey = MLKem1024PublicKey;

    fn generate_private_key() -> Result<Self::PrivateKey> {
        unsafe {
            let mut private_key_bytes = vec![0u8; MLKEM1024_PRIVATE_KEY_SIZE];
            let mut public_key_bytes = vec![0u8; MLKEM1024_PUBLIC_KEY_SIZE];

            let result = swift_mlkem1024_generate_keypair(
                private_key_bytes.as_mut_ptr(),
                public_key_bytes.as_mut_ptr(),
            );

            if result != 0 {
                return Err(CryptoKitError::KeyGenerationFailed);
            }

            Ok(MLKem1024PrivateKey {
                bytes: private_key_bytes,
                public_key: MLKem1024PublicKey {
                    bytes: public_key_bytes,
                },
            })
        }
    }
}

/// ML-KEM1024 private key
pub struct MLKem1024PrivateKey {
    bytes: Vec<u8>,
    public_key: MLKem1024PublicKey,
}

impl KEMPrivateKey for MLKem1024PrivateKey {
    type PublicKey = MLKem1024PublicKey;
    type SharedSecret = [u8; 32];

    fn public_key(&self) -> Self::PublicKey {
        self.public_key.clone()
    }

    fn decapsulate(&self, ciphertext: &[u8]) -> Result<Self::SharedSecret> {
        if ciphertext.len() != MLKEM1024_CIPHERTEXT_SIZE {
            return Err(CryptoKitError::InvalidInput(
                "Invalid ciphertext length".to_string(),
            ));
        }

        unsafe {
            let mut shared_secret = [0u8; 32];

            let result = swift_mlkem1024_decapsulate(
                self.bytes.as_ptr(),
                ciphertext.as_ptr(),
                shared_secret.as_mut_ptr(),
            );

            if result != 0 {
                return Err(CryptoKitError::DecryptionFailed);
            }

            Ok(shared_secret)
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != MLKEM1024_PRIVATE_KEY_SIZE {
            return Err(CryptoKitError::InvalidInput(
                "Invalid private key length".to_string(),
            ));
        }

        // Derive public key from private key
        unsafe {
            let mut public_key_bytes = vec![0u8; MLKEM1024_PUBLIC_KEY_SIZE];

            let result =
                swift_mlkem1024_derive_public_key(bytes.as_ptr(), public_key_bytes.as_mut_ptr());

            if result != 0 {
                return Err(CryptoKitError::InvalidInput(
                    "Invalid private key".to_string(),
                ));
            }

            Ok(MLKem1024PrivateKey {
                bytes: bytes.to_vec(),
                public_key: MLKem1024PublicKey {
                    bytes: public_key_bytes,
                },
            })
        }
    }
}

/// ML-KEM1024 public key
#[derive(Clone)]
pub struct MLKem1024PublicKey {
    bytes: Vec<u8>,
}

impl KEMPublicKey for MLKem1024PublicKey {
    type SharedSecret = [u8; 32];

    fn encapsulate(&self) -> Result<(Vec<u8>, Self::SharedSecret)> {
        unsafe {
            let mut ciphertext = vec![0u8; MLKEM1024_CIPHERTEXT_SIZE];
            let mut shared_secret = [0u8; 32];

            let result = swift_mlkem1024_encapsulate(
                self.bytes.as_ptr(),
                ciphertext.as_mut_ptr(),
                shared_secret.as_mut_ptr(),
            );

            if result != 0 {
                return Err(CryptoKitError::EncryptionFailed);
            }

            Ok((ciphertext, shared_secret))
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != MLKEM1024_PUBLIC_KEY_SIZE {
            return Err(CryptoKitError::InvalidInput(
                "Invalid public key length".to_string(),
            ));
        }

        Ok(MLKem1024PublicKey {
            bytes: bytes.to_vec(),
        })
    }
}

// X-Wing Hybrid KEM Implementation

/// X-Wing (ML-KEM768 + X25519) Hybrid KEM
pub struct XWingMLKem768X25519;

impl QuantumSafe for XWingMLKem768X25519 {
    fn algorithm_name() -> &'static str {
        "X-Wing-ML-KEM768-X25519"
    }

    fn security_level() -> u8 {
        1 // Security level based on ML-KEM768
    }
}

impl KeyEncapsulationMechanism for XWingMLKem768X25519 {
    type PrivateKey = XWingMLKem768X25519PrivateKey;
    type PublicKey = XWingMLKem768X25519PublicKey;

    fn generate_private_key() -> Result<Self::PrivateKey> {
        unsafe {
            let mut private_key_bytes = vec![0u8; XWING_PRIVATE_KEY_SIZE];
            let mut public_key_bytes = vec![0u8; XWING_PUBLIC_KEY_SIZE];

            let result = swift_xwing_generate_keypair(
                private_key_bytes.as_mut_ptr(),
                public_key_bytes.as_mut_ptr(),
            );

            if result != 0 {
                return Err(CryptoKitError::KeyGenerationFailed);
            }

            Ok(XWingMLKem768X25519PrivateKey {
                bytes: private_key_bytes,
                public_key: XWingMLKem768X25519PublicKey {
                    bytes: public_key_bytes,
                },
            })
        }
    }
}

/// X-Wing private key
pub struct XWingMLKem768X25519PrivateKey {
    bytes: Vec<u8>,
    public_key: XWingMLKem768X25519PublicKey,
}

impl KEMPrivateKey for XWingMLKem768X25519PrivateKey {
    type PublicKey = XWingMLKem768X25519PublicKey;
    type SharedSecret = [u8; 32];

    fn public_key(&self) -> Self::PublicKey {
        self.public_key.clone()
    }

    fn decapsulate(&self, ciphertext: &[u8]) -> Result<Self::SharedSecret> {
        if ciphertext.len() != XWING_CIPHERTEXT_SIZE {
            return Err(CryptoKitError::InvalidInput(
                "Invalid ciphertext length".to_string(),
            ));
        }

        unsafe {
            let mut shared_secret = [0u8; 32];

            let result = swift_xwing_decapsulate(
                self.bytes.as_ptr(),
                ciphertext.as_ptr(),
                shared_secret.as_mut_ptr(),
            );

            if result != 0 {
                return Err(CryptoKitError::DecryptionFailed);
            }

            Ok(shared_secret)
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != XWING_PRIVATE_KEY_SIZE {
            return Err(CryptoKitError::InvalidInput(
                "Invalid private key length".to_string(),
            ));
        }

        // Derive public key from private key
        unsafe {
            let mut public_key_bytes = vec![0u8; XWING_PUBLIC_KEY_SIZE];

            let result =
                swift_xwing_derive_public_key(bytes.as_ptr(), public_key_bytes.as_mut_ptr());

            if result != 0 {
                return Err(CryptoKitError::InvalidInput(
                    "Invalid private key".to_string(),
                ));
            }

            Ok(XWingMLKem768X25519PrivateKey {
                bytes: bytes.to_vec(),
                public_key: XWingMLKem768X25519PublicKey {
                    bytes: public_key_bytes,
                },
            })
        }
    }
}

/// X-Wing public key
#[derive(Clone)]
pub struct XWingMLKem768X25519PublicKey {
    bytes: Vec<u8>,
}

impl KEMPublicKey for XWingMLKem768X25519PublicKey {
    type SharedSecret = [u8; 32];

    fn encapsulate(&self) -> Result<(Vec<u8>, Self::SharedSecret)> {
        unsafe {
            let mut ciphertext = vec![0u8; XWING_CIPHERTEXT_SIZE];
            let mut shared_secret = [0u8; 32];

            let result = swift_xwing_encapsulate(
                self.bytes.as_ptr(),
                ciphertext.as_mut_ptr(),
                shared_secret.as_mut_ptr(),
            );

            if result != 0 {
                return Err(CryptoKitError::EncryptionFailed);
            }

            Ok((ciphertext, shared_secret))
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != XWING_PUBLIC_KEY_SIZE {
            return Err(CryptoKitError::InvalidInput(
                "Invalid public key length".to_string(),
            ));
        }

        Ok(XWingMLKem768X25519PublicKey {
            bytes: bytes.to_vec(),
        })
    }
}

// Constant definitions - According to NIST standard
const MLKEM768_PUBLIC_KEY_SIZE: usize = 1184;
const MLKEM768_PRIVATE_KEY_SIZE: usize = 2400;
const MLKEM768_CIPHERTEXT_SIZE: usize = 1088;

const MLKEM1024_PUBLIC_KEY_SIZE: usize = 1568;
const MLKEM1024_PRIVATE_KEY_SIZE: usize = 3168;
const MLKEM1024_CIPHERTEXT_SIZE: usize = 1568;

const XWING_PUBLIC_KEY_SIZE: usize = 1216; // ML-KEM768 public key + X25519 public key
const XWING_PRIVATE_KEY_SIZE: usize = 2432; // ML-KEM768 private key + X25519 private key
const XWING_CIPHERTEXT_SIZE: usize = 1120; // ML-KEM768 ciphertext + X25519 ciphertext

// Swift FFI declarations
extern "C" {
    // ML-KEM768
    fn swift_mlkem768_generate_keypair(private_key: *mut u8, public_key: *mut u8) -> i32;
    fn swift_mlkem768_encapsulate(
        public_key: *const u8,
        ciphertext: *mut u8,
        shared_secret: *mut u8,
    ) -> i32;
    fn swift_mlkem768_decapsulate(
        private_key: *const u8,
        ciphertext: *const u8,
        shared_secret: *mut u8,
    ) -> i32;
    fn swift_mlkem768_derive_public_key(private_key: *const u8, public_key: *mut u8) -> i32;

    // ML-KEM1024
    fn swift_mlkem1024_generate_keypair(private_key: *mut u8, public_key: *mut u8) -> i32;
    fn swift_mlkem1024_encapsulate(
        public_key: *const u8,
        ciphertext: *mut u8,
        shared_secret: *mut u8,
    ) -> i32;
    fn swift_mlkem1024_decapsulate(
        private_key: *const u8,
        ciphertext: *const u8,
        shared_secret: *mut u8,
    ) -> i32;
    fn swift_mlkem1024_derive_public_key(private_key: *const u8, public_key: *mut u8) -> i32;

    // X-Wing
    fn swift_xwing_generate_keypair(private_key: *mut u8, public_key: *mut u8) -> i32;
    fn swift_xwing_encapsulate(
        public_key: *const u8,
        ciphertext: *mut u8,
        shared_secret: *mut u8,
    ) -> i32;
    fn swift_xwing_decapsulate(
        private_key: *const u8,
        ciphertext: *const u8,
        shared_secret: *mut u8,
    ) -> i32;
    fn swift_xwing_derive_public_key(private_key: *const u8, public_key: *mut u8) -> i32;
}

//! # 量子安全数字签名算法
//!
//! 本模块实现了抗量子攻击的数字签名算法，包括：
//! - ML-DSA65: 基于格的数字签名算法，安全级别2
//! - ML-DSA87: 基于格的数字签名算法，安全级别3
//!
//! 这些算法提供量子安全的数字签名功能。

use crate::quantum::QuantumSafe;
use crate::{CryptoKitError, Result};

/// 数字签名算法的通用特征
pub trait DigitalSignatureAlgorithm: QuantumSafe {
    type PrivateKey: SignaturePrivateKey;
    type PublicKey: SignaturePublicKey;

    /// 生成新的私钥
    fn generate_private_key() -> Result<Self::PrivateKey>;
}

/// 签名私钥的通用特征
pub trait SignaturePrivateKey {
    type PublicKey: SignaturePublicKey;
    type Signature;

    /// 获取对应的公钥
    fn public_key(&self) -> Self::PublicKey;

    /// 对消息进行签名
    fn sign(&self, message: &[u8]) -> Result<Self::Signature>;

    /// 将私钥序列化为字节数组
    fn to_bytes(&self) -> Vec<u8>;

    /// 从字节数组反序列化私钥
    fn from_bytes(bytes: &[u8]) -> Result<Self>
    where
        Self: Sized;
}

/// 签名公钥的通用特征
pub trait SignaturePublicKey {
    type Signature;

    /// 验证签名
    fn verify(&self, message: &[u8], signature: &Self::Signature) -> Result<bool>;

    /// 将公钥序列化为字节数组
    fn to_bytes(&self) -> Vec<u8>;

    /// 从字节数组反序列化公钥
    fn from_bytes(bytes: &[u8]) -> Result<Self>
    where
        Self: Sized;
}

// ML-DSA65 实现

/// ML-DSA65 算法（安全级别2）
pub struct MLDsa65;

impl QuantumSafe for MLDsa65 {
    fn algorithm_name() -> &'static str {
        "ML-DSA-65"
    }

    fn security_level() -> u8 {
        2 // NIST 安全级别 2
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

/// ML-DSA65 私钥
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

        // 从私钥推导公钥
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

/// ML-DSA65 公钥
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

// ML-DSA87 实现

/// ML-DSA87 算法（安全级别3）
pub struct MLDsa87;

impl QuantumSafe for MLDsa87 {
    fn algorithm_name() -> &'static str {
        "ML-DSA-87"
    }

    fn security_level() -> u8 {
        3 // NIST 安全级别 3
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

/// ML-DSA87 私钥
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

        // 从私钥推导公钥
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

/// ML-DSA87 公钥
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

// 常量定义 - 根据NIST标准
const MLDSA65_PUBLIC_KEY_SIZE: usize = 1952;
const MLDSA65_PRIVATE_KEY_SIZE: usize = 4032;
const MLDSA65_SIGNATURE_SIZE: usize = 3309; // 最大签名长度

const MLDSA87_PUBLIC_KEY_SIZE: usize = 2592;
const MLDSA87_PRIVATE_KEY_SIZE: usize = 4896;
const MLDSA87_SIGNATURE_SIZE: usize = 4627; // 最大签名长度

// Swift FFI 声明
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

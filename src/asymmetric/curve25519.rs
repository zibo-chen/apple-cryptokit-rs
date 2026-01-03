use crate::asymmetric::{KeyAgreement, SignatureAlgorithm};
use crate::error::{CryptoKitError, Result};

// Curve25519 相关的 Swift FFI 声明
extern "C" {
    fn swift_ed25519_generate_keypair(private_key: *mut u8, public_key: *mut u8) -> i32;
    fn swift_ed25519_sign(
        private_key: *const u8,
        data: *const u8,
        data_len: i32,
        signature: *mut u8,
    ) -> i32;
    fn swift_ed25519_verify(
        public_key: *const u8,
        signature: *const u8,
        data: *const u8,
        data_len: i32,
    ) -> i32;
    fn swift_x25519_generate_keypair(private_key: *mut u8, public_key: *mut u8) -> i32;
    fn swift_x25519_key_agreement(
        private_key: *const u8,
        public_key: *const u8,
        shared_secret: *mut u8,
    ) -> i32;
}

/// Curve25519 私钥
#[derive(Clone)]
pub struct Curve25519PrivateKey {
    data: [u8; 32],
}

/// Curve25519 公钥
#[derive(Clone)]
pub struct Curve25519PublicKey {
    data: [u8; 32],
}

/// Ed25519 数字签名
#[derive(Clone)]
pub struct Ed25519Signature {
    data: [u8; 64],
}

/// 共享密钥
#[derive(Clone)]
pub struct SharedSecret {
    data: [u8; 32],
}

impl Curve25519PrivateKey {
    /// 从原始字节创建私钥
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { data: bytes }
    }

    /// 获取原始字节
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.data
    }
}

impl Curve25519PublicKey {
    /// 从原始字节创建公钥
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { data: bytes }
    }

    /// 获取原始字节
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.data
    }
}

impl Ed25519Signature {
    /// 从原始字节创建签名
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self { data: bytes }
    }

    /// 获取原始字节
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.data
    }
}

impl SharedSecret {
    /// 从原始字节创建共享密钥
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { data: bytes }
    }

    /// 获取原始字节
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.data
    }
}

/// Ed25519 数字签名算法（基于Curve25519）
pub struct Ed25519;

impl SignatureAlgorithm for Ed25519 {
    type PrivateKey = Curve25519PrivateKey;
    type PublicKey = Curve25519PublicKey;
    type Signature = Ed25519Signature;

    fn generate_key_pair() -> Result<(Self::PrivateKey, Self::PublicKey)> {
        unsafe {
            let mut private_key = [0u8; 32];
            let mut public_key = [0u8; 32];

            let result =
                swift_ed25519_generate_keypair(private_key.as_mut_ptr(), public_key.as_mut_ptr());

            if result == 0 {
                Ok((
                    Curve25519PrivateKey::from_bytes(private_key),
                    Curve25519PublicKey::from_bytes(public_key),
                ))
            } else {
                Err(CryptoKitError::KeyGenerationFailed)
            }
        }
    }

    fn sign(private_key: &Self::PrivateKey, data: &[u8]) -> Result<Self::Signature> {
        unsafe {
            let mut signature = [0u8; 64];

            let result = swift_ed25519_sign(
                private_key.as_bytes().as_ptr(),
                data.as_ptr(),
                data.len() as i32,
                signature.as_mut_ptr(),
            );

            if result == 0 {
                Ok(Ed25519Signature::from_bytes(signature))
            } else {
                Err(CryptoKitError::SignatureFailed)
            }
        }
    }

    fn verify(
        public_key: &Self::PublicKey,
        signature: &Self::Signature,
        data: &[u8],
    ) -> Result<bool> {
        unsafe {
            let result = swift_ed25519_verify(
                public_key.as_bytes().as_ptr(),
                signature.as_bytes().as_ptr(),
                data.as_ptr(),
                data.len() as i32,
            );

            match result {
                1 => Ok(true),
                0 => Ok(false),
                _ => Err(CryptoKitError::VerificationFailed),
            }
        }
    }
}

/// X25519 密钥交换算法（基于Curve25519）
pub struct X25519;

impl KeyAgreement for X25519 {
    type PrivateKey = Curve25519PrivateKey;
    type PublicKey = Curve25519PublicKey;
    type SharedSecret = SharedSecret;

    fn generate_key_pair() -> Result<(Self::PrivateKey, Self::PublicKey)> {
        unsafe {
            let mut private_key = [0u8; 32];
            let mut public_key = [0u8; 32];

            let result =
                swift_x25519_generate_keypair(private_key.as_mut_ptr(), public_key.as_mut_ptr());

            if result == 0 {
                Ok((
                    Curve25519PrivateKey::from_bytes(private_key),
                    Curve25519PublicKey::from_bytes(public_key),
                ))
            } else {
                Err(CryptoKitError::KeyGenerationFailed)
            }
        }
    }

    fn key_agreement(
        private_key: &Self::PrivateKey,
        public_key: &Self::PublicKey,
    ) -> Result<Self::SharedSecret> {
        unsafe {
            let mut shared_secret = [0u8; 32];

            let result = swift_x25519_key_agreement(
                private_key.as_bytes().as_ptr(),
                public_key.as_bytes().as_ptr(),
                shared_secret.as_mut_ptr(),
            );

            if result == 0 {
                Ok(SharedSecret::from_bytes(shared_secret))
            } else {
                Err(CryptoKitError::DerivationFailed)
            }
        }
    }
}

// 提供便利函数
pub fn ed25519_generate_keypair() -> Result<(Curve25519PrivateKey, Curve25519PublicKey)> {
    Ed25519::generate_key_pair()
}

pub fn ed25519_sign(private_key: &Curve25519PrivateKey, data: &[u8]) -> Result<Ed25519Signature> {
    Ed25519::sign(private_key, data)
}

pub fn ed25519_verify(
    public_key: &Curve25519PublicKey,
    signature: &Ed25519Signature,
    data: &[u8],
) -> Result<bool> {
    Ed25519::verify(public_key, signature, data)
}

pub fn x25519_generate_keypair() -> Result<(Curve25519PrivateKey, Curve25519PublicKey)> {
    X25519::generate_key_pair()
}

pub fn x25519_key_agreement(
    private_key: &Curve25519PrivateKey,
    public_key: &Curve25519PublicKey,
) -> Result<SharedSecret> {
    X25519::key_agreement(private_key, public_key)
}

// P-256 椭圆曲线实现

use crate::asymmetric::{KeyAgreement, SignatureAlgorithm};
use crate::error::{CryptoKitError, Result};

// P-256 相关的 Swift FFI 声明
extern "C" {
    fn swift_p256_generate_keypair(private_key: *mut u8, public_key: *mut u8) -> i32;
    fn swift_p256_sign(
        private_key: *const u8,
        data: *const u8,
        data_len: i32,
        signature: *mut u8,
    ) -> i32;
    fn swift_p256_verify(
        public_key: *const u8,
        signature: *const u8,
        data: *const u8,
        data_len: i32,
    ) -> i32;
    fn swift_p256_key_agreement(
        private_key: *const u8,
        public_key: *const u8,
        shared_secret: *mut u8,
    ) -> i32;
}

/// P-256 私钥 (32 bytes)
#[derive(Clone)]
pub struct P256PrivateKey {
    data: [u8; 32],
}

/// P-256 公钥 (64 bytes)
#[derive(Clone)]
pub struct P256PublicKey {
    data: [u8; 64],
}

/// P-256 签名 (64 bytes)
#[derive(Clone)]
pub struct P256Signature {
    data: [u8; 64],
}

/// P-256 共享密钥 (32 bytes)
#[derive(Clone)]
pub struct P256SharedSecret {
    data: [u8; 32],
}

impl P256PrivateKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { data: bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.data
    }
}

impl P256PublicKey {
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self { data: bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.data
    }
}

impl P256Signature {
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self { data: bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.data
    }
}

impl P256SharedSecret {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { data: bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.data
    }
}

/// P-256 椭圆曲线数字签名算法
pub struct P256;

impl SignatureAlgorithm for P256 {
    type PrivateKey = P256PrivateKey;
    type PublicKey = P256PublicKey;
    type Signature = P256Signature;

    fn generate_key_pair() -> Result<(Self::PrivateKey, Self::PublicKey)> {
        unsafe {
            let mut private_key = [0u8; 32];
            let mut public_key = [0u8; 64];

            let result =
                swift_p256_generate_keypair(private_key.as_mut_ptr(), public_key.as_mut_ptr());

            if result == 0 {
                Ok((
                    P256PrivateKey::from_bytes(private_key),
                    P256PublicKey::from_bytes(public_key),
                ))
            } else {
                Err(CryptoKitError::KeyGenerationFailed)
            }
        }
    }

    fn sign(private_key: &Self::PrivateKey, data: &[u8]) -> Result<Self::Signature> {
        unsafe {
            let mut signature = [0u8; 64];

            let result = swift_p256_sign(
                private_key.as_bytes().as_ptr(),
                data.as_ptr(),
                data.len() as i32,
                signature.as_mut_ptr(),
            );

            if result == 0 {
                Ok(P256Signature::from_bytes(signature))
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
            let result = swift_p256_verify(
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

impl KeyAgreement for P256 {
    type PrivateKey = P256PrivateKey;
    type PublicKey = P256PublicKey;
    type SharedSecret = P256SharedSecret;

    fn generate_key_pair() -> Result<(Self::PrivateKey, Self::PublicKey)> {
        <P256 as SignatureAlgorithm>::generate_key_pair()
    }

    fn key_agreement(
        private_key: &Self::PrivateKey,
        public_key: &Self::PublicKey,
    ) -> Result<Self::SharedSecret> {
        unsafe {
            let mut shared_secret = [0u8; 32];

            let result = swift_p256_key_agreement(
                private_key.as_bytes().as_ptr(),
                public_key.as_bytes().as_ptr(),
                shared_secret.as_mut_ptr(),
            );

            if result == 0 {
                Ok(P256SharedSecret::from_bytes(shared_secret))
            } else {
                Err(CryptoKitError::DerivationFailed)
            }
        }
    }
}

// 便利函数
pub fn generate_keypair() -> Result<(P256PrivateKey, P256PublicKey)> {
    <P256 as SignatureAlgorithm>::generate_key_pair()
}

pub fn sign(private_key: &P256PrivateKey, data: &[u8]) -> Result<P256Signature> {
    P256::sign(private_key, data)
}

pub fn verify(public_key: &P256PublicKey, signature: &P256Signature, data: &[u8]) -> Result<bool> {
    P256::verify(public_key, signature, data)
}

pub fn key_agreement(
    private_key: &P256PrivateKey,
    public_key: &P256PublicKey,
) -> Result<P256SharedSecret> {
    P256::key_agreement(private_key, public_key)
}

// P-384 椭圆曲线实现

use crate::asymmetric::{KeyAgreement, SignatureAlgorithm};
use crate::error::{CryptoKitError, Result};

// P-384 相关的 Swift FFI 声明
extern "C" {
    fn swift_p384_generate_keypair(private_key: *mut u8, public_key: *mut u8) -> i32;
    fn swift_p384_sign(
        private_key: *const u8,
        data: *const u8,
        data_len: i32,
        signature: *mut u8,
    ) -> i32;
    fn swift_p384_verify(
        public_key: *const u8,
        signature: *const u8,
        data: *const u8,
        data_len: i32,
    ) -> i32;
    fn swift_p384_key_agreement(
        private_key: *const u8,
        public_key: *const u8,
        shared_secret: *mut u8,
    ) -> i32;
}

/// P-384 私钥 (48 bytes)
#[derive(Clone)]
pub struct P384PrivateKey {
    data: [u8; 48],
}

/// P-384 公钥 (96 bytes)
#[derive(Clone)]
pub struct P384PublicKey {
    data: [u8; 96],
}

/// P-384 签名 (96 bytes)
#[derive(Clone)]
pub struct P384Signature {
    data: [u8; 96],
}

/// P-384 共享密钥 (48 bytes)
#[derive(Clone)]
pub struct P384SharedSecret {
    data: [u8; 48],
}

impl P384PrivateKey {
    pub fn from_bytes(bytes: [u8; 48]) -> Self {
        Self { data: bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 48] {
        &self.data
    }
}

impl P384PublicKey {
    pub fn from_bytes(bytes: [u8; 96]) -> Self {
        Self { data: bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 96] {
        &self.data
    }
}

impl P384Signature {
    pub fn from_bytes(bytes: [u8; 96]) -> Self {
        Self { data: bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 96] {
        &self.data
    }
}

impl P384SharedSecret {
    pub fn from_bytes(bytes: [u8; 48]) -> Self {
        Self { data: bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 48] {
        &self.data
    }
}

/// P-384 椭圆曲线数字签名算法
pub struct P384;

impl SignatureAlgorithm for P384 {
    type PrivateKey = P384PrivateKey;
    type PublicKey = P384PublicKey;
    type Signature = P384Signature;

    fn generate_key_pair() -> Result<(Self::PrivateKey, Self::PublicKey)> {
        unsafe {
            let mut private_key = [0u8; 48];
            let mut public_key = [0u8; 96];

            let result =
                swift_p384_generate_keypair(private_key.as_mut_ptr(), public_key.as_mut_ptr());

            if result == 0 {
                Ok((
                    P384PrivateKey::from_bytes(private_key),
                    P384PublicKey::from_bytes(public_key),
                ))
            } else {
                Err(CryptoKitError::KeyGenerationFailed)
            }
        }
    }

    fn sign(private_key: &Self::PrivateKey, data: &[u8]) -> Result<Self::Signature> {
        unsafe {
            let mut signature = [0u8; 96];

            let result = swift_p384_sign(
                private_key.as_bytes().as_ptr(),
                data.as_ptr(),
                data.len() as i32,
                signature.as_mut_ptr(),
            );

            if result == 0 {
                Ok(P384Signature::from_bytes(signature))
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
            let result = swift_p384_verify(
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

impl KeyAgreement for P384 {
    type PrivateKey = P384PrivateKey;
    type PublicKey = P384PublicKey;
    type SharedSecret = P384SharedSecret;

    fn generate_key_pair() -> Result<(Self::PrivateKey, Self::PublicKey)> {
        <P384 as SignatureAlgorithm>::generate_key_pair()
    }

    fn key_agreement(
        private_key: &Self::PrivateKey,
        public_key: &Self::PublicKey,
    ) -> Result<Self::SharedSecret> {
        unsafe {
            let mut shared_secret = [0u8; 48];

            let result = swift_p384_key_agreement(
                private_key.as_bytes().as_ptr(),
                public_key.as_bytes().as_ptr(),
                shared_secret.as_mut_ptr(),
            );

            if result == 0 {
                Ok(P384SharedSecret::from_bytes(shared_secret))
            } else {
                Err(CryptoKitError::DerivationFailed)
            }
        }
    }
}

// 便利函数
pub fn generate_keypair() -> Result<(P384PrivateKey, P384PublicKey)> {
    <P384 as SignatureAlgorithm>::generate_key_pair()
}

pub fn sign(private_key: &P384PrivateKey, data: &[u8]) -> Result<P384Signature> {
    P384::sign(private_key, data)
}

pub fn verify(public_key: &P384PublicKey, signature: &P384Signature, data: &[u8]) -> Result<bool> {
    P384::verify(public_key, signature, data)
}

pub fn key_agreement(
    private_key: &P384PrivateKey,
    public_key: &P384PublicKey,
) -> Result<P384SharedSecret> {
    P384::key_agreement(private_key, public_key)
}

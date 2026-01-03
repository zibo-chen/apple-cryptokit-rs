// P-521 椭圆曲线实现

use crate::asymmetric::{KeyAgreement, SignatureAlgorithm};
use crate::error::{CryptoKitError, Result};

// P-521 相关的 Swift FFI 声明
extern "C" {
    fn swift_p521_generate_keypair(private_key: *mut u8, public_key: *mut u8) -> i32;
    fn swift_p521_sign(
        private_key: *const u8,
        data: *const u8,
        data_len: i32,
        signature: *mut u8,
    ) -> i32;
    fn swift_p521_verify(
        public_key: *const u8,
        signature: *const u8,
        data: *const u8,
        data_len: i32,
    ) -> i32;
    fn swift_p521_key_agreement(
        private_key: *const u8,
        public_key: *const u8,
        shared_secret: *mut u8,
    ) -> i32;
}

/// P-521 私钥 (66 bytes)
#[derive(Clone)]
pub struct P521PrivateKey {
    data: [u8; 66],
}

/// P-521 公钥 (132 bytes)
#[derive(Clone)]
pub struct P521PublicKey {
    data: [u8; 132],
}

/// P-521 签名 (132 bytes)
#[derive(Clone)]
pub struct P521Signature {
    data: [u8; 132],
}

/// P-521 共享密钥 (66 bytes)
#[derive(Clone)]
pub struct P521SharedSecret {
    data: [u8; 66],
}

impl P521PrivateKey {
    pub fn from_bytes(bytes: [u8; 66]) -> Self {
        Self { data: bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 66] {
        &self.data
    }
}

impl P521PublicKey {
    pub fn from_bytes(bytes: [u8; 132]) -> Self {
        Self { data: bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 132] {
        &self.data
    }
}

impl P521Signature {
    pub fn from_bytes(bytes: [u8; 132]) -> Self {
        Self { data: bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 132] {
        &self.data
    }
}

impl P521SharedSecret {
    pub fn from_bytes(bytes: [u8; 66]) -> Self {
        Self { data: bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 66] {
        &self.data
    }
}

/// P-521 椭圆曲线数字签名算法
pub struct P521;

impl SignatureAlgorithm for P521 {
    type PrivateKey = P521PrivateKey;
    type PublicKey = P521PublicKey;
    type Signature = P521Signature;

    fn generate_key_pair() -> Result<(Self::PrivateKey, Self::PublicKey)> {
        unsafe {
            let mut private_key = [0u8; 66];
            let mut public_key = [0u8; 132];

            let result =
                swift_p521_generate_keypair(private_key.as_mut_ptr(), public_key.as_mut_ptr());

            if result == 0 {
                Ok((
                    P521PrivateKey::from_bytes(private_key),
                    P521PublicKey::from_bytes(public_key),
                ))
            } else {
                Err(CryptoKitError::KeyGenerationFailed)
            }
        }
    }

    fn sign(private_key: &Self::PrivateKey, data: &[u8]) -> Result<Self::Signature> {
        unsafe {
            let mut signature = [0u8; 132];

            let result = swift_p521_sign(
                private_key.as_bytes().as_ptr(),
                data.as_ptr(),
                data.len() as i32,
                signature.as_mut_ptr(),
            );

            if result == 0 {
                Ok(P521Signature::from_bytes(signature))
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
            let result = swift_p521_verify(
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

impl KeyAgreement for P521 {
    type PrivateKey = P521PrivateKey;
    type PublicKey = P521PublicKey;
    type SharedSecret = P521SharedSecret;

    fn generate_key_pair() -> Result<(Self::PrivateKey, Self::PublicKey)> {
        <P521 as SignatureAlgorithm>::generate_key_pair()
    }

    fn key_agreement(
        private_key: &Self::PrivateKey,
        public_key: &Self::PublicKey,
    ) -> Result<Self::SharedSecret> {
        unsafe {
            let mut shared_secret = [0u8; 66];

            let result = swift_p521_key_agreement(
                private_key.as_bytes().as_ptr(),
                public_key.as_bytes().as_ptr(),
                shared_secret.as_mut_ptr(),
            );

            if result == 0 {
                Ok(P521SharedSecret::from_bytes(shared_secret))
            } else {
                Err(CryptoKitError::DerivationFailed)
            }
        }
    }
}

// 便利函数
pub fn generate_keypair() -> Result<(P521PrivateKey, P521PublicKey)> {
    <P521 as SignatureAlgorithm>::generate_key_pair()
}

pub fn sign(private_key: &P521PrivateKey, data: &[u8]) -> Result<P521Signature> {
    P521::sign(private_key, data)
}

pub fn verify(public_key: &P521PublicKey, signature: &P521Signature, data: &[u8]) -> Result<bool> {
    P521::verify(public_key, signature, data)
}

pub fn key_agreement(
    private_key: &P521PrivateKey,
    public_key: &P521PublicKey,
) -> Result<P521SharedSecret> {
    P521::key_agreement(private_key, public_key)
}

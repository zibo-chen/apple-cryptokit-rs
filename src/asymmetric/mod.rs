use crate::error::Result;

pub mod curve25519;
pub mod p256;
pub mod p384;
pub mod p521;

/// 数字签名算法的通用trait
pub trait SignatureAlgorithm {
    type PrivateKey;
    type PublicKey;
    type Signature;

    /// 生成密钥对
    fn generate_key_pair() -> Result<(Self::PrivateKey, Self::PublicKey)>;

    /// 签名数据
    fn sign(private_key: &Self::PrivateKey, data: &[u8]) -> Result<Self::Signature>;

    /// 验证签名
    fn verify(
        public_key: &Self::PublicKey,
        signature: &Self::Signature,
        data: &[u8],
    ) -> Result<bool>;
}

/// 密钥交换算法的通用trait
pub trait KeyAgreement {
    type PrivateKey;
    type PublicKey;
    type SharedSecret;

    /// 生成密钥对
    fn generate_key_pair() -> Result<(Self::PrivateKey, Self::PublicKey)>;

    /// 执行密钥交换
    fn key_agreement(
        private_key: &Self::PrivateKey,
        public_key: &Self::PublicKey,
    ) -> Result<Self::SharedSecret>;
}

/// 公钥算法的通用trait，组合签名和密钥交换
pub trait PublicKeyAlgorithm: SignatureAlgorithm + KeyAgreement {}

// Re-export commonly used types
pub use curve25519::{
    Curve25519PrivateKey, Curve25519PublicKey, Ed25519, Ed25519Signature, SharedSecret, X25519,
    ed25519_generate_keypair, ed25519_sign, ed25519_verify, x25519_generate_keypair,
    x25519_key_agreement,
};

pub use p256::{
    P256, P256PrivateKey, P256PublicKey, P256SharedSecret, P256Signature,
    generate_keypair as p256_generate_keypair, key_agreement as p256_key_agreement,
    sign as p256_sign, verify as p256_verify,
};

pub use p384::{
    P384, P384PrivateKey, P384PublicKey, P384SharedSecret, P384Signature,
    generate_keypair as p384_generate_keypair, key_agreement as p384_key_agreement,
    sign as p384_sign, verify as p384_verify,
};

pub use p521::{
    P521, P521PrivateKey, P521PublicKey, P521SharedSecret, P521Signature,
    generate_keypair as p521_generate_keypair, key_agreement as p521_key_agreement,
    sign as p521_sign, verify as p521_verify,
};

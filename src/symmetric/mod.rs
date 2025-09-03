use crate::error::Result;

pub mod aes;
pub mod chacha;

/// 加密算法的通用trait
pub trait Cipher {
    type Key;
    type Nonce;

    /// 加密数据
    fn encrypt(key: &Self::Key, nonce: &Self::Nonce, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// 解密数据
    fn decrypt(key: &Self::Key, nonce: &Self::Nonce, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

/// 认证加密算法的trait (AEAD - Authenticated Encryption with Associated Data)
pub trait AuthenticatedCipher {
    type Key;
    type Nonce;

    /// 加密并认证数据
    fn seal(key: &Self::Key, nonce: &Self::Nonce, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// 验证并解密数据
    fn open(key: &Self::Key, nonce: &Self::Nonce, ciphertext: &[u8]) -> Result<Vec<u8>>;

    /// 加密并认证数据，支持附加认证数据(AAD)
    fn seal_with_aad(
        key: &Self::Key,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>>;

    /// 验证并解密数据，支持附加认证数据(AAD)
    fn open_with_aad(
        key: &Self::Key,
        nonce: &Self::Nonce,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>>;
}

use crate::error::Result;

pub mod aes;
pub mod chacha;

/// The cipher process may include authentication tags, so we allocate
/// extra space for tags to accomodate this.
const MAX_TAG_LEN: usize = 16;

/// 加密算法的通用trait
pub trait Cipher {
    type Key;
    type Nonce;

    /// 加密数据
    fn encrypt(key: &Self::Key, nonce: &Self::Nonce, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut ciphertext = vec![0u8; plaintext.len() + MAX_TAG_LEN]; // Extra space for tag
        let len = Self::encrypt_to(key, nonce, plaintext, &mut ciphertext)?;
        ciphertext.truncate(len);
        Ok(ciphertext)
    }

    fn encrypt_to(
        key: &Self::Key,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize>;

    /// 解密数据
    fn decrypt(key: &Self::Key, nonce: &Self::Nonce, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut plaintext = vec![0u8; ciphertext.len() + MAX_TAG_LEN];
        let len = Self::decrypt_to(key, nonce, ciphertext, &mut plaintext)?;
        plaintext.truncate(len);
        Ok(plaintext)
    }

    fn decrypt_to(
        key: &Self::Key,
        nonce: &Self::Nonce,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize>;
}

/// 认证加密算法的trait (AEAD - Authenticated Encryption with Associated Data)
pub trait AuthenticatedCipher {
    type Key;
    type Nonce;

    /// 加密并认证数据
    fn seal(key: &Self::Key, nonce: &Self::Nonce, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut ciphertext = vec![0u8; plaintext.len() + MAX_TAG_LEN]; // Extra space for tag
        let len = Self::seal_to(key, nonce, plaintext, &mut ciphertext)?;
        ciphertext.truncate(len);
        Ok(ciphertext)
    }

    fn seal_to(
        key: &Self::Key,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize>;

    /// 验证并解密数据
    fn open(key: &Self::Key, nonce: &Self::Nonce, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut plaintext = vec![0u8; ciphertext.len() + MAX_TAG_LEN];
        let len = Self::open_to(key, nonce, ciphertext, &mut plaintext)?;
        plaintext.truncate(len);
        Ok(plaintext)
    }

    fn open_to(
        key: &Self::Key,
        nonce: &Self::Nonce,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize>;

    /// 加密并认证数据，支持附加认证数据(AAD)
    fn seal_with_aad(
        key: &Self::Key,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        let mut ciphertext = vec![0u8; plaintext.len() + MAX_TAG_LEN]; // Extra space for tag
        let len = Self::seal_to_with_aad(key, nonce, plaintext, aad, &mut ciphertext)?;
        ciphertext.truncate(len);
        Ok(ciphertext)
    }

    fn seal_to_with_aad(
        key: &Self::Key,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        aad: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize>;

    /// 验证并解密数据，支持附加认证数据(AAD)
    fn open_with_aad(
        key: &Self::Key,
        nonce: &Self::Nonce,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        let mut plaintext = vec![0u8; ciphertext.len() + MAX_TAG_LEN];
        let len = Self::open_to_with_aad(key, nonce, ciphertext, aad, &mut plaintext)?;
        plaintext.truncate(len);
        Ok(plaintext)
    }

    fn open_to_with_aad(
        key: &Self::Key,
        nonce: &Self::Nonce,
        ciphertext: &[u8],
        aad: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize>;
}

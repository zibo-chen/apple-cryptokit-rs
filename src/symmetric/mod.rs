use crate::error::Result;

pub mod aes;
pub mod chacha;

/// 加密算法的通用trait
pub trait Cipher {
    type Key;
    type Nonce;

    /// 认证标签大小（字节）
    const TAG_SIZE: usize;

    /// 计算加密后的输出大小
    fn encrypted_size(plaintext_len: usize) -> usize {
        plaintext_len + Self::TAG_SIZE
    }

    /// 计算解密后的输出大小
    fn decrypted_size(ciphertext_len: usize) -> Option<usize> {
        ciphertext_len.checked_sub(Self::TAG_SIZE)
    }

    /// 加密数据
    fn encrypt(key: &Self::Key, nonce: &Self::Nonce, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut ciphertext = vec![0u8; Self::encrypted_size(plaintext.len())];
        let len = Self::encrypt_to(key, nonce, plaintext, &mut ciphertext)?;
        ciphertext.truncate(len);
        Ok(ciphertext)
    }

    /// 加密数据到提供的缓冲区（零分配）
    ///
    /// # 参数
    /// - `output`: 必须至少有 `plaintext.len() + TAG_SIZE` 字节
    ///
    /// # 返回
    /// - `Ok(usize)`: 写入的字节数
    fn encrypt_to(
        key: &Self::Key,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize>;

    /// 解密数据
    fn decrypt(key: &Self::Key, nonce: &Self::Nonce, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut plaintext = vec![0u8; ciphertext.len()];
        let len = Self::decrypt_to(key, nonce, ciphertext, &mut plaintext)?;
        plaintext.truncate(len);
        Ok(plaintext)
    }

    /// 解密数据到提供的缓冲区（零分配）
    ///
    /// # 参数
    /// - `output`: 必须至少有 `ciphertext.len() - TAG_SIZE` 字节
    ///
    /// # 返回
    /// - `Ok(usize)`: 写入的字节数
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

    /// 认证标签大小（字节）
    const TAG_SIZE: usize;

    /// 计算加密后的输出大小
    fn sealed_size(plaintext_len: usize) -> usize {
        plaintext_len + Self::TAG_SIZE
    }

    /// 计算解密后的输出大小
    fn opened_size(ciphertext_len: usize) -> Option<usize> {
        ciphertext_len.checked_sub(Self::TAG_SIZE)
    }

    /// 加密并认证数据
    fn seal(key: &Self::Key, nonce: &Self::Nonce, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut ciphertext = vec![0u8; Self::sealed_size(plaintext.len())];
        let len = Self::seal_to(key, nonce, plaintext, &mut ciphertext)?;
        ciphertext.truncate(len);
        Ok(ciphertext)
    }

    /// 加密并认证数据到提供的缓冲区（零分配）
    ///
    /// # 参数
    /// - `ciphertext`: 必须至少有 `plaintext.len() + TAG_SIZE` 字节
    ///
    /// # 返回
    /// - `Ok(usize)`: 写入的字节数（plaintext.len() + TAG_SIZE）
    fn seal_to(
        key: &Self::Key,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize>;

    /// 验证并解密数据
    fn open(key: &Self::Key, nonce: &Self::Nonce, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut plaintext = vec![0u8; ciphertext.len()];
        let len = Self::open_to(key, nonce, ciphertext, &mut plaintext)?;
        plaintext.truncate(len);
        Ok(plaintext)
    }

    /// 验证并解密数据到提供的缓冲区（零分配）
    ///
    /// # 参数
    /// - `plaintext`: 必须至少有 `ciphertext.len() - TAG_SIZE` 字节
    ///
    /// # 返回
    /// - `Ok(usize)`: 写入的字节数（ciphertext.len() - TAG_SIZE）
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
        let mut ciphertext = vec![0u8; Self::sealed_size(plaintext.len())];
        let len = Self::seal_to_with_aad(key, nonce, plaintext, aad, &mut ciphertext)?;
        ciphertext.truncate(len);
        Ok(ciphertext)
    }

    /// 加密并认证数据到提供的缓冲区，支持附加认证数据(AAD)（零分配）
    ///
    /// # 参数
    /// - `ciphertext`: 必须至少有 `plaintext.len() + TAG_SIZE` 字节
    ///
    /// # 返回
    /// - `Ok(usize)`: 写入的字节数（plaintext.len() + TAG_SIZE）
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
        let mut plaintext = vec![0u8; ciphertext.len()];
        let len = Self::open_to_with_aad(key, nonce, ciphertext, aad, &mut plaintext)?;
        plaintext.truncate(len);
        Ok(plaintext)
    }

    /// 验证并解密数据到提供的缓冲区，支持附加认证数据(AAD)（零分配）
    ///
    /// # 参数
    /// - `plaintext`: 必须至少有 `ciphertext.len() - TAG_SIZE` 字节
    ///
    /// # 返回
    /// - `Ok(usize)`: 写入的字节数（ciphertext.len() - TAG_SIZE）
    fn open_to_with_aad(
        key: &Self::Key,
        nonce: &Self::Nonce,
        ciphertext: &[u8],
        aad: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize>;
}

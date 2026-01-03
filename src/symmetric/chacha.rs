use crate::error::{CryptoKitError, Result};
use crate::symmetric::AuthenticatedCipher;

// ChaCha20-Poly1305 Swift FFI 声明
extern "C" {
    #[link_name = "chacha20poly1305_encrypt"]
    fn swift_chacha20poly1305_encrypt(
        key: *const u8,
        key_len: i32,
        nonce: *const u8,
        nonce_len: i32,
        plaintext: *const u8,
        plaintext_len: i32,
        ciphertext: *mut u8,
        ciphertext_len: *mut i32,
    ) -> i32;

    #[link_name = "chacha20poly1305_decrypt"]
    fn swift_chacha20poly1305_decrypt(
        key: *const u8,
        key_len: i32,
        nonce: *const u8,
        nonce_len: i32,
        ciphertext: *const u8,
        ciphertext_len: i32,
        plaintext: *mut u8,
        plaintext_len: *mut i32,
    ) -> i32;

    #[link_name = "chacha20poly1305_encrypt_with_aad"]
    fn swift_chacha20poly1305_encrypt_with_aad(
        key: *const u8,
        key_len: i32,
        nonce: *const u8,
        nonce_len: i32,
        plaintext: *const u8,
        plaintext_len: i32,
        aad: *const u8,
        aad_len: i32,
        ciphertext: *mut u8,
        ciphertext_len: *mut i32,
    ) -> i32;

    #[link_name = "chacha20poly1305_decrypt_with_aad"]
    fn swift_chacha20poly1305_decrypt_with_aad(
        key: *const u8,
        key_len: i32,
        nonce: *const u8,
        nonce_len: i32,
        ciphertext: *const u8,
        ciphertext_len: i32,
        aad: *const u8,
        aad_len: i32,
        plaintext: *mut u8,
        plaintext_len: *mut i32,
    ) -> i32;

    #[link_name = "generate_chacha20poly1305_key"]
    fn swift_generate_chacha20poly1305_key(key_data: *mut u8) -> i32;

    #[link_name = "generate_chacha20poly1305_nonce"]
    fn swift_generate_chacha20poly1305_nonce(nonce_data: *mut u8) -> i32;
}

/// ChaCha20密钥 (32字节)
#[derive(Clone)]
pub struct ChaChaKey {
    pub(crate) bytes: [u8; 32],
}

impl ChaChaKey {
    /// 从字节数组创建ChaCha20密钥
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(CryptoKitError::InvalidKey);
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(bytes);
        Ok(Self { bytes: key_bytes })
    }

    /// 生成随机ChaCha20密钥
    pub fn generate() -> Result<Self> {
        unsafe {
            let mut bytes = [0u8; 32];
            let result = swift_generate_chacha20poly1305_key(bytes.as_mut_ptr());

            if result == 0 {
                Ok(Self { bytes })
            } else {
                Err(CryptoKitError::KeyGenerationFailed)
            }
        }
    }

    /// 获取密钥字节
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// ChaCha20-Poly1305 nonce (12字节)
#[derive(Clone)]
pub struct ChaChaPolyNonce {
    pub(crate) bytes: [u8; 12],
}

impl ChaChaPolyNonce {
    /// 从字节数组创建nonce
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 12 {
            return Err(CryptoKitError::InvalidNonce);
        }

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(bytes);
        Ok(Self { bytes: nonce_bytes })
    }

    /// 生成随机nonce
    pub fn generate() -> Result<Self> {
        unsafe {
            let mut bytes = [0u8; 12];
            let result = swift_generate_chacha20poly1305_nonce(bytes.as_mut_ptr());

            if result == 0 {
                Ok(Self { bytes })
            } else {
                Err(CryptoKitError::NonceGenerationFailed)
            }
        }
    }

    /// 获取nonce字节
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// ChaCha20-Poly1305 认证加密实现
pub struct ChaChaPoly;

impl AuthenticatedCipher for ChaChaPoly {
    type Key = ChaChaKey;
    type Nonce = ChaChaPolyNonce;

    fn seal(key: &Self::Key, nonce: &Self::Nonce, plaintext: &[u8]) -> Result<Vec<u8>> {
        unsafe {
            let mut ciphertext = vec![0u8; plaintext.len() + 16]; // plaintext + tag
            let mut ciphertext_len = 0i32;

            let result = swift_chacha20poly1305_encrypt(
                key.bytes.as_ptr(),
                key.bytes.len() as i32,
                nonce.bytes.as_ptr(),
                nonce.bytes.len() as i32,
                plaintext.as_ptr(),
                plaintext.len() as i32,
                ciphertext.as_mut_ptr(),
                &mut ciphertext_len,
            );

            if result == 0 {
                ciphertext.resize(ciphertext_len as usize, 0);
                Ok(ciphertext)
            } else {
                Err(CryptoKitError::EncryptionFailed)
            }
        }
    }

    fn open(key: &Self::Key, nonce: &Self::Nonce, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 16 {
            return Err(CryptoKitError::InvalidInput(
                "Ciphertext too short".to_string(),
            ));
        }

        unsafe {
            let mut plaintext = vec![0u8; ciphertext.len()];
            let mut plaintext_len = 0i32;

            let result = swift_chacha20poly1305_decrypt(
                key.bytes.as_ptr(),
                key.bytes.len() as i32,
                nonce.bytes.as_ptr(),
                nonce.bytes.len() as i32,
                ciphertext.as_ptr(),
                ciphertext.len() as i32,
                plaintext.as_mut_ptr(),
                &mut plaintext_len,
            );

            if result == 0 {
                plaintext.resize(plaintext_len as usize, 0);
                Ok(plaintext)
            } else {
                Err(CryptoKitError::DecryptionFailed)
            }
        }
    }

    fn seal_with_aad(
        key: &Self::Key,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        unsafe {
            let mut ciphertext = vec![0u8; plaintext.len() + 16];
            let mut ciphertext_len = 0i32;

            let result = swift_chacha20poly1305_encrypt_with_aad(
                key.bytes.as_ptr(),
                key.bytes.len() as i32,
                nonce.bytes.as_ptr(),
                nonce.bytes.len() as i32,
                plaintext.as_ptr(),
                plaintext.len() as i32,
                aad.as_ptr(),
                aad.len() as i32,
                ciphertext.as_mut_ptr(),
                &mut ciphertext_len,
            );

            if result == 0 {
                ciphertext.resize(ciphertext_len as usize, 0);
                Ok(ciphertext)
            } else {
                Err(CryptoKitError::EncryptionFailed)
            }
        }
    }

    fn open_with_aad(
        key: &Self::Key,
        nonce: &Self::Nonce,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        if ciphertext.len() < 16 {
            return Err(CryptoKitError::InvalidInput(
                "Ciphertext too short".to_string(),
            ));
        }

        unsafe {
            let mut plaintext = vec![0u8; ciphertext.len()];
            let mut plaintext_len = 0i32;

            let result = swift_chacha20poly1305_decrypt_with_aad(
                key.bytes.as_ptr(),
                key.bytes.len() as i32,
                nonce.bytes.as_ptr(),
                nonce.bytes.len() as i32,
                ciphertext.as_ptr(),
                ciphertext.len() as i32,
                aad.as_ptr(),
                aad.len() as i32,
                plaintext.as_mut_ptr(),
                &mut plaintext_len,
            );

            if result == 0 {
                plaintext.resize(plaintext_len as usize, 0);
                Ok(plaintext)
            } else {
                Err(CryptoKitError::DecryptionFailed)
            }
        }
    }
}

/// 便利函数：ChaCha20-Poly1305 加密
pub fn chacha20poly1305_encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let key = ChaChaKey::from_bytes(key)?;
    let nonce = ChaChaPolyNonce::from_bytes(nonce)?;
    ChaChaPoly::seal(&key, &nonce, plaintext)
}

/// 便利函数：ChaCha20-Poly1305 解密
pub fn chacha20poly1305_decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let key = ChaChaKey::from_bytes(key)?;
    let nonce = ChaChaPolyNonce::from_bytes(nonce)?;
    ChaChaPoly::open(&key, &nonce, ciphertext)
}

/// 便利函数：ChaCha20-Poly1305 带AAD加密
pub fn chacha20poly1305_encrypt_with_aad(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let key = ChaChaKey::from_bytes(key)?;
    let nonce = ChaChaPolyNonce::from_bytes(nonce)?;
    ChaChaPoly::seal_with_aad(&key, &nonce, plaintext, aad)
}

/// 便利函数：ChaCha20-Poly1305 带AAD解密
pub fn chacha20poly1305_decrypt_with_aad(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let key = ChaChaKey::from_bytes(key)?;
    let nonce = ChaChaPolyNonce::from_bytes(nonce)?;
    ChaChaPoly::open_with_aad(&key, &nonce, ciphertext, aad)
}

use crate::error::{CryptoKitError, Result};
use crate::symmetric::AuthenticatedCipher;

// AES-GCM Swift FFI 声明
extern "C" {
    #[link_name = "aes_gcm_encrypt"]
    fn swift_aes_gcm_encrypt(
        key: *const u8,
        key_len: i32,
        nonce: *const u8,
        nonce_len: i32,
        plaintext: *const u8,
        plaintext_len: i32,
        ciphertext: *mut u8,
        ciphertext_len: *mut i32,
    ) -> i32;

    #[link_name = "aes_gcm_decrypt"]
    fn swift_aes_gcm_decrypt(
        key: *const u8,
        key_len: i32,
        nonce: *const u8,
        nonce_len: i32,
        ciphertext: *const u8,
        ciphertext_len: i32,
        plaintext: *mut u8,
        plaintext_len: *mut i32,
    ) -> i32;

    #[link_name = "aes_gcm_encrypt_with_aad"]
    fn swift_aes_gcm_encrypt_with_aad(
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

    #[link_name = "aes_gcm_decrypt_with_aad"]
    fn swift_aes_gcm_decrypt_with_aad(
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

    #[link_name = "generate_symmetric_key"]
    fn swift_generate_symmetric_key(size_bits: i32, key_data: *mut u8) -> i32;

    #[link_name = "generate_aes_gcm_nonce"]
    fn swift_generate_aes_gcm_nonce(nonce_data: *mut u8) -> i32;
}

/// AES密钥
#[derive(Clone)]
pub struct AESKey {
    pub(crate) bytes: Vec<u8>,
}

impl AESKey {
    /// 从字节数组创建AES密钥
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        match bytes.len() {
            16 | 24 | 32 => Ok(Self {
                bytes: bytes.to_vec(),
            }),
            _ => Err(CryptoKitError::InvalidKey),
        }
    }

    /// 生成随机AES密钥
    pub fn generate(size: AESKeySize) -> Result<Self> {
        let len = match size {
            AESKeySize::AES128 => 16,
            AESKeySize::AES192 => 24,
            AESKeySize::AES256 => 32,
        };

        unsafe {
            let mut bytes = vec![0u8; len];
            let result = swift_generate_symmetric_key(
                (len * 8) as i32, // 位数
                bytes.as_mut_ptr(),
            );

            if result == 0 {
                Ok(Self { bytes })
            } else {
                Err(CryptoKitError::KeyGenerationFailed)
            }
        }
    }
}

/// AES密钥大小
#[derive(Debug, Clone, Copy)]
pub enum AESKeySize {
    AES128,
    AES192,
    AES256,
}

/// AES-GCM nonce
#[derive(Clone)]
pub struct AESGCMNonce {
    pub(crate) bytes: [u8; 12],
}

impl AESGCMNonce {
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
            let result = swift_generate_aes_gcm_nonce(bytes.as_mut_ptr());

            if result == 0 {
                Ok(Self { bytes })
            } else {
                Err(CryptoKitError::NonceGenerationFailed)
            }
        }
    }
}

/// AES-GCM 认证加密实现
pub struct AesGcm;

impl AuthenticatedCipher for AesGcm {
    type Key = AESKey;
    type Nonce = AESGCMNonce;

    fn seal(key: &Self::Key, nonce: &Self::Nonce, plaintext: &[u8]) -> Result<Vec<u8>> {
        unsafe {
            let mut ciphertext = vec![0u8; plaintext.len() + 16]; // plaintext + tag
            let mut ciphertext_len = 0i32;

            let result = swift_aes_gcm_encrypt(
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

            let result = swift_aes_gcm_decrypt(
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

            let result = swift_aes_gcm_encrypt_with_aad(
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

            let result = swift_aes_gcm_decrypt_with_aad(
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

/// 便利函数：AES-GCM 加密
pub fn aes_gcm_encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let key = AESKey::from_bytes(key)?;
    let nonce = AESGCMNonce::from_bytes(nonce)?;
    AesGcm::seal(&key, &nonce, plaintext)
}

/// 便利函数：AES-GCM 解密
pub fn aes_gcm_decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let key = AESKey::from_bytes(key)?;
    let nonce = AESGCMNonce::from_bytes(nonce)?;
    AesGcm::open(&key, &nonce, ciphertext)
}

/// 便利函数：AES-GCM 带AAD加密
pub fn aes_gcm_encrypt_with_aad(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let key = AESKey::from_bytes(key)?;
    let nonce = AESGCMNonce::from_bytes(nonce)?;
    AesGcm::seal_with_aad(&key, &nonce, plaintext, aad)
}

/// 便利函数：AES-GCM 带AAD解密
pub fn aes_gcm_decrypt_with_aad(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let key = AESKey::from_bytes(key)?;
    let nonce = AESGCMNonce::from_bytes(nonce)?;
    AesGcm::open_with_aad(&key, &nonce, ciphertext, aad)
}

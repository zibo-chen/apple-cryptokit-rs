use crate::error::Result;

pub mod aes;
pub mod chacha;

/// Generic trait for cipher algorithms
pub trait Cipher {
    type Key;
    type Nonce;

    /// Authentication tag size (bytes)
    const TAG_SIZE: usize;

    /// Calculate encrypted output size
    fn encrypted_size(plaintext_len: usize) -> usize {
        plaintext_len + Self::TAG_SIZE
    }

    /// Calculate decrypted output size
    fn decrypted_size(ciphertext_len: usize) -> Option<usize> {
        ciphertext_len.checked_sub(Self::TAG_SIZE)
    }

    /// Encrypt data
    fn encrypt(key: &Self::Key, nonce: &Self::Nonce, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut ciphertext = vec![0u8; Self::encrypted_size(plaintext.len())];
        let len = Self::encrypt_to(key, nonce, plaintext, &mut ciphertext)?;
        ciphertext.truncate(len);
        Ok(ciphertext)
    }

    /// Encrypt data to provided buffer (zero-allocation)
    ///
    /// # Parameters
    /// - `output`: Must be at least `plaintext.len() + TAG_SIZE` bytes
    ///
    /// # Returns
    /// - `Ok(usize)`: Bytes written
    fn encrypt_to(
        key: &Self::Key,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize>;

    /// Decrypt data
    fn decrypt(key: &Self::Key, nonce: &Self::Nonce, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut plaintext = vec![0u8; ciphertext.len()];
        let len = Self::decrypt_to(key, nonce, ciphertext, &mut plaintext)?;
        plaintext.truncate(len);
        Ok(plaintext)
    }

    /// Decrypt data to provided buffer (zero-allocation)
    ///
    /// # Parameters
    /// - `output`: Must be at least `ciphertext.len() - TAG_SIZE` bytes
    ///
    /// # Returns
    /// - `Ok(usize)`: Bytes written
    fn decrypt_to(
        key: &Self::Key,
        nonce: &Self::Nonce,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize>;
}

/// Trait for authenticated encryption algorithms (AEAD - Authenticated Encryption with Associated Data)
pub trait AuthenticatedCipher {
    type Key;
    type Nonce;

    /// Authentication tag size (bytes)
    const TAG_SIZE: usize;

    /// Calculate sealed output size
    fn sealed_size(plaintext_len: usize) -> usize {
        plaintext_len + Self::TAG_SIZE
    }

    /// Calculate opened output size
    fn opened_size(ciphertext_len: usize) -> Option<usize> {
        ciphertext_len.checked_sub(Self::TAG_SIZE)
    }

    /// Encrypt and authenticate data
    fn seal(key: &Self::Key, nonce: &Self::Nonce, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut ciphertext = vec![0u8; Self::sealed_size(plaintext.len())];
        let len = Self::seal_to(key, nonce, plaintext, &mut ciphertext)?;
        ciphertext.truncate(len);
        Ok(ciphertext)
    }

    /// Encrypt and authenticate data to provided buffer (zero-allocation)
    ///
    /// # Parameters
    /// - `ciphertext`: Must be at least `plaintext.len() + TAG_SIZE` bytes
    ///
    /// # Returns
    /// - `Ok(usize)`: Bytes written (plaintext.len() + TAG_SIZE)
    fn seal_to(
        key: &Self::Key,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize>;

    /// Verify and decrypt data
    fn open(key: &Self::Key, nonce: &Self::Nonce, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut plaintext = vec![0u8; ciphertext.len()];
        let len = Self::open_to(key, nonce, ciphertext, &mut plaintext)?;
        plaintext.truncate(len);
        Ok(plaintext)
    }

    /// Verify and decrypt data to provided buffer (zero-allocation)
    ///
    /// # Parameters
    /// - `plaintext`: Must be at least `ciphertext.len() - TAG_SIZE` bytes
    ///
    /// # Returns
    /// - `Ok(usize)`: Bytes written (ciphertext.len() - TAG_SIZE)
    fn open_to(
        key: &Self::Key,
        nonce: &Self::Nonce,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize>;

    /// Encrypt and authenticate data with additional authenticated data (AAD)
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

    /// Encrypt and authenticate data to provided buffer with additional authenticated data (AAD) (zero-allocation)
    ///
    /// # Parameters
    /// - `ciphertext`: Must be at least `plaintext.len() + TAG_SIZE` bytes
    ///
    /// # Returns
    /// - `Ok(usize)`: Bytes written (plaintext.len() + TAG_SIZE)
    fn seal_to_with_aad(
        key: &Self::Key,
        nonce: &Self::Nonce,
        plaintext: &[u8],
        aad: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize>;

    /// Verify and decrypt data with additional authenticated data (AAD)
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

    /// Verify and decrypt data to provided buffer with additional authenticated data (AAD) (zero-allocation)
    ///
    /// # Parameters
    /// - `plaintext`: Must be at least `ciphertext.len() - TAG_SIZE` bytes
    ///
    /// # Returns
    /// - `Ok(usize)`: Bytes written (ciphertext.len() - TAG_SIZE)
    fn open_to_with_aad(
        key: &Self::Key,
        nonce: &Self::Nonce,
        ciphertext: &[u8],
        aad: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize>;
}

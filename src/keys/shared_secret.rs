use crate::error::{CryptoKitError, Result};
use crate::keys::symmetric::{SymmetricKey, SymmetricKeySize};

// Shared secret Swift FFI declarations
unsafe extern "C" {
    #[link_name = "shared_secret_hkdf_derive_key"]
    fn swift_shared_secret_hkdf_derive_key(
        secret: *const u8,
        secret_len: i32,
        salt: *const u8,
        salt_len: i32,
        info: *const u8,
        info_len: i32,
        output_len: i32,
        output: *mut u8,
    ) -> i32;

    #[link_name = "shared_secret_x963_derive_key"]
    fn swift_shared_secret_x963_derive_key(
        secret: *const u8,
        secret_len: i32,
        shared_info: *const u8,
        shared_info_len: i32,
        output_len: i32,
        output: *mut u8,
    ) -> i32;
}

/// Shared secret trait definition
///
/// Defines the basic functionality that a shared secret should have
pub trait SharedSecret {
    /// Derive a symmetric key from the shared secret using HKDF-SHA256
    fn hkdf_derive_key(
        &self,
        salt: &[u8],
        info: &[u8],
        output_byte_count: usize,
    ) -> Result<SymmetricKey>;

    /// Derive a symmetric key from the shared secret using X9.63 KDF
    fn x963_derive_key(&self, shared_info: &[u8], output_byte_count: usize)
        -> Result<SymmetricKey>;

    /// Get the byte representation of the shared secret
    fn as_bytes(&self) -> &[u8];
}

/// Concrete implementation of shared secret
///
/// Corresponds to Apple CryptoKit's SharedSecret, typically obtained from key exchange algorithms
#[derive(Clone)]
pub struct SharedSecretImpl {
    bytes: Vec<u8>,
}

impl SharedSecretImpl {
    /// Create a shared secret from byte data
    ///
    /// # Arguments
    /// * `data` - The byte data of the shared secret
    ///
    /// # Returns
    /// A new shared secret instance
    pub fn from_data(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(CryptoKitError::InvalidInput(
                "Shared secret data cannot be empty".to_string(),
            ));
        }

        Ok(Self {
            bytes: data.to_vec(),
        })
    }

    /// Get the byte length of the shared secret
    pub fn byte_count(&self) -> usize {
        self.bytes.len()
    }

    /// Compare two shared secrets for equality
    ///
    /// Uses constant-time comparison to avoid timing attacks
    pub fn equals(&self, other: &Self) -> bool {
        if self.bytes.len() != other.bytes.len() {
            return false;
        }

        // Constant-time comparison
        let mut result = 0u8;
        for (a, b) in self.bytes.iter().zip(other.bytes.iter()) {
            result |= a ^ b;
        }
        result == 0
    }
}

impl SharedSecret for SharedSecretImpl {
    /// Derive a symmetric key from the shared secret using HKDF-SHA256
    ///
    /// # Arguments
    /// * `salt` - Salt value (can be empty)
    /// * `info` - Context information (can be empty)
    /// * `output_byte_count` - Byte length of the output key
    ///
    /// # Returns
    /// The derived symmetric key
    fn hkdf_derive_key(
        &self,
        salt: &[u8],
        info: &[u8],
        output_byte_count: usize,
    ) -> Result<SymmetricKey> {
        // Validate output length
        let _size = SymmetricKeySize::from_byte_count(output_byte_count)?;

        unsafe {
            let mut output = vec![0u8; output_byte_count];

            let result = swift_shared_secret_hkdf_derive_key(
                self.bytes.as_ptr(),
                self.bytes.len() as i32,
                salt.as_ptr(),
                salt.len() as i32,
                info.as_ptr(),
                info.len() as i32,
                output_byte_count as i32,
                output.as_mut_ptr(),
            );

            if result == 0 {
                SymmetricKey::from_data(&output)
            } else {
                Err(CryptoKitError::DerivationFailed)
            }
        }
    }

    /// Derive a symmetric key from the shared secret using X9.63 KDF
    ///
    /// # Arguments
    /// * `shared_info` - Shared information (can be empty)
    /// * `output_byte_count` - Byte length of the output key
    ///
    /// # Returns
    /// The derived symmetric key
    fn x963_derive_key(
        &self,
        shared_info: &[u8],
        output_byte_count: usize,
    ) -> Result<SymmetricKey> {
        // Validate output length
        let _size = SymmetricKeySize::from_byte_count(output_byte_count)?;

        unsafe {
            let mut output = vec![0u8; output_byte_count];

            let result = swift_shared_secret_x963_derive_key(
                self.bytes.as_ptr(),
                self.bytes.len() as i32,
                shared_info.as_ptr(),
                shared_info.len() as i32,
                output_byte_count as i32,
                output.as_mut_ptr(),
            );

            if result == 0 {
                SymmetricKey::from_data(&output)
            } else {
                Err(CryptoKitError::DerivationFailed)
            }
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl PartialEq for SharedSecretImpl {
    fn eq(&self, other: &Self) -> bool {
        self.equals(other)
    }
}

impl Eq for SharedSecretImpl {}

impl std::fmt::Debug for SharedSecretImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedSecret")
            .field("byte_count", &self.byte_count())
            .finish_non_exhaustive() // Don't display actual key data to prevent accidental leakage
    }
}

// Prevent accidental leakage of key data
impl Drop for SharedSecretImpl {
    fn drop(&mut self) {
        // Zero out key data
        for byte in &mut self.bytes {
            *byte = 0;
        }
    }
}

// Ensure shared secret cannot be accidentally displayed
impl std::fmt::Display for SharedSecretImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SharedSecret({} bytes)", self.byte_count())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shared_secret_creation() {
        let data = vec![1u8; 32];
        let secret = SharedSecretImpl::from_data(&data).unwrap();
        assert_eq!(secret.byte_count(), 32);
        assert_eq!(secret.as_bytes(), &data);
    }

    #[test]
    fn test_shared_secret_empty_data() {
        let empty_data = vec![];
        let result = SharedSecretImpl::from_data(&empty_data);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            CryptoKitError::InvalidInput("Shared secret data cannot be empty".to_string())
        );
    }

    #[test]
    fn test_shared_secret_equality() {
        let data1 = vec![1u8; 32];
        let data2 = vec![1u8; 32];
        let data3 = vec![2u8; 32];

        let secret1 = SharedSecretImpl::from_data(&data1).unwrap();
        let secret2 = SharedSecretImpl::from_data(&data2).unwrap();
        let secret3 = SharedSecretImpl::from_data(&data3).unwrap();

        assert!(secret1.equals(&secret2));
        assert!(!secret1.equals(&secret3));
        assert_eq!(secret1, secret2);
        assert_ne!(secret1, secret3);
    }
}

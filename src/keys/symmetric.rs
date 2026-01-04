use crate::error::{CryptoKitError, Result};

// Symmetric key management Swift FFI declarations
unsafe extern "C" {
    #[link_name = "symmetric_key_generate"]
    fn swift_symmetric_key_generate(size: i32, output: *mut u8) -> i32;

    #[link_name = "symmetric_key_from_data"]
    fn swift_symmetric_key_from_data(data: *const u8, len: i32, output: *mut u8) -> i32;
}

/// Symmetric key size enumeration
///
/// Supports common symmetric key lengths, corresponding to Apple CryptoKit's SymmetricKeySize
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymmetricKeySize {
    /// 128-bit (16 bytes) - suitable for AES-128
    Bits128,
    /// 192-bit (24 bytes) - suitable for AES-192
    Bits192,
    /// 256-bit (32 bytes) - suitable for AES-256, ChaCha20
    Bits256,
}

impl SymmetricKeySize {
    /// Get key length (bytes)
    pub fn byte_count(&self) -> usize {
        match self {
            SymmetricKeySize::Bits128 => 16,
            SymmetricKeySize::Bits192 => 24,
            SymmetricKeySize::Bits256 => 32,
        }
    }

    /// Get key length (bits)
    pub fn bit_count(&self) -> usize {
        self.byte_count() * 8
    }

    /// Create SymmetricKeySize from byte count
    pub fn from_byte_count(bytes: usize) -> Result<Self> {
        match bytes {
            16 => Ok(SymmetricKeySize::Bits128),
            24 => Ok(SymmetricKeySize::Bits192),
            32 => Ok(SymmetricKeySize::Bits256),
            _ => Err(CryptoKitError::InvalidLength),
        }
    }

    /// Create SymmetricKeySize from bit count
    pub fn from_bit_count(bits: usize) -> Result<Self> {
        match bits {
            128 => Ok(SymmetricKeySize::Bits128),
            192 => Ok(SymmetricKeySize::Bits192),
            256 => Ok(SymmetricKeySize::Bits256),
            _ => Err(CryptoKitError::InvalidLength),
        }
    }
}

/// Symmetric key wrapper
///
/// Provides secure symmetric key management, corresponding to Apple CryptoKit's SymmetricKey
#[derive(Clone)]
pub struct SymmetricKey {
    bytes: Vec<u8>,
    size: SymmetricKeySize,
}

impl SymmetricKey {
    /// Generate a random symmetric key of the specified size
    ///
    /// # Arguments
    /// * `size` - Key size
    ///
    /// # Returns
    /// New random symmetric key
    pub fn generate(size: SymmetricKeySize) -> Result<Self> {
        let byte_count = size.byte_count();

        unsafe {
            let mut output = vec![0u8; byte_count];
            let result = swift_symmetric_key_generate(byte_count as i32, output.as_mut_ptr());

            if result == 0 {
                Ok(Self {
                    bytes: output,
                    size,
                })
            } else {
                Err(CryptoKitError::KeyGenerationFailed)
            }
        }
    }

    /// Create symmetric key from byte data
    ///
    /// # Arguments
    /// * `data` - Key data bytes
    ///
    /// # Returns
    /// New symmetric key
    pub fn from_data(data: &[u8]) -> Result<Self> {
        let size = SymmetricKeySize::from_byte_count(data.len())?;

        unsafe {
            let mut output = vec![0u8; data.len()];
            let result = swift_symmetric_key_from_data(
                data.as_ptr(),
                data.len() as i32,
                output.as_mut_ptr(),
            );

            if result == 0 {
                Ok(Self {
                    bytes: output,
                    size,
                })
            } else {
                Err(CryptoKitError::InvalidKey)
            }
        }
    }

    /// Get a reference to the key byte data
    ///
    /// Note: This method returns the raw bytes of the key, use with caution to avoid leakage
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get key size enumeration value
    pub fn size(&self) -> SymmetricKeySize {
        self.size
    }

    /// Get key length (bytes)
    pub fn byte_count(&self) -> usize {
        self.bytes.len()
    }

    /// Get key length (bits)
    pub fn bit_count(&self) -> usize {
        self.bytes.len() * 8
    }

    /// Securely access key byte data
    ///
    /// Provides a callback function to access key bytes, similar to Apple CryptoKit's withUnsafeBytes
    ///
    /// # Arguments
    /// * `callback` - Callback function to process key bytes
    pub fn with_unsafe_bytes<F, R>(&self, callback: F) -> Result<R>
    where
        F: FnOnce(&[u8]) -> R,
    {
        // Directly call the callback function since we already have the byte data
        Ok(callback(&self.bytes))
    }

    /// Compare if two keys are equal
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

impl PartialEq for SymmetricKey {
    fn eq(&self, other: &Self) -> bool {
        self.equals(other)
    }
}

impl Eq for SymmetricKey {}

impl std::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SymmetricKey")
            .field("size", &self.size)
            .field("byte_count", &self.byte_count())
            .finish_non_exhaustive() // Do not show actual key data to prevent accidental leakage
    }
}

// Prevent accidental key data leakage
impl Drop for SymmetricKey {
    fn drop(&mut self) {
        // Zero out key data
        for byte in &mut self.bytes {
            *byte = 0;
        }
    }
}

// Ensure key cannot be accidentally displayed
impl std::fmt::Display for SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SymmetricKey({})", self.size.bit_count())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symmetric_key_size() {
        assert_eq!(SymmetricKeySize::Bits128.byte_count(), 16);
        assert_eq!(SymmetricKeySize::Bits192.byte_count(), 24);
        assert_eq!(SymmetricKeySize::Bits256.byte_count(), 32);

        assert_eq!(SymmetricKeySize::Bits128.bit_count(), 128);
        assert_eq!(SymmetricKeySize::Bits192.bit_count(), 192);
        assert_eq!(SymmetricKeySize::Bits256.bit_count(), 256);
    }

    #[test]
    fn test_symmetric_key_size_from_bytes() {
        assert_eq!(
            SymmetricKeySize::from_byte_count(16).unwrap(),
            SymmetricKeySize::Bits128
        );
        assert_eq!(
            SymmetricKeySize::from_byte_count(24).unwrap(),
            SymmetricKeySize::Bits192
        );
        assert_eq!(
            SymmetricKeySize::from_byte_count(32).unwrap(),
            SymmetricKeySize::Bits256
        );

        assert!(SymmetricKeySize::from_byte_count(15).is_err());
        assert!(SymmetricKeySize::from_byte_count(17).is_err());
    }

    #[test]
    fn test_symmetric_key_size_from_bits() {
        assert_eq!(
            SymmetricKeySize::from_bit_count(128).unwrap(),
            SymmetricKeySize::Bits128
        );
        assert_eq!(
            SymmetricKeySize::from_bit_count(192).unwrap(),
            SymmetricKeySize::Bits192
        );
        assert_eq!(
            SymmetricKeySize::from_bit_count(256).unwrap(),
            SymmetricKeySize::Bits256
        );

        assert!(SymmetricKeySize::from_bit_count(127).is_err());
        assert!(SymmetricKeySize::from_bit_count(129).is_err());
    }
}

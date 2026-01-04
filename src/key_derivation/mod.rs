use crate::error::{CryptoKitError, Result};

pub mod hkdf_sha256;
pub mod hkdf_sha384;
pub mod hkdf_sha512;

/// Hash algorithm enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA256 hash algorithm
    SHA256,
    /// SHA384 hash algorithm
    SHA384,
    /// SHA512 hash algorithm
    SHA512,
}

impl HashAlgorithm {
    /// Get the output length of the hash algorithm (in bytes)
    pub fn output_length(&self) -> usize {
        match self {
            HashAlgorithm::SHA256 => 32,
            HashAlgorithm::SHA384 => 48,
            HashAlgorithm::SHA512 => 64,
        }
    }

    /// Get the maximum output length of HKDF (255 * hash_length)
    pub fn max_hkdf_output_length(&self) -> usize {
        255 * self.output_length()
    }
}

/// Generic trait for key derivation functions
pub trait KeyDerivationFunction {
    /// Derive key from input key material
    fn derive(
        input_key_material: &[u8],
        salt: &[u8],
        info: &[u8],
        output_length: usize,
    ) -> Result<Vec<u8>> {
        let mut output = vec![0u8; output_length];
        Self::derive_to(input_key_material, salt, info, &mut output)?;
        Ok(output)
    }

    /// Derive key from input key material to the provided buffer (zero-allocation)
    ///
    /// # Parameters
    /// - `output`: Buffer whose length determines the length of the derived key
    ///
    /// # Returns
    /// Number of bytes written (same as output.len())
    fn derive_to(
        input_key_material: &[u8],
        salt: &[u8],
        info: &[u8],
        output: &mut [u8],
    ) -> Result<usize>;
}

/// Generic HKDF implementation
pub struct HKDF;

impl HKDF {
    /// Perform HKDF key derivation using the specified hash algorithm
    ///
    /// # Parameters
    /// * `algorithm` - The hash algorithm to use
    /// * `input_key_material` - Input Key Material (IKM)
    /// * `salt` - Optional salt value, recommended to use a random value
    /// * `info` - Optional context and application-specific information
    /// * `output_length` - Desired output key length
    ///
    /// # Returns
    /// Derived key data
    ///
    /// # Errors
    /// * `CryptoKitError::InvalidInput` - If the input key material is empty
    /// * `CryptoKitError::InvalidLength` - If the output length is invalid
    /// * `CryptoKitError::DerivationFailed` - If key derivation fails
    ///
    /// # Example
    /// ```rust,no_run
    /// use apple_cryptokit::key_derivation::{HKDF, HashAlgorithm};
    ///
    /// let ikm = b"input key material";
    /// let salt = b"optional salt";
    /// let info = b"application context";
    ///
    /// let derived_key = HKDF::derive_key(
    ///     HashAlgorithm::SHA256,
    ///     ikm,
    ///     salt,
    ///     info,
    ///     32
    /// ).unwrap();
    /// ```
    pub fn derive_key(
        algorithm: HashAlgorithm,
        input_key_material: &[u8],
        salt: &[u8],
        info: &[u8],
        output_length: usize,
    ) -> Result<Vec<u8>> {
        // Validate input parameters
        if input_key_material.is_empty() {
            return Err(CryptoKitError::InvalidInput(
                "Input key material cannot be empty".to_string(),
            ));
        }

        if output_length == 0 || output_length > algorithm.max_hkdf_output_length() {
            return Err(CryptoKitError::InvalidLength);
        }

        match algorithm {
            HashAlgorithm::SHA256 => {
                hkdf_sha256::HKDF_SHA256::derive(input_key_material, salt, info, output_length)
            }
            HashAlgorithm::SHA384 => {
                hkdf_sha384::HKDF_SHA384::derive(input_key_material, salt, info, output_length)
            }
            HashAlgorithm::SHA512 => {
                hkdf_sha512::HKDF_SHA512::derive(input_key_material, salt, info, output_length)
            }
        }
    }

    /// Perform HKDF key derivation to the provided buffer using the specified hash algorithm (zero-allocation)
    ///
    /// # Parameters
    /// * `algorithm` - The hash algorithm to use
    /// * `input_key_material` - Input Key Material (IKM)
    /// * `salt` - Optional salt value, recommended to use a random value
    /// * `info` - Optional context and application-specific information
    /// * `output` - Output buffer whose length determines the length of the derived key
    ///
    /// # Returns
    /// Number of bytes written to output
    pub fn derive_key_to(
        algorithm: HashAlgorithm,
        input_key_material: &[u8],
        salt: &[u8],
        info: &[u8],
        output: &mut [u8],
    ) -> Result<usize> {
        // Validate input parameters
        if input_key_material.is_empty() {
            return Err(CryptoKitError::InvalidInput(
                "Input key material cannot be empty".to_string(),
            ));
        }

        let output_length = output.len();
        if output_length == 0 || output_length > algorithm.max_hkdf_output_length() {
            return Err(CryptoKitError::InvalidLength);
        }

        match algorithm {
            HashAlgorithm::SHA256 => {
                hkdf_sha256::HKDF_SHA256::derive_to(input_key_material, salt, info, output)
            }
            HashAlgorithm::SHA384 => {
                hkdf_sha384::HKDF_SHA384::derive_to(input_key_material, salt, info, output)
            }
            HashAlgorithm::SHA512 => {
                hkdf_sha512::HKDF_SHA512::derive_to(input_key_material, salt, info, output)
            }
        }
    }

    /// Convenience method: HKDF key derivation using SHA256
    pub fn derive_key_sha256(
        input_key_material: &[u8],
        salt: &[u8],
        info: &[u8],
        output_length: usize,
    ) -> Result<Vec<u8>> {
        Self::derive_key(
            HashAlgorithm::SHA256,
            input_key_material,
            salt,
            info,
            output_length,
        )
    }

    /// Convenience method: HKDF key derivation using SHA384
    pub fn derive_key_sha384(
        input_key_material: &[u8],
        salt: &[u8],
        info: &[u8],
        output_length: usize,
    ) -> Result<Vec<u8>> {
        Self::derive_key(
            HashAlgorithm::SHA384,
            input_key_material,
            salt,
            info,
            output_length,
        )
    }

    /// Convenience method: HKDF key derivation using SHA512
    pub fn derive_key_sha512(
        input_key_material: &[u8],
        salt: &[u8],
        info: &[u8],
        output_length: usize,
    ) -> Result<Vec<u8>> {
        Self::derive_key(
            HashAlgorithm::SHA512,
            input_key_material,
            salt,
            info,
            output_length,
        )
    }

    /// Derive symmetric key from shared secret
    ///
    /// This is a convenience method for deriving symmetric encryption keys from shared secrets
    /// obtained from operations such as elliptic curve key agreement
    ///
    /// # Parameters
    /// * `shared_secret` - Shared secret data
    /// * `algorithm` - Hash algorithm
    /// * `salt` - Optional salt value
    /// * `info` - Application context information
    /// * `output_length` - Output key length
    pub fn derive_symmetric_key(
        shared_secret: &[u8],
        algorithm: HashAlgorithm,
        salt: Option<&[u8]>,
        info: &[u8],
        output_length: usize,
    ) -> Result<Vec<u8>> {
        let salt = salt.unwrap_or(&[]);
        Self::derive_key(algorithm, shared_secret, salt, info, output_length)
    }
}

/// HKDF-SHA256 key derivation implementation (re-exported)
pub use hkdf_sha256::HKDF_SHA256;

/// HKDF-SHA384 key derivation implementation (re-export)
pub use hkdf_sha384::HKDF_SHA384;

/// HKDF-SHA512 key derivation implementation (re-export)
pub use hkdf_sha512::HKDF_SHA512;

// ============================================================================
// Convenience functions
// ============================================================================

/// Convenience function: HKDF-SHA256 key derivation
///
/// # Parameters
/// * `input_key_material` - Input key material
/// * `salt` - Salt value (optional, recommended)
/// * `info` - Application-specific information (optional)
/// * `output_length` - Output key length
///
/// # Example
/// ```rust,no_run
/// use apple_cryptokit::key_derivation::hkdf_sha256_derive;
///
/// let ikm = b"input key material";
/// let salt = b"optional salt";
/// let info = b"application context";
///
/// let derived_key = hkdf_sha256_derive(ikm, salt, info, 32).unwrap();
/// ```
pub fn hkdf_sha256_derive(
    input_key_material: &[u8],
    salt: &[u8],
    info: &[u8],
    output_length: usize,
) -> Result<Vec<u8>> {
    hkdf_sha256::hkdf_sha256_derive(input_key_material, salt, info, output_length)
}

/// Convenience function: HKDF-SHA384 key derivation
///
/// # Parameters
/// * `input_key_material` - Input key material
/// * `salt` - Salt value (optional, recommended)
/// * `info` - Application-specific information (optional)
/// * `output_length` - Output key length
pub fn hkdf_sha384_derive(
    input_key_material: &[u8],
    salt: &[u8],
    info: &[u8],
    output_length: usize,
) -> Result<Vec<u8>> {
    hkdf_sha384::hkdf_sha384_derive(input_key_material, salt, info, output_length)
}

/// Convenience function: HKDF-SHA512 key derivation
///
/// # Parameters
/// * `input_key_material` - Input key material
/// * `salt` - Salt value (optional, recommended)
/// * `info` - Application-specific information (optional)
/// * `output_length` - Output key length
pub fn hkdf_sha512_derive(
    input_key_material: &[u8],
    salt: &[u8],
    info: &[u8],
    output_length: usize,
) -> Result<Vec<u8>> {
    hkdf_sha512::hkdf_sha512_derive(input_key_material, salt, info, output_length)
}

// ============================================================================
// Predefined common key lengths
// ============================================================================

/// Common symmetric key length definitions
pub mod key_sizes {
    /// AES-128 key length (16 bytes)
    pub const AES_128: usize = 16;
    /// AES-192 key length (24 bytes)
    pub const AES_192: usize = 24;
    /// AES-256 key length (32 bytes)
    pub const AES_256: usize = 32;
    /// ChaCha20 key length (32 bytes)
    pub const CHACHA20: usize = 32;
    /// HMAC-SHA256 recommended key length (32 bytes)
    pub const HMAC_SHA256: usize = 32;
    /// HMAC-SHA384 recommended key length (48 bytes)
    pub const HMAC_SHA384: usize = 48;
    /// HMAC-SHA512 recommended key length (64 bytes)
    pub const HMAC_SHA512: usize = 64;
}

// ============================================================================
// Test module
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_algorithm_properties() {
        assert_eq!(HashAlgorithm::SHA256.output_length(), 32);
        assert_eq!(HashAlgorithm::SHA384.output_length(), 48);
        assert_eq!(HashAlgorithm::SHA512.output_length(), 64);

        assert_eq!(HashAlgorithm::SHA256.max_hkdf_output_length(), 255 * 32);
        assert_eq!(HashAlgorithm::SHA384.max_hkdf_output_length(), 255 * 48);
        assert_eq!(HashAlgorithm::SHA512.max_hkdf_output_length(), 255 * 64);
    }

    #[test]
    fn test_invalid_input_validation() {
        // Test empty input key material
        let result = HKDF::derive_key(HashAlgorithm::SHA256, &[], b"salt", b"info", 32);
        assert!(matches!(result, Err(CryptoKitError::InvalidInput(_))));

        // Test zero output length
        let result = HKDF::derive_key(HashAlgorithm::SHA256, b"ikm", b"salt", b"info", 0);
        assert!(matches!(result, Err(CryptoKitError::InvalidLength)));

        // Test excessive output length
        let result = HKDF::derive_key(
            HashAlgorithm::SHA256,
            b"ikm",
            b"salt",
            b"info",
            255 * 32 + 1,
        );
        assert!(matches!(result, Err(CryptoKitError::InvalidLength)));
    }
}

use super::KeyDerivationFunction;
use crate::error::{CryptoKitError, Result};

// HKDF-SHA256 Swift FFI declarations
extern "C" {
    #[link_name = "hkdf_sha256_derive"]
    fn swift_hkdf_sha256_derive(
        input_key: *const u8,
        input_key_len: i32,
        salt: *const u8,
        salt_len: i32,
        info: *const u8,
        info_len: i32,
        output_length: i32,
        output: *mut u8,
    ) -> i32;
}

/// HKDF-SHA256 key derivation implementation
#[allow(non_camel_case_types)]
pub struct HKDF_SHA256;

impl HKDF_SHA256 {
    /// Derive key from input key material using SHA256 hash algorithm
    ///
    /// # Parameters
    /// * `input_key_material` - Input key material
    /// * `salt` - Salt value (optional, recommended)
    /// * `info` - Application-specific information (optional)
    /// * `output_length` - Output key length
    ///
    /// # Returns
    /// Derived key data
    ///
    /// # Errors
    /// Returns `CryptoKitError::DerivationFailed` if key derivation fails
    ///
    /// # Example
    /// ```rust,no_run
    /// use apple_cryptokit::key_derivation::hkdf_sha256::HKDF_SHA256;
    /// use apple_cryptokit::key_derivation::KeyDerivationFunction;
    ///
    /// let ikm = b"input key material";
    /// let salt = b"optional salt";
    /// let info = b"application context";
    ///
    /// let derived_key = HKDF_SHA256::derive(ikm, salt, info, 32).unwrap();
    /// ```
    pub fn derive_key(
        input_key_material: &[u8],
        salt: &[u8],
        info: &[u8],
        output_length: usize,
    ) -> Result<Vec<u8>> {
        Self::derive(input_key_material, salt, info, output_length)
    }
}

impl KeyDerivationFunction for HKDF_SHA256 {
    fn derive_to(
        input_key_material: &[u8],
        salt: &[u8],
        info: &[u8],
        output: &mut [u8],
    ) -> Result<()> {
        if input_key_material.is_empty() {
            return Err(CryptoKitError::InvalidInput(
                "Input key material cannot be empty".to_string(),
            ));
        }

        let output_length = output.len();
        if output_length == 0 || output_length > 255 * 32 {
            // SHA256 outputs 32 bytes, maximum 255 output blocks
            return Err(CryptoKitError::InvalidLength);
        }

        unsafe {
            let result = swift_hkdf_sha256_derive(
                input_key_material.as_ptr(),
                input_key_material.len() as i32,
                salt.as_ptr(),
                salt.len() as i32,
                info.as_ptr(),
                info.len() as i32,
                output_length as i32,
                output.as_mut_ptr(),
            );

            if result == 0 {
                Ok(())
            } else {
                Err(CryptoKitError::DerivationFailed)
            }
        }
    }
}

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
    HKDF_SHA256::derive(input_key_material, salt, info, output_length)
}

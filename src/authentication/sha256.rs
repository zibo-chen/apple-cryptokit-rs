use crate::authentication::hmac::HMAC;
use crate::error::{CryptoKitError, Result};

// HMAC-SHA256 Swift FFI declarations
extern "C" {
    #[link_name = "hmac_sha256"]
    fn swift_hmac_sha256(
        key: *const u8,
        key_len: i32,
        data: *const u8,
        data_len: i32,
        output: *mut u8,
    ) -> i32;
}

/// HMAC-SHA256 output size
pub const HMAC_SHA256_OUTPUT_SIZE: usize = 32;

/// HMAC-SHA256 message authentication code
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; HMAC_SHA256_OUTPUT_SIZE]> {
    let mut output = [0u8; HMAC_SHA256_OUTPUT_SIZE];
    hmac_sha256_to(key, data, &mut output)?;
    Ok(output)
}

/// HMAC-SHA256 message authentication code to provided buffer (zero-allocation)
///
/// # Parameters
/// - `output`: Must be at least 32 bytes
///
/// # Returns
/// Number of bytes written (always HMAC_SHA256_OUTPUT_SIZE)
pub fn hmac_sha256_to(key: &[u8], data: &[u8], output: &mut [u8]) -> Result<usize> {
    assert!(
        output.len() >= HMAC_SHA256_OUTPUT_SIZE,
        "Output buffer too small: {} < {}",
        output.len(),
        HMAC_SHA256_OUTPUT_SIZE
    );
    unsafe {
        let result = swift_hmac_sha256(
            key.as_ptr(),
            key.len() as i32,
            data.as_ptr(),
            data.len() as i32,
            output.as_mut_ptr(),
        );

        if result < 0 {
            Err(CryptoKitError::SignatureFailed)
        } else {
            Ok(HMAC_SHA256_OUTPUT_SIZE)
        }
    }
}

/// HMAC-SHA256 implementation
pub struct HmacSha256;

impl HMAC for HmacSha256 {
    const OUTPUT_SIZE: usize = HMAC_SHA256_OUTPUT_SIZE;

    fn authenticate_to(key: &[u8], data: &[u8], output: &mut [u8]) -> Result<usize> {
        hmac_sha256_to(key, data, output)
    }
}

impl HmacSha256 {
    /// Verify HMAC-SHA256
    pub fn verify(key: &[u8], data: &[u8], expected: &[u8]) -> Result<bool> {
        let computed = Self::authenticate(key, data)?;
        Ok(super::hmac::constant_time_eq(&computed, expected))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha256_basic() {
        let key = b"secret_key";
        let data = b"hello world";

        let result = hmac_sha256(key, data);
        assert!(result.is_ok());

        let hmac_result = result.unwrap();
        assert_eq!(hmac_result.len(), HMAC_SHA256_OUTPUT_SIZE);
    }

    #[test]
    fn test_hmac_sha256_trait() {
        let key = b"test_key";
        let data = b"test_message";

        let result = HmacSha256::authenticate(key, data);
        assert!(result.is_ok());

        let hmac_result = result.unwrap();
        assert_eq!(hmac_result.len(), HmacSha256::output_size());
    }

    #[test]
    fn test_hmac_sha256_verify() {
        let key = b"verify_key";
        let data = b"verify_message";

        let hmac_result = HmacSha256::authenticate(key, data).unwrap();
        let verify_result = HmacSha256::verify(key, data, &hmac_result);

        assert!(verify_result.is_ok());
        assert!(verify_result.unwrap());

        // Test wrong HMAC
        let wrong_hmac = [0u8; HMAC_SHA256_OUTPUT_SIZE];
        let verify_wrong = HmacSha256::verify(key, data, &wrong_hmac);
        assert!(verify_wrong.is_ok());
        assert!(!verify_wrong.unwrap());
    }

    #[test]
    fn test_hmac_sha256_empty_key() {
        let key = b"";
        let data = b"test_data";

        let result = hmac_sha256(key, data);
        assert!(result.is_ok()); // HMAC allows empty keys, but not recommended
    }

    #[test]
    fn test_hmac_sha256_empty_data() {
        let key = b"test_key";
        let data = b"";

        let result = hmac_sha256(key, data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_hmac_sha256_consistency() {
        let key = b"consistency_key";
        let data = b"consistency_data";

        let result1 = hmac_sha256(key, data).unwrap();
        let result2 = hmac_sha256(key, data).unwrap();

        assert_eq!(result1, result2);
    }
}

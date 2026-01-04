use crate::authentication::hmac::HMAC;
use crate::error::{CryptoKitError, Result};

// HMAC-SHA1 Swift FFI declarations
extern "C" {
    #[link_name = "hmac_sha1"]
    fn swift_hmac_sha1(
        key: *const u8,
        key_len: i32,
        data: *const u8,
        data_len: i32,
        output: *mut u8,
    ) -> i32;
}

/// HMAC-SHA1 output size
pub const HMAC_SHA1_OUTPUT_SIZE: usize = 20;

/// HMAC-SHA1 message authentication code
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> Result<[u8; HMAC_SHA1_OUTPUT_SIZE]> {
    let mut output = [0u8; HMAC_SHA1_OUTPUT_SIZE];
    hmac_sha1_to(key, data, &mut output)?;
    Ok(output)
}

/// HMAC-SHA1 message authentication code to provided buffer (zero-allocation)
///
/// # Parameters
/// - `output`: Must be at least 20 bytes
pub fn hmac_sha1_to(key: &[u8], data: &[u8], output: &mut [u8]) -> Result<()> {
    assert!(
        output.len() >= HMAC_SHA1_OUTPUT_SIZE,
        "Output buffer too small: {} < {}",
        output.len(),
        HMAC_SHA1_OUTPUT_SIZE
    );
    unsafe {
        let result = swift_hmac_sha1(
            key.as_ptr(),
            key.len() as i32,
            data.as_ptr(),
            data.len() as i32,
            output.as_mut_ptr(),
        );

        if result < 0 {
            Err(CryptoKitError::SignatureFailed)
        } else {
            Ok(())
        }
    }
}

/// HMAC-SHA1 implementation (insecure, for compatibility only)
pub struct HmacSha1;

impl HMAC for HmacSha1 {
    const OUTPUT_SIZE: usize = HMAC_SHA1_OUTPUT_SIZE;

    fn authenticate_to(key: &[u8], data: &[u8], output: &mut [u8]) -> Result<()> {
        hmac_sha1_to(key, data, output)
    }
}

impl HmacSha1 {
    /// Verify HMAC-SHA1
    pub fn verify(key: &[u8], data: &[u8], expected: &[u8]) -> Result<bool> {
        let computed = Self::authenticate(key, data)?;
        Ok(super::hmac::constant_time_eq(&computed, expected))
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha1_basic() {
        let key = b"secret_key";
        let data = b"hello world";

        let result = hmac_sha1(key, data);
        assert!(result.is_ok());

        let hmac_result = result.unwrap();
        assert_eq!(hmac_result.len(), HMAC_SHA1_OUTPUT_SIZE);
    }

    #[test]
    fn test_hmac_sha1_trait() {
        let key = b"test_key";
        let data = b"test_message";

        let result = HmacSha1::authenticate(key, data);
        assert!(result.is_ok());

        let hmac_result = result.unwrap();
        assert_eq!(hmac_result.len(), HmacSha1::output_size());
    }

    #[test]
    fn test_hmac_sha1_verify() {
        let key = b"verify_key";
        let data = b"verify_message";

        let hmac_result = HmacSha1::authenticate(key, data).unwrap();
        let verify_result = HmacSha1::verify(key, data, &hmac_result);

        assert!(verify_result.is_ok());
        assert!(verify_result.unwrap());

        // Test wrong HMAC
        let wrong_hmac = [0u8; HMAC_SHA1_OUTPUT_SIZE];
        let verify_wrong = HmacSha1::verify(key, data, &wrong_hmac);
        assert!(verify_wrong.is_ok());
        assert!(!verify_wrong.unwrap());
    }
}

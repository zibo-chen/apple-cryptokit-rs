use crate::authentication::hmac::HMAC;
use crate::error::{CryptoKitError, Result};

// HMAC-SHA1 Swift FFI 声明
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

/// HMAC-SHA1 输出大小
pub const HMAC_SHA1_OUTPUT_SIZE: usize = 20;

/// HMAC-SHA1 消息认证码
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> Result<[u8; HMAC_SHA1_OUTPUT_SIZE]> {
    unsafe {
        let mut output = [0u8; HMAC_SHA1_OUTPUT_SIZE];
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
            Ok(output)
        }
    }
}

/// HMAC-SHA1 实现 (不安全，仅用于兼容性)
pub struct HmacSha1;

impl HMAC for HmacSha1 {
    type Output = [u8; HMAC_SHA1_OUTPUT_SIZE];

    fn authenticate(key: &[u8], data: &[u8]) -> Result<Self::Output> {
        hmac_sha1(key, data)
    }

    fn output_size() -> usize {
        HMAC_SHA1_OUTPUT_SIZE
    }
}

impl HmacSha1 {
    /// 验证HMAC-SHA1
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

        // 测试错误的HMAC
        let wrong_hmac = [0u8; HMAC_SHA1_OUTPUT_SIZE];
        let verify_wrong = HmacSha1::verify(key, data, &wrong_hmac);
        assert!(verify_wrong.is_ok());
        assert!(!verify_wrong.unwrap());
    }
}

use crate::authentication::hmac::HMAC;
use crate::error::{CryptoKitError, Result};

// HMAC-SHA384 Swift FFI 声明
extern "C" {
    #[link_name = "hmac_sha384"]
    fn swift_hmac_sha384(
        key: *const u8,
        key_len: i32,
        data: *const u8,
        data_len: i32,
        output: *mut u8,
    ) -> i32;
}

/// HMAC-SHA384 输出大小
pub const HMAC_SHA384_OUTPUT_SIZE: usize = 48;

/// HMAC-SHA384 消息认证码
pub fn hmac_sha384(key: &[u8], data: &[u8]) -> Result<[u8; HMAC_SHA384_OUTPUT_SIZE]> {
    unsafe {
        let mut output = [0u8; HMAC_SHA384_OUTPUT_SIZE];
        let result = swift_hmac_sha384(
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

/// HMAC-SHA384 实现
pub struct HmacSha384;

impl HMAC for HmacSha384 {
    type Output = [u8; HMAC_SHA384_OUTPUT_SIZE];

    fn authenticate(key: &[u8], data: &[u8]) -> Result<Self::Output> {
        hmac_sha384(key, data)
    }

    fn output_size() -> usize {
        HMAC_SHA384_OUTPUT_SIZE
    }
}

impl HmacSha384 {
    /// 验证HMAC-SHA384
    pub fn verify(key: &[u8], data: &[u8], expected: &[u8]) -> Result<bool> {
        let computed = Self::authenticate(key, data)?;
        Ok(super::hmac::constant_time_eq(&computed, expected))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha384_basic() {
        let key = b"secret_key";
        let data = b"hello world";

        let result = hmac_sha384(key, data);
        assert!(result.is_ok());

        let hmac_result = result.unwrap();
        assert_eq!(hmac_result.len(), HMAC_SHA384_OUTPUT_SIZE);
    }

    #[test]
    fn test_hmac_sha384_trait() {
        let key = b"test_key";
        let data = b"test_message";

        let result = HmacSha384::authenticate(key, data);
        assert!(result.is_ok());

        let hmac_result = result.unwrap();
        assert_eq!(hmac_result.len(), HmacSha384::output_size());
    }

    #[test]
    fn test_hmac_sha384_verify() {
        let key = b"verify_key";
        let data = b"verify_message";

        let hmac_result = HmacSha384::authenticate(key, data).unwrap();
        let verify_result = HmacSha384::verify(key, data, &hmac_result);

        assert!(verify_result.is_ok());
        assert!(verify_result.unwrap());

        // 测试错误的HMAC
        let wrong_hmac = [0u8; HMAC_SHA384_OUTPUT_SIZE];
        let verify_wrong = HmacSha384::verify(key, data, &wrong_hmac);
        assert!(verify_wrong.is_ok());
        assert!(!verify_wrong.unwrap());
    }

    #[test]
    fn test_hmac_sha384_consistency() {
        let key = b"consistency_key";
        let data = b"consistency_data";

        let result1 = hmac_sha384(key, data).unwrap();
        let result2 = hmac_sha384(key, data).unwrap();

        assert_eq!(result1, result2);
    }
}

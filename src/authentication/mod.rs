pub mod hmac;
pub mod sha1;
pub mod sha256;
pub mod sha384;
pub mod sha512;

// Re-export public API
pub use hmac::{constant_time_eq, verify_hmac, HmacAlgorithm, HmacBuilder, HMAC};

pub use sha1::{hmac_sha1, hmac_sha1_to, HmacSha1, HMAC_SHA1_OUTPUT_SIZE};

pub use sha256::{hmac_sha256, hmac_sha256_to, HmacSha256, HMAC_SHA256_OUTPUT_SIZE};

pub use sha384::{hmac_sha384, hmac_sha384_to, HmacSha384, HMAC_SHA384_OUTPUT_SIZE};

pub use sha512::{hmac_sha512, hmac_sha512_to, HmacSha512, HMAC_SHA512_OUTPUT_SIZE};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_algorithm_enum() {
        let key = b"test_key";
        let data = b"test_message";

        // 测试所有算法
        let algorithms = [
            HmacAlgorithm::Sha1,
            HmacAlgorithm::Sha256,
            HmacAlgorithm::Sha384,
            HmacAlgorithm::Sha512,
        ];

        for algorithm in &algorithms {
            let result = algorithm.compute(key, data);
            assert!(result.is_ok());

            let hmac_result = result.unwrap();
            assert_eq!(hmac_result.len(), algorithm.output_size());

            // 测试验证
            let verify_result = algorithm.verify(key, data, &hmac_result);
            assert!(verify_result.is_ok());
            assert!(verify_result.unwrap());
        }
    }

    #[test]
    fn test_hmac_builder() {
        let key = b"builder_key";
        let data = b"builder_message";

        let builder = HmacBuilder::new(HmacAlgorithm::Sha256).key(key);

        let result = builder.compute(data);
        assert!(result.is_ok());

        let hmac_result = result.unwrap();
        assert_eq!(hmac_result.len(), 32); // SHA-256 输出长度

        // 测试验证
        let verify_result = builder.verify(data, &hmac_result);
        assert!(verify_result.is_ok());
        assert!(verify_result.unwrap());
    }

    #[test]
    fn test_constant_time_eq() {
        let a = b"hello";
        let b = b"hello";
        let c = b"world";

        assert!(constant_time_eq(a, b));
        assert!(!constant_time_eq(a, c));
        assert!(!constant_time_eq(a, b"hello world")); // 不同长度
    }

    #[test]
    fn test_verify_hmac() {
        let hmac1 = b"test_hmac_value";
        let hmac2 = b"test_hmac_value";
        let hmac3 = b"different_value";

        assert!(verify_hmac(hmac1, hmac2));
        assert!(!verify_hmac(hmac1, hmac3));
    }

    #[test]
    fn test_cross_algorithm_interoperability() {
        let key = b"interop_key";
        let data = b"interop_data";

        // 使用不同方式计算相同算法的HMAC
        let direct_result = hmac_sha256(key, data).unwrap();
        let trait_result = HmacSha256::authenticate(key, data).unwrap();
        let enum_result = HmacAlgorithm::Sha256.compute(key, data).unwrap();
        let builder_result = HmacBuilder::new(HmacAlgorithm::Sha256)
            .key(key)
            .compute(data)
            .unwrap();

        assert_eq!(direct_result.as_ref() as &[u8], trait_result.as_slice());
        assert_eq!(direct_result.as_ref() as &[u8], &enum_result[..]);
        assert_eq!(direct_result.as_ref() as &[u8], &builder_result[..]);
    }
}

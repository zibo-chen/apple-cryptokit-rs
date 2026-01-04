use apple_cryptokit::authentication::*;

mod hmac_sha1_tests {
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

mod hmac_sha256_tests {
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
    }

    #[test]
    fn test_hmac_sha256_empty_key() {
        let key = b"";
        let data = b"test_data";

        let result = hmac_sha256(key, data);
        assert!(result.is_ok());
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

mod hmac_sha384_tests {
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
}

mod hmac_sha512_tests {
    use super::*;

    #[test]
    fn test_hmac_sha512_basic() {
        let key = b"secret_key";
        let data = b"hello world";

        let result = hmac_sha512(key, data);
        assert!(result.is_ok());

        let hmac_result = result.unwrap();
        assert_eq!(hmac_result.len(), HMAC_SHA512_OUTPUT_SIZE);
    }

    #[test]
    fn test_hmac_sha512_trait() {
        let key = b"test_key";
        let data = b"test_message";

        let result = HmacSha512::authenticate(key, data);
        assert!(result.is_ok());

        let hmac_result = result.unwrap();
        assert_eq!(hmac_result.len(), HmacSha512::output_size());
    }

    #[test]
    fn test_hmac_sha512_large_data() {
        let key = b"large_data_key";
        let data = vec![0u8; 10000]; // 10KB数据

        let result = hmac_sha512(key, &data);
        assert!(result.is_ok());

        let hmac_result = result.unwrap();
        assert_eq!(hmac_result.len(), HMAC_SHA512_OUTPUT_SIZE);
    }
}

mod integration_tests {
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

    #[test]
    fn test_different_key_sizes() {
        let data = b"test_message";

        // 测试不同长度的密钥
        let keys = [
            b"short".as_slice(),
            b"medium_length_key".as_slice(),
            b"very_long_key_that_exceeds_typical_block_sizes_and_tests_key_handling".as_slice(),
        ];

        for key in &keys {
            let result = hmac_sha256(key, data);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_different_data_sizes() {
        let key = b"test_key";

        // 测试不同长度的数据
        let data_sizes = [0, 1, 16, 64, 256, 1024];

        for &size in &data_sizes {
            let data = vec![0u8; size];
            let result = hmac_sha256(key, &data);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_output_sizes() {
        assert_eq!(HMAC_SHA1_OUTPUT_SIZE, 20);
        assert_eq!(HMAC_SHA256_OUTPUT_SIZE, 32);
        assert_eq!(HMAC_SHA384_OUTPUT_SIZE, 48);
        assert_eq!(HMAC_SHA512_OUTPUT_SIZE, 64);

        assert_eq!(HmacAlgorithm::Sha1.output_size(), 20);
        assert_eq!(HmacAlgorithm::Sha256.output_size(), 32);
        assert_eq!(HmacAlgorithm::Sha384.output_size(), 48);
        assert_eq!(HmacAlgorithm::Sha512.output_size(), 64);
    }

    #[test]
    fn test_timing_attack_resistance() {
        let key = b"timing_key";
        let data = b"timing_data";

        let correct_hmac = hmac_sha256(key, data).unwrap();
        let mut wrong_hmac = correct_hmac.clone();
        wrong_hmac[0] ^= 0xFF; // 修改第一个字节

        // 这两个比较应该都花费大致相同的时间
        assert!(constant_time_eq(&correct_hmac, &correct_hmac));
        assert!(!constant_time_eq(&correct_hmac, &wrong_hmac));
    }
}

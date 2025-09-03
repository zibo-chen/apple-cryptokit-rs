use apple_cryptokit::hashing::*;

mod sha1_tests {
    use super::*;

    #[test]
    fn test_sha1_basic() {
        let data = b"hello world";
        let hash = sha1_hash(data);
        assert_eq!(hash.len(), 20);
    }

    #[test]
    fn test_sha1_trait() {
        let data = b"test message";
        let hash = SHA1::hash(data);
        assert_eq!(hash.len(), 20);
    }

    #[test]
    fn test_sha1_empty() {
        let data = b"";
        let hash = sha1_hash(data);
        assert_eq!(hash.len(), 20);
        // SHA1 of empty string: da39a3ee5e6b4b0d3255bfef95601890afd80709
        let expected = [
            0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
            0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
        ];
        assert_eq!(hash, expected);
    }
}

mod sha256_tests {
    use super::*;

    #[test]
    fn test_sha256_basic() {
        let data = b"hello world";
        let hash = sha256_hash(data);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_sha256_trait() {
        let data = b"test message";
        let hash = SHA256::hash(data);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_sha256_streaming() {
        let mut sha256 = Sha256::new();
        sha256.update(b"hello");
        sha256.update(b" ");
        sha256.update(b"world");
        let hash = sha256.finalize();

        let direct_hash = sha256_hash(b"hello world");
        assert_eq!(hash, direct_hash);
    }

    #[test]
    fn test_sha256_empty() {
        let data = b"";
        let hash = sha256_hash(data);
        assert_eq!(hash.len(), 32);

        // SHA256 of empty string: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(hash, expected);
    }
}

mod sha384_tests {
    use super::*;

    #[test]
    fn test_sha384_basic() {
        let data = b"hello world";
        let hash = sha384_hash(data);
        assert_eq!(hash.len(), 48);
    }

    #[test]
    fn test_sha384_trait() {
        let data = b"test message";
        let hash = SHA384::hash(data);
        assert_eq!(hash.len(), 48);
    }

    #[test]
    fn test_sha384_streaming() {
        let mut sha384 = Sha384::new();
        sha384.update(b"hello");
        sha384.update(b" ");
        sha384.update(b"world");
        let hash = sha384.finalize();

        let direct_hash = sha384_hash(b"hello world");
        assert_eq!(hash, direct_hash);
    }
}

mod sha512_tests {
    use super::*;

    #[test]
    fn test_sha512_basic() {
        let data = b"hello world";
        let hash = sha512_hash(data);
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_sha512_trait() {
        let data = b"test message";
        let hash = SHA512::hash(data);
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_sha512_streaming() {
        let mut sha512 = Sha512::new();
        sha512.update(b"hello");
        sha512.update(b" ");
        sha512.update(b"world");
        let hash = sha512.finalize();

        let direct_hash = sha512_hash(b"hello world");
        assert_eq!(hash, direct_hash);
    }
}

mod hash_algorithm_tests {
    use super::*;

    #[test]
    fn test_hash_algorithm_output_sizes() {
        assert_eq!(HashAlgorithm::Sha1.output_size(), 20);
        assert_eq!(HashAlgorithm::Sha256.output_size(), 32);
        assert_eq!(HashAlgorithm::Sha384.output_size(), 48);
        assert_eq!(HashAlgorithm::Sha512.output_size(), 64);
    }

    #[test]
    fn test_hash_algorithm_compute() {
        let data = b"test data";

        let sha1_result = HashAlgorithm::Sha1.compute(data);
        assert_eq!(sha1_result.len(), 20);

        let sha256_result = HashAlgorithm::Sha256.compute(data);
        assert_eq!(sha256_result.len(), 32);

        let sha384_result = HashAlgorithm::Sha384.compute(data);
        assert_eq!(sha384_result.len(), 48);

        let sha512_result = HashAlgorithm::Sha512.compute(data);
        assert_eq!(sha512_result.len(), 64);
    }

    #[test]
    fn test_hash_builder() {
        let data = b"builder test";

        let builder_sha256 = HashBuilder::new(HashAlgorithm::Sha256);
        let result = builder_sha256.compute(data);
        assert_eq!(result.len(), 32);
        assert_eq!(builder_sha256.output_size(), 32);

        let direct_result = sha256_hash(data).to_vec();
        assert_eq!(result, direct_result);
    }
}

mod consistency_tests {
    use super::*;

    #[test]
    fn test_sha256_consistency() {
        let data = b"consistency test data";

        // 直接函数调用
        let direct = sha256_hash(data);

        // 通过trait调用
        let trait_result = SHA256::hash(data);

        // 通过枚举调用
        let enum_result = HashAlgorithm::Sha256.compute(data);

        // 通过构建器调用
        let builder = HashBuilder::new(HashAlgorithm::Sha256);
        let builder_result = builder.compute(data);

        assert_eq!(direct, trait_result);
        assert_eq!(direct.to_vec(), enum_result);
        assert_eq!(direct.to_vec(), builder_result);
    }

    #[test]
    fn test_streaming_vs_direct() {
        let data = b"streaming comparison test";

        // SHA256
        let mut sha256 = Sha256::new();
        sha256.update(data);
        let streaming_result = sha256.finalize();
        let direct_result = sha256_hash(data);
        assert_eq!(streaming_result, direct_result);

        // SHA384
        let mut sha384 = Sha384::new();
        sha384.update(data);
        let streaming_result = sha384.finalize();
        let direct_result = sha384_hash(data);
        assert_eq!(streaming_result, direct_result);

        // SHA512
        let mut sha512 = Sha512::new();
        sha512.update(data);
        let streaming_result = sha512.finalize();
        let direct_result = sha512_hash(data);
        assert_eq!(streaming_result, direct_result);
    }
}

mod performance_tests {
    use super::*;

    #[test]
    fn test_large_data_hashing() {
        let large_data = vec![0xabu8; 1024 * 1024]; // 1MB of data

        // 测试直接哈希
        let hash = sha256_hash(&large_data);
        assert_eq!(hash.len(), 32);

        // 测试流式哈希
        let mut sha256 = Sha256::new();
        for chunk in large_data.chunks(1024) {
            sha256.update(chunk);
        }
        let streaming_hash = sha256.finalize();

        assert_eq!(hash, streaming_hash);
    }

    #[test]
    fn test_multiple_updates() {
        let data_parts = [b"part1", b"part2", b"part3", b"part4"];

        let mut sha256 = Sha256::new();
        for part in &data_parts {
            sha256.update(*part);
        }
        let streaming_result = sha256.finalize();

        let combined_data = b"part1part2part3part4";
        let direct_result = sha256_hash(combined_data);

        assert_eq!(streaming_result, direct_result);
    }
}

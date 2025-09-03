use apple_cryptokit::error::CryptoKitError;
use apple_cryptokit::key_derivation::*;

#[cfg(test)]
mod hkdf_tests {
    use super::*;

    #[test]
    fn test_hkdf_sha256_basic() {
        let ikm = b"this is some input key material";
        let salt = b"salt value";
        let info = b"context information";
        let length = 32;

        let derived = hkdf_sha256_derive(ikm, salt, info, length).unwrap();
        assert_eq!(derived.len(), length);

        // 测试一致性 - 相同输入应该产生相同输出
        let derived2 = hkdf_sha256_derive(ikm, salt, info, length).unwrap();
        assert_eq!(derived, derived2);
    }

    #[test]
    fn test_hkdf_sha384_basic() {
        let ikm = b"input key material for sha384";
        let salt = b"sha384 salt";
        let info = b"sha384 context";
        let length = 48;

        let derived = hkdf_sha384_derive(ikm, salt, info, length).unwrap();
        assert_eq!(derived.len(), length);
    }

    #[test]
    fn test_hkdf_sha512_basic() {
        let ikm = b"input key material for sha512";
        let salt = b"sha512 salt";
        let info = b"sha512 context";
        let length = 64;

        let derived = hkdf_sha512_derive(ikm, salt, info, length).unwrap();
        assert_eq!(derived.len(), length);
    }

    #[test]
    fn test_hkdf_different_lengths() {
        let ikm = b"test input key material";
        let salt = b"test salt";
        let info = b"test info";

        // 测试不同的输出长度
        for length in [1, 16, 32, 64, 128] {
            let derived = HKDF_SHA256::derive_key(ikm, salt, info, length).unwrap();
            assert_eq!(derived.len(), length);
        }
    }

    #[test]
    fn test_hkdf_empty_salt_info() {
        let ikm = b"input key material";
        let empty_salt = &[];
        let empty_info = &[];
        let length = 32;

        // 测试空盐值和信息
        let derived = hkdf_sha256_derive(ikm, empty_salt, empty_info, length).unwrap();
        assert_eq!(derived.len(), length);
    }

    #[test]
    fn test_hkdf_class_methods() {
        let ikm = b"test input key material";
        let salt = b"test salt";
        let info = b"test info";
        let length = 32;

        // 测试类方法
        let derived1 = HKDF_SHA256::derive_key(ikm, salt, info, length).unwrap();
        let derived2 = HKDF_SHA384::derive_key(ikm, salt, info, length).unwrap();
        let derived3 = HKDF_SHA512::derive_key(ikm, salt, info, length).unwrap();

        assert_eq!(derived1.len(), length);
        assert_eq!(derived2.len(), length);
        assert_eq!(derived3.len(), length);

        // 不同算法应产生不同的结果
        assert_ne!(derived1, derived2);
        assert_ne!(derived2, derived3);
        assert_ne!(derived1, derived3);
    }
}

#[cfg(test)]
mod general_hkdf_tests {
    use super::*;

    #[test]
    fn test_hkdf_general_interface() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"info";
        let length = 32;

        // 测试通用接口
        let derived256 = HKDF::derive_key(HashAlgorithm::SHA256, ikm, salt, info, length).unwrap();
        let derived384 = HKDF::derive_key(HashAlgorithm::SHA384, ikm, salt, info, length).unwrap();
        let derived512 = HKDF::derive_key(HashAlgorithm::SHA512, ikm, salt, info, length).unwrap();

        assert_eq!(derived256.len(), length);
        assert_eq!(derived384.len(), length);
        assert_eq!(derived512.len(), length);

        // 不同算法应产生不同的结果
        assert_ne!(derived256, derived384);
        assert_ne!(derived384, derived512);
        assert_ne!(derived256, derived512);
    }

    #[test]
    fn test_hkdf_convenience_methods() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"info";
        let length = 32;

        // 测试便利方法
        let derived256 = HKDF::derive_key_sha256(ikm, salt, info, length).unwrap();
        let derived384 = HKDF::derive_key_sha384(ikm, salt, info, length).unwrap();
        let derived512 = HKDF::derive_key_sha512(ikm, salt, info, length).unwrap();

        // 应该与通用接口产生相同结果
        let general256 = HKDF::derive_key(HashAlgorithm::SHA256, ikm, salt, info, length).unwrap();
        let general384 = HKDF::derive_key(HashAlgorithm::SHA384, ikm, salt, info, length).unwrap();
        let general512 = HKDF::derive_key(HashAlgorithm::SHA512, ikm, salt, info, length).unwrap();

        assert_eq!(derived256, general256);
        assert_eq!(derived384, general384);
        assert_eq!(derived512, general512);
    }

    #[test]
    fn test_derive_symmetric_key() {
        let shared_secret = b"shared secret from key exchange";
        let info = b"symmetric key derivation";
        let length = key_sizes::AES_256;

        // 测试带盐值的派生
        let salt = b"random salt value";
        let key_with_salt = HKDF::derive_symmetric_key(
            shared_secret,
            HashAlgorithm::SHA256,
            Some(salt),
            info,
            length,
        )
        .unwrap();

        // 测试不带盐值的派生
        let key_without_salt =
            HKDF::derive_symmetric_key(shared_secret, HashAlgorithm::SHA256, None, info, length)
                .unwrap();

        assert_eq!(key_with_salt.len(), length);
        assert_eq!(key_without_salt.len(), length);
        assert_ne!(key_with_salt, key_without_salt);
    }
}

#[cfg(test)]
mod error_handling_tests {
    use super::*;

    #[test]
    fn test_empty_input_key_material() {
        let result = hkdf_sha256_derive(&[], b"salt", b"info", 32);
        assert!(matches!(result, Err(CryptoKitError::InvalidInput(_))));

        let result = HKDF::derive_key(HashAlgorithm::SHA256, &[], b"salt", b"info", 32);
        assert!(matches!(result, Err(CryptoKitError::InvalidInput(_))));
    }

    #[test]
    fn test_invalid_output_length() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"info";

        // 测试零长度
        let result = hkdf_sha256_derive(ikm, salt, info, 0);
        assert!(matches!(result, Err(CryptoKitError::InvalidLength)));

        // 测试过大长度（超过255 * hash_length）
        let result = hkdf_sha256_derive(ikm, salt, info, 255 * 32 + 1);
        assert!(matches!(result, Err(CryptoKitError::InvalidLength)));

        // 测试通用接口的长度验证
        let result = HKDF::derive_key(HashAlgorithm::SHA384, ikm, salt, info, 255 * 48 + 1);
        assert!(matches!(result, Err(CryptoKitError::InvalidLength)));
    }
}

#[cfg(test)]
mod compatibility_tests {
    use super::*;

    #[test]
    fn test_trait_implementation() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"info";
        let length = 32;

        // 测试trait方法与直接方法的一致性
        let trait_result = HKDF_SHA256::derive(ikm, salt, info, length).unwrap();
        let direct_result = HKDF_SHA256::derive_key(ikm, salt, info, length).unwrap();
        let convenience_result = hkdf_sha256_derive(ikm, salt, info, length).unwrap();

        assert_eq!(trait_result, direct_result);
        assert_eq!(direct_result, convenience_result);
    }

    #[test]
    fn test_known_key_sizes() {
        let ikm = b"input key material for known sizes";
        let salt = b"salt";

        // 测试预定义的密钥大小
        let aes128_key = hkdf_sha256_derive(ikm, salt, b"AES-128", key_sizes::AES_128).unwrap();
        let aes192_key = hkdf_sha256_derive(ikm, salt, b"AES-192", key_sizes::AES_192).unwrap();
        let aes256_key = hkdf_sha256_derive(ikm, salt, b"AES-256", key_sizes::AES_256).unwrap();
        let chacha20_key = hkdf_sha256_derive(ikm, salt, b"ChaCha20", key_sizes::CHACHA20).unwrap();

        assert_eq!(aes128_key.len(), 16);
        assert_eq!(aes192_key.len(), 24);
        assert_eq!(aes256_key.len(), 32);
        assert_eq!(chacha20_key.len(), 32);

        // 不同用途应产生不同密钥
        assert_ne!(aes128_key, aes192_key[..16]);
        assert_ne!(aes256_key, chacha20_key);
    }
}

#[cfg(test)]
mod performance_tests {
    use super::*;

    #[test]
    fn test_large_derivation() {
        let ikm = b"input key material for large derivation test";
        let salt = b"salt for large test";
        let info = b"info for large test";

        // 测试大量密钥派生（但不超过限制）
        let large_length = 1024; // 1KB
        let derived = hkdf_sha256_derive(ikm, salt, info, large_length).unwrap();
        assert_eq!(derived.len(), large_length);

        // 检查输出不全为零（这表明实际进行了派生）
        assert!(derived.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_multiple_derivations_consistency() {
        let ikm = b"base input key material";
        let salt = b"consistent salt";

        // 测试多次派生的一致性
        let mut results = Vec::new();
        for i in 0..10 {
            let info = format!("context {}", i);
            let derived = hkdf_sha256_derive(ikm, salt, info.as_bytes(), 32).unwrap();
            results.push(derived);
        }

        // 验证不同info产生不同结果
        for i in 0..results.len() {
            for j in i + 1..results.len() {
                assert_ne!(
                    results[i], results[j],
                    "Derivation {} and {} should be different",
                    i, j
                );
            }
        }
    }
}

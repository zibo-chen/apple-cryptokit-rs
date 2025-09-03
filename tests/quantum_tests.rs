use apple_cryptokit::quantum::{
    DigitalSignatureAlgorithm,

    KEMPrivateKey,
    KEMPublicKey,
    KeyEncapsulationMechanism,

    // 数字签名算法
    MLDsa65,
    MLDsa87,
    // KEM 算法
    MLKem768,
    MLKem1024,
    // 通用特征
    QuantumSafe,
    SignaturePrivateKey,
    SignaturePublicKey,
    XWingMLKem768X25519,
};

#[cfg(test)]
mod quantum_tests {
    use super::*;

    /// 测试ML-KEM768的基本功能
    #[test]
    fn test_mlkem768_basic_operations() {
        let private_key =
            MLKem768::generate_private_key().expect("Failed to generate ML-KEM768 private key");
        let public_key = private_key.public_key();

        // 测试封装
        let (ciphertext, shared_secret1) = public_key.encapsulate().expect("Failed to encapsulate");

        // 测试解封装
        let shared_secret2 = private_key
            .decapsulate(&ciphertext)
            .expect("Failed to decapsulate");

        // 验证共享密钥相同
        assert_eq!(
            shared_secret1, shared_secret2,
            "Shared secrets should match"
        );
        assert_eq!(shared_secret1.len(), 32, "Shared secret should be 32 bytes");

        // 验证密钥大小
        assert_eq!(
            private_key.to_bytes().len(),
            2400,
            "ML-KEM768 private key should be 2400 bytes"
        );
        assert_eq!(
            public_key.to_bytes().len(),
            1184,
            "ML-KEM768 public key should be 1184 bytes"
        );
        assert_eq!(
            ciphertext.len(),
            1088,
            "ML-KEM768 ciphertext should be 1088 bytes"
        );
    }

    /// 测试ML-KEM1024的基本功能
    #[test]
    fn test_mlkem1024_basic_operations() {
        let private_key =
            MLKem1024::generate_private_key().expect("Failed to generate ML-KEM1024 private key");
        let public_key = private_key.public_key();

        let (ciphertext, shared_secret1) = public_key.encapsulate().expect("Failed to encapsulate");
        let shared_secret2 = private_key
            .decapsulate(&ciphertext)
            .expect("Failed to decapsulate");

        assert_eq!(
            shared_secret1, shared_secret2,
            "Shared secrets should match"
        );
        assert_eq!(shared_secret1.len(), 32, "Shared secret should be 32 bytes");

        // 验证ML-KEM1024的密钥大小
        assert_eq!(
            private_key.to_bytes().len(),
            3168,
            "ML-KEM1024 private key should be 3168 bytes"
        );
        assert_eq!(
            public_key.to_bytes().len(),
            1568,
            "ML-KEM1024 public key should be 1568 bytes"
        );
        assert_eq!(
            ciphertext.len(),
            1568,
            "ML-KEM1024 ciphertext should be 1568 bytes"
        );
    }

    /// 测试X-Wing混合KEM的基本功能
    #[test]
    fn test_xwing_basic_operations() {
        let private_key = XWingMLKem768X25519::generate_private_key()
            .expect("Failed to generate X-Wing private key");
        let public_key = private_key.public_key();

        let (ciphertext, shared_secret1) = public_key.encapsulate().expect("Failed to encapsulate");
        let shared_secret2 = private_key
            .decapsulate(&ciphertext)
            .expect("Failed to decapsulate");

        assert_eq!(
            shared_secret1, shared_secret2,
            "Shared secrets should match"
        );
        assert_eq!(shared_secret1.len(), 32, "Shared secret should be 32 bytes");

        // 验证X-Wing的密钥大小
        assert_eq!(
            private_key.to_bytes().len(),
            2432,
            "X-Wing private key should be 2432 bytes"
        );
        assert_eq!(
            public_key.to_bytes().len(),
            1216,
            "X-Wing public key should be 1216 bytes"
        );
        assert_eq!(
            ciphertext.len(),
            1120,
            "X-Wing ciphertext should be 1120 bytes"
        );
    }

    /// 测试ML-DSA65的基本功能
    #[test]
    fn test_mldsa65_basic_operations() {
        let private_key =
            MLDsa65::generate_private_key().expect("Failed to generate ML-DSA65 private key");
        let public_key = private_key.public_key();

        let message = b"Hello, ML-DSA65!";
        let signature = private_key.sign(message).expect("Failed to sign message");

        // 验证正确的消息
        let is_valid = public_key
            .verify(message, &signature)
            .expect("Failed to verify signature");
        assert!(is_valid, "Signature should be valid");

        // 验证错误的消息
        let wrong_message = b"Wrong message";
        let is_invalid = public_key
            .verify(wrong_message, &signature)
            .expect("Failed to verify wrong message");
        assert!(!is_invalid, "Signature should be invalid for wrong message");

        // 验证密钥和签名大小
        assert_eq!(
            private_key.to_bytes().len(),
            4032,
            "ML-DSA65 private key should be 4032 bytes"
        );
        assert_eq!(
            public_key.to_bytes().len(),
            1952,
            "ML-DSA65 public key should be 1952 bytes"
        );
        assert!(
            signature.len() <= 3309,
            "ML-DSA65 signature should be at most 3309 bytes"
        );
    }

    /// 测试ML-DSA87的基本功能
    #[test]
    fn test_mldsa87_basic_operations() {
        let private_key =
            MLDsa87::generate_private_key().expect("Failed to generate ML-DSA87 private key");
        let public_key = private_key.public_key();

        let message = b"Hello, ML-DSA87!";
        let signature = private_key.sign(message).expect("Failed to sign message");

        // 验证正确的消息
        let is_valid = public_key
            .verify(message, &signature)
            .expect("Failed to verify signature");
        assert!(is_valid, "Signature should be valid");

        // 验证错误的消息
        let wrong_message = b"Wrong message";
        let is_invalid = public_key
            .verify(wrong_message, &signature)
            .expect("Failed to verify wrong message");
        assert!(!is_invalid, "Signature should be invalid for wrong message");

        // 验证密钥和签名大小
        assert_eq!(
            private_key.to_bytes().len(),
            4896,
            "ML-DSA87 private key should be 4896 bytes"
        );
        assert_eq!(
            public_key.to_bytes().len(),
            2592,
            "ML-DSA87 public key should be 2592 bytes"
        );
        assert!(
            signature.len() <= 4627,
            "ML-DSA87 signature should be at most 4627 bytes"
        );
    }

    /// 测试密钥序列化和反序列化
    #[test]
    fn test_key_serialization_mlkem768() {
        let original_private =
            MLKem768::generate_private_key().expect("Failed to generate private key");
        let original_public = original_private.public_key();

        // 序列化
        let private_bytes = original_private.to_bytes();
        let public_bytes = original_public.to_bytes();

        // 反序列化
        let restored_private =
            apple_cryptokit::quantum::MLKem768PrivateKey::from_bytes(&private_bytes)
                .expect("Failed to deserialize private key");
        let restored_public =
            apple_cryptokit::quantum::MLKem768PublicKey::from_bytes(&public_bytes)
                .expect("Failed to deserialize public key");

        // 测试恢复的密钥是否正常工作
        let (ciphertext, secret1) = restored_public
            .encapsulate()
            .expect("Failed to encapsulate with restored key");
        let secret2 = restored_private
            .decapsulate(&ciphertext)
            .expect("Failed to decapsulate with restored key");

        assert_eq!(
            secret1, secret2,
            "Shared secrets should match with restored keys"
        );
    }

    /// 测试算法属性
    #[test]
    fn test_algorithm_properties() {
        // 测试ML-KEM768属性
        assert_eq!(MLKem768::algorithm_name(), "ML-KEM-768");
        assert_eq!(MLKem768::security_level(), 1);
        assert!(MLKem768::is_post_quantum());

        // 测试ML-KEM1024属性
        assert_eq!(MLKem1024::algorithm_name(), "ML-KEM-1024");
        assert_eq!(MLKem1024::security_level(), 3);
        assert!(MLKem1024::is_post_quantum());

        // 测试X-Wing属性
        assert_eq!(
            XWingMLKem768X25519::algorithm_name(),
            "X-Wing-ML-KEM768-X25519"
        );
        assert_eq!(XWingMLKem768X25519::security_level(), 1);
        assert!(XWingMLKem768X25519::is_post_quantum());

        // 测试ML-DSA65属性
        assert_eq!(MLDsa65::algorithm_name(), "ML-DSA-65");
        assert_eq!(MLDsa65::security_level(), 2);
        assert!(MLDsa65::is_post_quantum());

        // 测试ML-DSA87属性
        assert_eq!(MLDsa87::algorithm_name(), "ML-DSA-87");
        assert_eq!(MLDsa87::security_level(), 3);
        assert!(MLDsa87::is_post_quantum());
    }

    /// 测试不同消息的签名唯一性
    #[test]
    fn test_signature_uniqueness() {
        let private_key = MLDsa65::generate_private_key().expect("Failed to generate private key");

        let message1 = b"First message";
        let message2 = b"Second message";

        let signature1 = private_key
            .sign(message1)
            .expect("Failed to sign first message");
        let signature2 = private_key
            .sign(message2)
            .expect("Failed to sign second message");

        // 不同消息应该产生不同的签名
        assert_ne!(
            signature1, signature2,
            "Different messages should produce different signatures"
        );
    }

    /// 测试密钥一致性
    #[test]
    fn test_key_consistency() {
        let private_key = MLKem768::generate_private_key().expect("Failed to generate private key");
        let public_key1 = private_key.public_key();
        let public_key2 = private_key.public_key();

        // 从同一个私钥派生的公钥应该相同
        assert_eq!(
            public_key1.to_bytes(),
            public_key2.to_bytes(),
            "Public keys derived from same private key should be identical"
        );
    }

    /// 测试错误的密钥长度处理
    #[test]
    fn test_invalid_key_lengths() {
        // 测试无效的私钥长度
        let invalid_private_key_bytes = vec![0u8; 100]; // 错误的长度
        let result =
            apple_cryptokit::quantum::MLKem768PrivateKey::from_bytes(&invalid_private_key_bytes);
        assert!(
            result.is_err(),
            "Should fail with invalid private key length"
        );

        // 测试无效的公钥长度
        let invalid_public_key_bytes = vec![0u8; 100]; // 错误的长度
        let result =
            apple_cryptokit::quantum::MLKem768PublicKey::from_bytes(&invalid_public_key_bytes);
        assert!(
            result.is_err(),
            "Should fail with invalid public key length"
        );
    }

    /// 测试错误的密文长度处理
    #[test]
    fn test_invalid_ciphertext_length() {
        let private_key = MLKem768::generate_private_key().expect("Failed to generate private key");

        // 测试无效的密文长度
        let invalid_ciphertext = vec![0u8; 100]; // 错误的长度
        let result = private_key.decapsulate(&invalid_ciphertext);
        assert!(
            result.is_err(),
            "Should fail with invalid ciphertext length"
        );
    }

    /// 压力测试 - 多次操作
    #[test]
    fn test_multiple_operations() {
        for i in 0..10 {
            let private_key = MLKem768::generate_private_key().expect(&format!(
                "Failed to generate private key on iteration {}",
                i
            ));
            let public_key = private_key.public_key();

            let (ciphertext, secret1) = public_key
                .encapsulate()
                .expect(&format!("Failed to encapsulate on iteration {}", i));
            let secret2 = private_key
                .decapsulate(&ciphertext)
                .expect(&format!("Failed to decapsulate on iteration {}", i));

            assert_eq!(
                secret1, secret2,
                "Shared secrets should match on iteration {}",
                i
            );
        }
    }
}

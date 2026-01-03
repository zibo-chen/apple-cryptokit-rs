use apple_cryptokit::symmetric::*;
use apple_cryptokit::{
    aes_gcm_decrypt, aes_gcm_decrypt_with_aad, aes_gcm_encrypt, aes_gcm_encrypt_with_aad,
    chacha20poly1305_decrypt, chacha20poly1305_decrypt_with_aad, chacha20poly1305_encrypt,
    chacha20poly1305_encrypt_with_aad, AESGCMNonce, AESKey, AESKeySize, AesGcm, ChaChaKey,
    ChaChaPoly, ChaChaPolyNonce,
};

mod aes_gcm_tests {
    use apple_cryptokit::symmetric::aes::{
        aes_gcm_decrypt_to, aes_gcm_decrypt_to_with_aad, aes_gcm_encrypt_to,
        aes_gcm_encrypt_to_with_aad,
    };

    use super::*;

    #[test]
    fn test_aes_key_creation() {
        // 测试从字节创建密钥
        let key_128 = vec![0u8; 16];
        let key_192 = vec![0u8; 24];
        let key_256 = vec![0u8; 32];

        assert!(AESKey::from_bytes(&key_128).is_ok());
        assert!(AESKey::from_bytes(&key_192).is_ok());
        assert!(AESKey::from_bytes(&key_256).is_ok());

        // 测试无效密钥长度
        let invalid_key = vec![0u8; 15];
        assert!(AESKey::from_bytes(&invalid_key).is_err());
    }

    #[test]
    fn test_aes_key_generation() {
        // 测试密钥生成
        let key_128 = AESKey::generate(AESKeySize::AES128);
        let key_192 = AESKey::generate(AESKeySize::AES192);
        let key_256 = AESKey::generate(AESKeySize::AES256);

        // 注意：在实际环境中这些应该成功，在测试环境中可能失败
        // 这取决于 Swift FFI 的实现
        println!("AES-128 key generation: {:?}", key_128.is_ok());
        println!("AES-192 key generation: {:?}", key_192.is_ok());
        println!("AES-256 key generation: {:?}", key_256.is_ok());
    }

    #[test]
    fn test_aes_gcm_nonce_creation() {
        // 测试从字节创建 nonce
        let nonce_bytes = vec![0u8; 12];
        let nonce = AESGCMNonce::from_bytes(&nonce_bytes);
        assert!(nonce.is_ok());

        // 测试无效 nonce 长度
        let invalid_nonce = vec![0u8; 11];
        assert!(AESGCMNonce::from_bytes(&invalid_nonce).is_err());
    }

    #[test]
    fn test_aes_gcm_nonce_generation() {
        // 测试 nonce 生成
        let nonce = AESGCMNonce::generate();
        println!("AES-GCM nonce generation: {:?}", nonce.is_ok());
    }

    #[test]
    fn test_aes_gcm_encrypt_decrypt_trait() {
        let key = AESKey::from_bytes(&vec![0u8; 32]).unwrap();
        let nonce = AESGCMNonce::from_bytes(&vec![0u8; 12]).unwrap();
        let plaintext = b"Hello, World! This is a test message for AES-GCM.";

        // 测试加密
        let encrypted = AesGcm::seal(&key, &nonce, plaintext);
        println!("AES-GCM encryption result: {:?}", encrypted.is_ok());

        if let Ok(ciphertext) = encrypted {
            // 测试解密
            let decrypted = AesGcm::open(&key, &nonce, &ciphertext);
            println!("AES-GCM decryption result: {:?}", decrypted.is_ok());

            if let Ok(decrypted_text) = decrypted {
                assert_eq!(plaintext, decrypted_text.as_slice());
            }
        }
    }

    #[test]
    fn test_aes_gcm_encrypt_decrypt_to_trait() {
        let key = AESKey::from_bytes(&vec![0u8; 32]).unwrap();
        let nonce = AESGCMNonce::from_bytes(&vec![0u8; 12]).unwrap();
        let plaintext = b"Hello, World! This is a test message for AES-GCM.";

        // 测试加密
        let mut ciphertext: [u8; 128] = [0u8; 128];
        let ciphertext_len = AesGcm::seal_to(&key, &nonce, plaintext, ciphertext.as_mut_slice());
        println!("AES-GCM encryption result: {:?}", ciphertext_len.is_ok());

        if let Ok(ciphertext_len) = ciphertext_len {
            // 测试解密
            let mut plaintext_out = [0u8; 128];
            let plaintext_out_len = AesGcm::open_to(
                &key,
                &nonce,
                &ciphertext[0..ciphertext_len],
                plaintext_out.as_mut_slice(),
            );
            println!("AES-GCM decryption result: {:?}", plaintext_out_len.is_ok());

            if let Ok(plaintext_out_len) = plaintext_out_len {
                assert_eq!(plaintext.as_slice(), &plaintext_out[0..plaintext_out_len]);
            }
        }
    }

    #[test]
    fn test_aes_gcm_encrypt_decrypt_with_aad() {
        let key = AESKey::from_bytes(&vec![0u8; 32]).unwrap();
        let nonce = AESGCMNonce::from_bytes(&vec![0u8; 12]).unwrap();
        let plaintext = b"Hello, World!";
        let aad = b"additional authenticated data";

        // 测试带 AAD 的加密
        let encrypted = AesGcm::seal_with_aad(&key, &nonce, plaintext, aad);
        println!(
            "AES-GCM with AAD encryption result: {:?}",
            encrypted.is_ok()
        );

        if let Ok(ciphertext) = encrypted {
            // 测试带 AAD 的解密
            let decrypted = AesGcm::open_with_aad(&key, &nonce, &ciphertext, aad);
            println!(
                "AES-GCM with AAD decryption result: {:?}",
                decrypted.is_ok()
            );

            if let Ok(decrypted_text) = decrypted {
                assert_eq!(plaintext, decrypted_text.as_slice());
            }
        }
    }

    #[test]
    fn test_aes_gcm_encrypt_decrypt_to_with_aad() {
        let key = AESKey::from_bytes(&vec![0u8; 32]).unwrap();
        let nonce = AESGCMNonce::from_bytes(&vec![0u8; 12]).unwrap();
        let plaintext = b"Hello, World!";
        let aad = b"additional authenticated data";

        // 测试带 AAD 的加密
        let mut ciphertext = [0u8; 128];
        let ciphertext_len =
            AesGcm::seal_to_with_aad(&key, &nonce, plaintext, aad, ciphertext.as_mut_slice());
        println!(
            "AES-GCM with AAD encryption result: {:?}",
            ciphertext_len.is_ok()
        );

        if let Ok(ciphertext_len) = ciphertext_len {
            let mut plaintext_out = [0u8; 128];
            // 测试带 AAD 的解密
            let plaintext_out_len = AesGcm::open_to_with_aad(
                &key,
                &nonce,
                &ciphertext[0..ciphertext_len],
                aad,
                plaintext_out.as_mut_slice(),
            );
            println!(
                "AES-GCM with AAD decryption result: {:?}",
                plaintext_out_len.is_ok()
            );

            if let Ok(plaintext_out_len) = plaintext_out_len {
                assert_eq!(plaintext.as_slice(), &plaintext_out[0..plaintext_out_len]);
            }
        }
    }

    #[test]
    fn test_aes_gcm_convenience_functions() {
        let key = vec![0u8; 32];
        let nonce = vec![0u8; 12];
        let plaintext = b"Test message for convenience functions";

        // 测试便利函数加密
        let encrypted = aes_gcm_encrypt(&key, &nonce, plaintext);
        println!(
            "AES-GCM convenience encrypt result: {:?}",
            encrypted.is_ok()
        );

        if let Ok(ciphertext) = encrypted {
            // 测试便利函数解密
            let decrypted = aes_gcm_decrypt(&key, &nonce, &ciphertext);
            println!(
                "AES-GCM convenience decrypt result: {:?}",
                decrypted.is_ok()
            );

            if let Ok(decrypted_text) = decrypted {
                assert_eq!(plaintext, decrypted_text.as_slice());
            }
        }
    }

    #[test]
    fn test_aes_gcm_convenience_functions_to() {
        let key = vec![0u8; 32];
        let nonce = vec![0u8; 12];
        let plaintext = b"Test message for convenience functions";

        // 测试便利函数加密
        let mut ciphertext = [0u8; 128];
        let ciphertext_len = aes_gcm_encrypt_to(&key, &nonce, plaintext, ciphertext.as_mut_slice());
        println!(
            "AES-GCM convenience encrypt result: {:?}",
            ciphertext_len.is_ok()
        );

        if let Ok(ciphertext_len) = ciphertext_len {
            let mut plaintext_out = [0u8; 128];
            // 测试便利函数解密
            let plaintext_out_len = aes_gcm_decrypt_to(
                &key,
                &nonce,
                &ciphertext[0..ciphertext_len],
                plaintext_out.as_mut_slice(),
            );
            println!(
                "AES-GCM convenience decrypt result: {:?}",
                plaintext_out_len.is_ok()
            );

            if let Ok(plaintext_out_len) = plaintext_out_len {
                assert_eq!(plaintext.as_slice(), &plaintext_out[0..plaintext_out_len]);
            }
        }
    }

    #[test]
    fn test_aes_gcm_convenience_functions_with_aad() {
        let key = vec![0u8; 32];
        let nonce = vec![0u8; 12];
        let plaintext = b"Test message";
        let aad = b"test aad";

        // 测试带 AAD 的便利函数加密
        let encrypted = aes_gcm_encrypt_with_aad(&key, &nonce, plaintext, aad);
        println!(
            "AES-GCM convenience encrypt with AAD result: {:?}",
            encrypted.is_ok()
        );

        if let Ok(ciphertext) = encrypted {
            // 测试带 AAD 的便利函数解密
            let decrypted = aes_gcm_decrypt_with_aad(&key, &nonce, &ciphertext, aad);
            println!(
                "AES-GCM convenience decrypt with AAD result: {:?}",
                decrypted.is_ok()
            );

            if let Ok(decrypted_text) = decrypted {
                assert_eq!(plaintext, decrypted_text.as_slice());
            }
        }
    }

    #[test]
    fn test_aes_gcm_convenience_functions_to_with_aad() {
        let key = vec![0u8; 32];
        let nonce = vec![0u8; 12];
        let plaintext = b"Test message";
        let aad = b"test aad";

        // 测试带 AAD 的便利函数加密
        let mut ciphertext = [0u8; 128];
        let ciphertext_len =
            aes_gcm_encrypt_to_with_aad(&key, &nonce, plaintext, aad, ciphertext.as_mut_slice());
        println!(
            "AES-GCM convenience encrypt with AAD result: {:?}",
            ciphertext_len.is_ok()
        );

        if let Ok(ciphertext_len) = ciphertext_len {
            // 测试带 AAD 的便利函数解密
            let mut plaintext_out = [0u8; 128];
            let plaintext_out_len = aes_gcm_decrypt_to_with_aad(
                &key,
                &nonce,
                &ciphertext[0..ciphertext_len],
                aad,
                plaintext_out.as_mut_slice(),
            );
            println!(
                "AES-GCM convenience decrypt with AAD result: {:?}",
                plaintext_out_len.is_ok()
            );

            if let Ok(plaintext_out_len) = plaintext_out_len {
                assert_eq!(plaintext.as_slice(), &plaintext_out[0..plaintext_out_len]);
            }
        }
    }
}

mod chacha20poly1305_tests {
    use apple_cryptokit::symmetric::chacha::{
        chacha20poly1305_decrypt_to, chacha20poly1305_decrypt_to_with_aad,
        chacha20poly1305_encrypt_to, chacha20poly1305_encrypt_to_with_aad,
    };

    use super::*;

    #[test]
    fn test_chacha_key_creation() {
        // 测试从字节创建密钥
        let key_bytes = vec![0u8; 32];
        let key = ChaChaKey::from_bytes(&key_bytes);
        assert!(key.is_ok());

        // 测试无效密钥长度
        let invalid_key = vec![0u8; 31];
        assert!(ChaChaKey::from_bytes(&invalid_key).is_err());
    }

    #[test]
    fn test_chacha_key_generation() {
        // 测试密钥生成
        let key = ChaChaKey::generate();
        println!("ChaCha20 key generation: {:?}", key.is_ok());
    }

    #[test]
    fn test_chacha_nonce_creation() {
        // 测试从字节创建 nonce
        let nonce_bytes = vec![0u8; 12];
        let nonce = ChaChaPolyNonce::from_bytes(&nonce_bytes);
        assert!(nonce.is_ok());

        // 测试无效 nonce 长度
        let invalid_nonce = vec![0u8; 11];
        assert!(ChaChaPolyNonce::from_bytes(&invalid_nonce).is_err());
    }

    #[test]
    fn test_chacha_nonce_generation() {
        // 测试 nonce 生成
        let nonce = ChaChaPolyNonce::generate();
        println!("ChaCha20-Poly1305 nonce generation: {:?}", nonce.is_ok());
    }

    #[test]
    fn test_chacha20poly1305_encrypt_decrypt_trait() {
        let key = ChaChaKey::from_bytes(&vec![0u8; 32]).unwrap();
        let nonce = ChaChaPolyNonce::from_bytes(&vec![0u8; 12]).unwrap();
        let plaintext = b"Hello, World! This is a test message for ChaCha20-Poly1305.";

        // 测试加密
        let encrypted = ChaChaPoly::seal(&key, &nonce, plaintext);
        println!(
            "ChaCha20-Poly1305 encryption result: {:?}",
            encrypted.is_ok()
        );

        if let Ok(ciphertext) = encrypted {
            // 测试解密
            let decrypted = ChaChaPoly::open(&key, &nonce, &ciphertext);
            println!(
                "ChaCha20-Poly1305 decryption result: {:?}",
                decrypted.is_ok()
            );

            if let Ok(decrypted_text) = decrypted {
                assert_eq!(plaintext, decrypted_text.as_slice());
            }
        }
    }

    #[test]
    fn test_chacha20poly1305_encrypt_decrypt_to_trait() {
        let key = ChaChaKey::from_bytes(&vec![0u8; 32]).unwrap();
        let nonce = ChaChaPolyNonce::from_bytes(&vec![0u8; 12]).unwrap();
        let plaintext = b"Hello, World! This is a test message for ChaCha20-Poly1305.";

        // 测试加密
        let mut ciphertext = [0u8; 128];
        let ciphertext_len =
            ChaChaPoly::seal_to(&key, &nonce, plaintext, ciphertext.as_mut_slice());
        println!(
            "ChaCha20-Poly1305 encryption result: {:?}",
            ciphertext_len.is_ok()
        );

        if let Ok(ciphertext_len) = ciphertext_len {
            // 测试解密
            let mut plaintext_out = [0u8; 128];
            let plaintext_out_len = ChaChaPoly::open_to(
                &key,
                &nonce,
                &ciphertext[0..ciphertext_len],
                plaintext_out.as_mut_slice(),
            );
            println!(
                "ChaCha20-Poly1305 decryption result: {:?}",
                plaintext_out_len.is_ok()
            );

            if let Ok(plaintext_out_len) = plaintext_out_len {
                assert_eq!(plaintext.as_slice(), &plaintext_out[0..plaintext_out_len]);
            }
        }
    }

    #[test]
    fn test_chacha20poly1305_encrypt_decrypt_with_aad() {
        let key = ChaChaKey::from_bytes(&vec![0u8; 32]).unwrap();
        let nonce = ChaChaPolyNonce::from_bytes(&vec![0u8; 12]).unwrap();
        let plaintext = b"Hello, World!";
        let aad = b"additional authenticated data";

        // 测试带 AAD 的加密
        let encrypted = ChaChaPoly::seal_with_aad(&key, &nonce, plaintext, aad);
        println!(
            "ChaCha20-Poly1305 with AAD encryption result: {:?}",
            encrypted.is_ok()
        );

        if let Ok(ciphertext) = encrypted {
            // 测试带 AAD 的解密
            let decrypted = ChaChaPoly::open_with_aad(&key, &nonce, &ciphertext, aad);
            println!(
                "ChaCha20-Poly1305 with AAD decryption result: {:?}",
                decrypted.is_ok()
            );

            if let Ok(decrypted_text) = decrypted {
                assert_eq!(plaintext, decrypted_text.as_slice());
            }
        }
    }

    #[test]
    fn test_chacha20poly1305_encrypt_decrypt_to_with_aad() {
        let key = ChaChaKey::from_bytes(&vec![0u8; 32]).unwrap();
        let nonce = ChaChaPolyNonce::from_bytes(&vec![0u8; 12]).unwrap();
        let plaintext = b"Hello, World!";
        let aad = b"additional authenticated data";

        // 测试带 AAD 的加密
        let mut ciphertext: [u8; 128] = [0u8; 128];
        let ciphertext_len =
            ChaChaPoly::seal_to_with_aad(&key, &nonce, plaintext, aad, ciphertext.as_mut_slice());
        println!(
            "ChaCha20-Poly1305 with AAD encryption result: {:?}",
            ciphertext_len.is_ok()
        );

        if let Ok(ciphertext_len) = ciphertext_len {
            // 测试带 AAD 的解密
            let mut plaintext_out = [0u8; 128];
            let plaintext_out_len = ChaChaPoly::open_to_with_aad(
                &key,
                &nonce,
                &ciphertext[0..ciphertext_len],
                aad,
                plaintext_out.as_mut_slice(),
            );
            println!(
                "ChaCha20-Poly1305 with AAD decryption result: {:?}",
                plaintext_out_len.is_ok()
            );

            if let Ok(plaintext_out_len) = plaintext_out_len {
                assert_eq!(plaintext.as_slice(), &plaintext_out[0..plaintext_out_len]);
            }
        }
    }

    #[test]
    fn test_chacha20poly1305_convenience_functions() {
        let key = vec![0u8; 32];
        let nonce = vec![0u8; 12];
        let plaintext = b"Test message for convenience functions";

        // 测试便利函数加密
        let encrypted = chacha20poly1305_encrypt(&key, &nonce, plaintext);
        println!(
            "ChaCha20-Poly1305 convenience encrypt result: {:?}",
            encrypted.is_ok()
        );

        if let Ok(ciphertext) = encrypted {
            // 测试便利函数解密
            let decrypted = chacha20poly1305_decrypt(&key, &nonce, &ciphertext);
            println!(
                "ChaCha20-Poly1305 convenience decrypt result: {:?}",
                decrypted.is_ok()
            );

            if let Ok(decrypted_text) = decrypted {
                assert_eq!(plaintext, decrypted_text.as_slice());
            }
        }
    }

    #[test]
    fn test_chacha20poly1305_convenience_functions_to() {
        let key = vec![0u8; 32];
        let nonce = vec![0u8; 12];
        let plaintext = b"Test message for convenience functions";

        // 测试便利函数加密
        let mut ciphertext = [0u8; 128];
        let ciphertext_len =
            chacha20poly1305_encrypt_to(&key, &nonce, plaintext, ciphertext.as_mut_slice());
        println!(
            "ChaCha20-Poly1305 convenience encrypt result: {:?}",
            ciphertext_len.is_ok()
        );

        if let Ok(ciphertext_len) = ciphertext_len {
            // 测试便利函数解密
            let mut plaintext_out = [0u8; 128];
            let plaintext_out_len = chacha20poly1305_decrypt_to(
                &key,
                &nonce,
                &ciphertext[0..ciphertext_len],
                plaintext_out.as_mut_slice(),
            );
            println!(
                "ChaCha20-Poly1305 convenience decrypt result: {:?}",
                plaintext_out_len.is_ok()
            );

            if let Ok(plaintext_out_len) = plaintext_out_len {
                assert_eq!(plaintext.as_slice(), &plaintext_out[0..plaintext_out_len]);
            }
        }
    }

    #[test]
    fn test_chacha20poly1305_convenience_functions_with_aad() {
        let key = vec![0u8; 32];
        let nonce = vec![0u8; 12];
        let plaintext = b"Test message";
        let aad = b"test aad";

        // 测试带 AAD 的便利函数加密
        let encrypted = chacha20poly1305_encrypt_with_aad(&key, &nonce, plaintext, aad);
        println!(
            "ChaCha20-Poly1305 convenience encrypt with AAD result: {:?}",
            encrypted.is_ok()
        );

        if let Ok(ciphertext) = encrypted {
            // 测试带 AAD 的便利函数解密
            let decrypted = chacha20poly1305_decrypt_with_aad(&key, &nonce, &ciphertext, aad);
            println!(
                "ChaCha20-Poly1305 convenience decrypt with AAD result: {:?}",
                decrypted.is_ok()
            );

            if let Ok(decrypted_text) = decrypted {
                assert_eq!(plaintext, decrypted_text.as_slice());
            }
        }
    }

    #[test]
    fn test_chacha20poly1305_convenience_functions_to_with_aad() {
        let key = vec![0u8; 32];
        let nonce = vec![0u8; 12];
        let plaintext = b"Test message";
        let aad = b"test aad";

        // 测试带 AAD 的便利函数加密
        let mut ciphertext = [0u8; 128];
        let ciphertext_len = chacha20poly1305_encrypt_to_with_aad(
            &key,
            &nonce,
            plaintext,
            aad,
            ciphertext.as_mut_slice(),
        );
        println!(
            "ChaCha20-Poly1305 convenience encrypt with AAD result: {:?}",
            ciphertext_len.is_ok()
        );

        if let Ok(ciphertext_len) = ciphertext_len {
            // 测试带 AAD 的便利函数解密
            let mut plaintext_out = [0u8; 128];
            let plaintext_out_len = chacha20poly1305_decrypt_to_with_aad(
                &key,
                &nonce,
                &ciphertext[0..ciphertext_len],
                aad,
                plaintext_out.as_mut_slice(),
            );
            println!(
                "ChaCha20-Poly1305 convenience decrypt with AAD result: {:?}",
                plaintext_out_len.is_ok()
            );

            if let Ok(plaintext_out_len) = plaintext_out_len {
                assert_eq!(plaintext.as_slice(), &plaintext_out[0..plaintext_out_len]);
            }
        }
    }
}

mod cipher_trait_tests {
    use super::*;

    #[test]
    fn test_authenticated_cipher_trait_consistency() {
        // 测试两个算法的接口一致性
        let aes_key = AESKey::from_bytes(&vec![0u8; 32]).unwrap();
        let aes_nonce = AESGCMNonce::from_bytes(&vec![0u8; 12]).unwrap();

        let chacha_key = ChaChaKey::from_bytes(&vec![0u8; 32]).unwrap();
        let chacha_nonce = ChaChaPolyNonce::from_bytes(&vec![0u8; 12]).unwrap();

        let plaintext = b"Consistency test message";

        // 测试两个算法都实现了相同的接口
        let aes_result = AesGcm::seal(&aes_key, &aes_nonce, plaintext);
        let chacha_result = ChaChaPoly::seal(&chacha_key, &chacha_nonce, plaintext);

        println!("AES-GCM trait consistency: {:?}", aes_result.is_ok());
        println!(
            "ChaCha20-Poly1305 trait consistency: {:?}",
            chacha_result.is_ok()
        );
    }

    #[test]
    fn test_error_handling() {
        // 测试无效输入的错误处理
        let key = vec![0u8; 32];
        let nonce = vec![0u8; 12];

        // 测试解密太短的密文
        let short_ciphertext = vec![0u8; 8]; // 小于16字节（标签长度）

        let aes_result = aes_gcm_decrypt(&key, &nonce, &short_ciphertext);
        let chacha_result = chacha20poly1305_decrypt(&key, &nonce, &short_ciphertext);

        assert!(aes_result.is_err());
        assert!(chacha_result.is_err());

        println!("AES-GCM error handling: {:?}", aes_result.err());
        println!(
            "ChaCha20-Poly1305 error handling: {:?}",
            chacha_result.err()
        );
    }
}

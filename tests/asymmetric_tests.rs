use apple_cryptokit::asymmetric::curve25519::{Ed25519, X25519};
use apple_cryptokit::asymmetric::p256::P256;
use apple_cryptokit::asymmetric::p384::P384;
use apple_cryptokit::asymmetric::p521::P521;
use apple_cryptokit::asymmetric::{KeyAgreement, SignatureAlgorithm};

#[cfg(test)]
mod curve25519_tests {
    use super::*;
    use apple_cryptokit::asymmetric::curve25519;

    #[test]
    fn test_ed25519_keypair_generation() {
        let result = curve25519::ed25519_generate_keypair();
        assert!(result.is_ok(), "Ed25519 keypair generation should succeed");

        let (private_key, public_key) = result.unwrap();
        assert_eq!(private_key.as_bytes().len(), 32);
        assert_eq!(public_key.as_bytes().len(), 32);
    }

    #[test]
    fn test_ed25519_sign_and_verify() {
        let (private_key, public_key) =
            curve25519::ed25519_generate_keypair().expect("Failed to generate Ed25519 keypair");

        let test_data = b"Hello, Ed25519!";

        // 签名
        let signature =
            curve25519::ed25519_sign(&private_key, test_data).expect("Failed to sign data");

        assert_eq!(signature.as_bytes().len(), 64);

        // 验证
        let is_valid = curve25519::ed25519_verify(&public_key, &signature, test_data)
            .expect("Failed to verify signature");

        assert!(is_valid, "Signature should be valid");

        // 验证错误的数据应该失败
        let wrong_data = b"Wrong data";
        let is_invalid = curve25519::ed25519_verify(&public_key, &signature, wrong_data)
            .expect("Failed to verify wrong signature");

        assert!(!is_invalid, "Signature should be invalid for wrong data");
    }

    #[test]
    fn test_x25519_keypair_generation() {
        let result = curve25519::x25519_generate_keypair();
        assert!(result.is_ok(), "X25519 keypair generation should succeed");

        let (private_key, public_key) = result.unwrap();
        assert_eq!(private_key.as_bytes().len(), 32);
        assert_eq!(public_key.as_bytes().len(), 32);
    }

    #[test]
    fn test_x25519_key_agreement() {
        // Alice 的密钥对
        let (alice_private, alice_public) =
            curve25519::x25519_generate_keypair().expect("Failed to generate Alice's keypair");

        // Bob 的密钥对
        let (bob_private, bob_public) =
            curve25519::x25519_generate_keypair().expect("Failed to generate Bob's keypair");

        // Alice 计算共享密钥
        let alice_shared = curve25519::x25519_key_agreement(&alice_private, &bob_public)
            .expect("Alice's key agreement failed");

        // Bob 计算共享密钥
        let bob_shared = curve25519::x25519_key_agreement(&bob_private, &alice_public)
            .expect("Bob's key agreement failed");

        // 共享密钥应该相同
        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
        assert_eq!(alice_shared.as_bytes().len(), 32);
    }

    #[test]
    fn test_ed25519_trait_implementation() {
        // 测试通过 trait 使用 Ed25519
        let (private_key, public_key) =
            Ed25519::generate_key_pair().expect("Failed to generate keypair via trait");

        let test_data = b"Trait test data";

        let signature = Ed25519::sign(&private_key, test_data).expect("Failed to sign via trait");

        let is_valid = Ed25519::verify(&public_key, &signature, test_data)
            .expect("Failed to verify via trait");

        assert!(is_valid, "Trait-based signature should be valid");
    }

    #[test]
    fn test_x25519_trait_implementation() {
        // 测试通过 trait 使用 X25519
        let (alice_private, alice_public) =
            X25519::generate_key_pair().expect("Failed to generate Alice's keypair via trait");

        let (bob_private, bob_public) =
            X25519::generate_key_pair().expect("Failed to generate Bob's keypair via trait");

        let alice_shared = X25519::key_agreement(&alice_private, &bob_public)
            .expect("Alice's trait-based key agreement failed");

        let bob_shared = X25519::key_agreement(&bob_private, &alice_public)
            .expect("Bob's trait-based key agreement failed");

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }
}

#[cfg(test)]
mod p256_tests {
    use super::*;
    use apple_cryptokit::asymmetric::p256;

    #[test]
    fn test_p256_keypair_generation() {
        let result = p256::generate_keypair();
        assert!(result.is_ok(), "P256 keypair generation should succeed");

        let (private_key, public_key) = result.unwrap();
        assert_eq!(private_key.as_bytes().len(), 32);
        assert_eq!(public_key.as_bytes().len(), 64);
    }

    #[test]
    fn test_p256_sign_and_verify() {
        let (private_key, public_key) =
            p256::generate_keypair().expect("Failed to generate P256 keypair");

        let test_data = b"Hello, P-256!";

        // 签名
        let signature = p256::sign(&private_key, test_data).expect("Failed to sign data");

        assert_eq!(signature.as_bytes().len(), 64);

        // 验证
        let is_valid =
            p256::verify(&public_key, &signature, test_data).expect("Failed to verify signature");

        assert!(is_valid, "Signature should be valid");
    }

    #[test]
    fn test_p256_key_agreement() {
        let (alice_private, alice_public) =
            p256::generate_keypair().expect("Failed to generate Alice's P256 keypair");

        let (bob_private, bob_public) =
            p256::generate_keypair().expect("Failed to generate Bob's P256 keypair");

        let alice_shared = p256::key_agreement(&alice_private, &bob_public)
            .expect("Alice's P256 key agreement failed");

        let bob_shared = p256::key_agreement(&bob_private, &alice_public)
            .expect("Bob's P256 key agreement failed");

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
        assert_eq!(alice_shared.as_bytes().len(), 32);
    }

    #[test]
    fn test_p256_trait_implementation() {
        let (private_key, public_key) = <P256 as SignatureAlgorithm>::generate_key_pair()
            .expect("Failed to generate P256 keypair via trait");

        let test_data = b"P256 trait test";

        let signature = P256::sign(&private_key, test_data).expect("Failed to sign via trait");

        let is_valid =
            P256::verify(&public_key, &signature, test_data).expect("Failed to verify via trait");

        assert!(is_valid, "P256 trait-based signature should be valid");
    }
}

#[cfg(test)]
mod p384_tests {
    use super::*;
    use apple_cryptokit::asymmetric::p384;

    #[test]
    fn test_p384_keypair_generation() {
        let result = p384::generate_keypair();
        assert!(result.is_ok(), "P384 keypair generation should succeed");

        let (private_key, public_key) = result.unwrap();
        assert_eq!(private_key.as_bytes().len(), 48);
        assert_eq!(public_key.as_bytes().len(), 96);
    }

    #[test]
    fn test_p384_sign_and_verify() {
        let (private_key, public_key) =
            p384::generate_keypair().expect("Failed to generate P384 keypair");

        let test_data = b"Hello, P-384!";

        let signature = p384::sign(&private_key, test_data).expect("Failed to sign data");

        assert_eq!(signature.as_bytes().len(), 96);

        let is_valid =
            p384::verify(&public_key, &signature, test_data).expect("Failed to verify signature");

        assert!(is_valid, "P384 signature should be valid");
    }

    #[test]
    fn test_p384_key_agreement() {
        let (alice_private, alice_public) =
            p384::generate_keypair().expect("Failed to generate Alice's P384 keypair");

        let (bob_private, bob_public) =
            p384::generate_keypair().expect("Failed to generate Bob's P384 keypair");

        let alice_shared = p384::key_agreement(&alice_private, &bob_public)
            .expect("Alice's P384 key agreement failed");

        let bob_shared = p384::key_agreement(&bob_private, &alice_public)
            .expect("Bob's P384 key agreement failed");

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
        assert_eq!(alice_shared.as_bytes().len(), 48);
    }

    #[test]
    fn test_p384_trait_implementation() {
        let (private_key, public_key) = <P384 as SignatureAlgorithm>::generate_key_pair()
            .expect("Failed to generate P384 keypair via trait");

        let test_data = b"P384 trait test";

        let signature = P384::sign(&private_key, test_data).expect("Failed to sign via trait");

        let is_valid =
            P384::verify(&public_key, &signature, test_data).expect("Failed to verify via trait");

        assert!(is_valid, "P384 trait-based signature should be valid");
    }
}

#[cfg(test)]
mod p521_tests {
    use super::*;
    use apple_cryptokit::asymmetric::p521;

    #[test]
    fn test_p521_keypair_generation() {
        let result = p521::generate_keypair();
        assert!(result.is_ok(), "P521 keypair generation should succeed");

        let (private_key, public_key) = result.unwrap();
        assert_eq!(private_key.as_bytes().len(), 66);
        assert_eq!(public_key.as_bytes().len(), 132);
    }

    #[test]
    fn test_p521_sign_and_verify() {
        let (private_key, public_key) =
            p521::generate_keypair().expect("Failed to generate P521 keypair");

        let test_data = b"Hello, P-521!";

        let signature = p521::sign(&private_key, test_data).expect("Failed to sign data");

        assert_eq!(signature.as_bytes().len(), 132);

        let is_valid =
            p521::verify(&public_key, &signature, test_data).expect("Failed to verify signature");

        assert!(is_valid, "P521 signature should be valid");
    }

    #[test]
    fn test_p521_key_agreement() {
        let (alice_private, alice_public) =
            p521::generate_keypair().expect("Failed to generate Alice's P521 keypair");

        let (bob_private, bob_public) =
            p521::generate_keypair().expect("Failed to generate Bob's P521 keypair");

        let alice_shared = p521::key_agreement(&alice_private, &bob_public)
            .expect("Alice's P521 key agreement failed");

        let bob_shared = p521::key_agreement(&bob_private, &alice_public)
            .expect("Bob's P521 key agreement failed");

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
        assert_eq!(alice_shared.as_bytes().len(), 66);
    }

    #[test]
    fn test_p521_trait_implementation() {
        let (private_key, public_key) = <P521 as SignatureAlgorithm>::generate_key_pair()
            .expect("Failed to generate P521 keypair via trait");

        let test_data = b"P521 trait test";

        let signature = P521::sign(&private_key, test_data).expect("Failed to sign via trait");

        let is_valid =
            P521::verify(&public_key, &signature, test_data).expect("Failed to verify via trait");

        assert!(is_valid, "P521 trait-based signature should be valid");
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_different_algorithms_interoperability() {
        // 测试不同算法的密钥对是否有正确的大小
        let (ed25519_priv, ed25519_pub) =
            Ed25519::generate_key_pair().expect("Ed25519 keypair generation failed");
        let (p256_priv, p256_pub) = <P256 as SignatureAlgorithm>::generate_key_pair()
            .expect("P256 keypair generation failed");
        let (p384_priv, p384_pub) = <P384 as SignatureAlgorithm>::generate_key_pair()
            .expect("P384 keypair generation failed");
        let (p521_priv, p521_pub) = <P521 as SignatureAlgorithm>::generate_key_pair()
            .expect("P521 keypair generation failed");

        // 验证密钥大小
        assert_eq!(ed25519_priv.as_bytes().len(), 32);
        assert_eq!(ed25519_pub.as_bytes().len(), 32);

        assert_eq!(p256_priv.as_bytes().len(), 32);
        assert_eq!(p256_pub.as_bytes().len(), 64);

        assert_eq!(p384_priv.as_bytes().len(), 48);
        assert_eq!(p384_pub.as_bytes().len(), 96);

        assert_eq!(p521_priv.as_bytes().len(), 66);
        assert_eq!(p521_pub.as_bytes().len(), 132);
    }

    #[test]
    fn test_signature_lengths() {
        let test_data = b"Test signature lengths";

        // Ed25519
        let (ed25519_priv, _) = Ed25519::generate_key_pair().unwrap();
        let ed25519_sig = Ed25519::sign(&ed25519_priv, test_data).unwrap();
        assert_eq!(ed25519_sig.as_bytes().len(), 64);

        // P256
        let (p256_priv, _) = <P256 as SignatureAlgorithm>::generate_key_pair().unwrap();
        let p256_sig = P256::sign(&p256_priv, test_data).unwrap();
        assert_eq!(p256_sig.as_bytes().len(), 64);

        // P384
        let (p384_priv, _) = <P384 as SignatureAlgorithm>::generate_key_pair().unwrap();
        let p384_sig = P384::sign(&p384_priv, test_data).unwrap();
        assert_eq!(p384_sig.as_bytes().len(), 96);

        // P521
        let (p521_priv, _) = <P521 as SignatureAlgorithm>::generate_key_pair().unwrap();
        let p521_sig = P521::sign(&p521_priv, test_data).unwrap();
        assert_eq!(p521_sig.as_bytes().len(), 132);
    }

    #[test]
    fn test_shared_secret_lengths() {
        // X25519
        let (x25519_priv1, _x25519_pub1) = X25519::generate_key_pair().unwrap();
        let (_x25519_priv2, x25519_pub2) = X25519::generate_key_pair().unwrap();
        let x25519_shared = X25519::key_agreement(&x25519_priv1, &x25519_pub2).unwrap();
        assert_eq!(x25519_shared.as_bytes().len(), 32);

        // P256
        let (p256_priv1, _p256_pub1) = <P256 as KeyAgreement>::generate_key_pair().unwrap();
        let (_p256_priv2, p256_pub2) = <P256 as KeyAgreement>::generate_key_pair().unwrap();
        let p256_shared = P256::key_agreement(&p256_priv1, &p256_pub2).unwrap();
        assert_eq!(p256_shared.as_bytes().len(), 32);

        // P384
        let (p384_priv1, _p384_pub1) = <P384 as KeyAgreement>::generate_key_pair().unwrap();
        let (_p384_priv2, p384_pub2) = <P384 as KeyAgreement>::generate_key_pair().unwrap();
        let p384_shared = P384::key_agreement(&p384_priv1, &p384_pub2).unwrap();
        assert_eq!(p384_shared.as_bytes().len(), 48);

        // P521
        let (p521_priv1, _p521_pub1) = <P521 as KeyAgreement>::generate_key_pair().unwrap();
        let (_p521_priv2, p521_pub2) = <P521 as KeyAgreement>::generate_key_pair().unwrap();
        let p521_shared = P521::key_agreement(&p521_priv1, &p521_pub2).unwrap();
        assert_eq!(p521_shared.as_bytes().len(), 66);
    }
}

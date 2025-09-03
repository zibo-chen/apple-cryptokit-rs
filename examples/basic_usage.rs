//! # Apple CryptoKit for Rust - Basic Usage Examples
//!
//! This example demonstrates the basic usage of various cryptographic functions
//! provided by the apple-cryptokit-rs library, including traditional and post-quantum
//! cryptography algorithms.

use apple_cryptokit::{
    Result,
    // Asymmetric Cryptography
    asymmetric::p256::{generate_keypair, sign, verify},
    // HMAC Authentication
    authentication::hmac_sha256,
    // Hashing
    hashing::{HashAlgorithm, HashFunction, SHA256, sha256_hash},
    // Key Derivation
    key_derivation::hkdf_sha256_derive,
    // Post-Quantum Cryptography
    quantum::{
        DigitalSignatureAlgorithm, KEMPrivateKey, KEMPublicKey, KeyEncapsulationMechanism, MLDsa65,
        MLKem768, SignaturePrivateKey, SignaturePublicKey, XWingMLKem768X25519,
    },
    // Symmetric Encryption
    symmetric::aes::{aes_gcm_decrypt, aes_gcm_encrypt},
};

fn main() -> Result<()> {
    println!("Apple CryptoKit for Rust - Basic Usage Examples");
    println!("===================================================\n");

    // 1. Hashing Examples
    hashing_examples()?;

    // 2. Message Authentication Examples
    authentication_examples()?;

    // 3. Symmetric Encryption Examples
    symmetric_encryption_examples()?;

    // 4. Key Derivation Examples
    key_derivation_examples()?;

    // 5. Asymmetric Cryptography Examples
    asymmetric_examples()?;

    // 6. Post-Quantum Cryptography Examples
    post_quantum_examples()?;

    println!("\nAll examples completed successfully!");
    Ok(())
}

/// Demonstrates various hashing algorithms
fn hashing_examples() -> Result<()> {
    println!("Hashing Examples");
    println!("------------------");

    let data = b"Hello, Apple CryptoKit!";

    // Using convenience functions
    let hash = sha256_hash(data);
    println!("SHA256 hash: {}", hex::encode(hash));

    // Using trait interface
    let hash_trait = SHA256::hash(data);
    println!("SHA256 (trait): {}", hex::encode(hash_trait));

    // Using dynamic algorithm selection
    let algorithm = HashAlgorithm::Sha256;
    let dynamic_hash = algorithm.compute(data);
    println!("SHA256 (dynamic): {}\n", hex::encode(dynamic_hash));

    Ok(())
}

/// Demonstrates HMAC message authentication
fn authentication_examples() -> Result<()> {
    println!("Message Authentication Examples");
    println!("----------------------------------");

    let key = b"my-secret-key";
    let message = b"Important message to authenticate";

    let mac = hmac_sha256(key, message)?;
    println!("HMAC-SHA256: {}", hex::encode(mac));

    // Verify HMAC by computing again
    let verify_mac = hmac_sha256(key, message)?;
    let is_valid = mac == verify_mac;
    println!(
        "HMAC verification: {}\n",
        if is_valid { "Valid" } else { "❌ Invalid" }
    );

    Ok(())
}

/// Demonstrates symmetric encryption with AES-GCM
fn symmetric_encryption_examples() -> Result<()> {
    println!("Symmetric Encryption Examples");
    println!("---------------------------------");

    let key = b"0123456789abcdef0123456789abcdef"; // 32-byte key for AES-256
    let nonce = b"unique12byte"; // 12-byte nonce for GCM
    let plaintext = b"This is a secret message that needs encryption!";

    // Encrypt
    let ciphertext = aes_gcm_encrypt(key, nonce, plaintext)?;
    println!("Plaintext: {}", String::from_utf8_lossy(plaintext));
    println!("Ciphertext: {}", hex::encode(&ciphertext));

    // Decrypt
    let decrypted = aes_gcm_decrypt(key, nonce, &ciphertext)?;
    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));

    let success = plaintext == decrypted.as_slice();
    println!(
        "Encryption/Decryption: {}\n",
        if success { "Success" } else { "Failed" }
    );

    Ok(())
}

/// Demonstrates key derivation using HKDF
fn key_derivation_examples() -> Result<()> {
    println!("Key Derivation Examples");
    println!("--------------------------");

    let input_key_material = b"shared-secret-from-key-exchange";
    let salt = b"random-salt";
    let info = b"application-specific-context";
    let output_length = 32; // 256 bits

    let derived_key = hkdf_sha256_derive(input_key_material, salt, info, output_length)?;
    println!("Input key material: {}", hex::encode(input_key_material));
    println!("Derived key (32 bytes): {}\n", hex::encode(derived_key));

    Ok(())
}

/// Demonstrates asymmetric cryptography with P-256
fn asymmetric_examples() -> Result<()> {
    println!("Asymmetric Cryptography Examples");
    println!("------------------------------------");

    // Generate key pair
    let (private_key, public_key) = generate_keypair()?;

    println!("Generated P-256 key pair");

    // Sign a message
    let message = b"Document to be signed";
    let signature = sign(&private_key, message)?;
    println!("Message: {}", String::from_utf8_lossy(message));
    println!("Signature: {}", hex::encode(signature.as_bytes()));

    // Verify signature
    let is_valid = verify(&public_key, &signature, message)?;
    println!(
        "Signature verification: {}\n",
        if is_valid { "Valid" } else { "Invalid" }
    );

    Ok(())
}

/// Demonstrates post-quantum cryptography
fn post_quantum_examples() -> Result<()> {
    println!("Post-Quantum Cryptography Examples");
    println!("--------------------------------------");

    // ML-KEM768 Key Encapsulation Mechanism
    println!("ML-KEM768 (Quantum-resistant KEM):");
    let kem_private = MLKem768::generate_private_key()?;
    let kem_public = kem_private.public_key();

    let (ciphertext, shared_secret) = kem_public.encapsulate()?;
    let decapsulated_secret = kem_private.decapsulate(&ciphertext)?;

    let kem_success = shared_secret == decapsulated_secret;
    println!("   Shared secret length: {} bytes", shared_secret.len());
    println!(
        "   Encapsulation/Decapsulation: {}",
        if kem_success { "Success" } else { "Failed" }
    );

    // X-Wing Hybrid KEM (ML-KEM768 + X25519)
    println!("\nX-Wing (Hybrid ML-KEM768 + X25519):");
    let xwing_private = XWingMLKem768X25519::generate_private_key()?;
    let xwing_public = xwing_private.public_key();

    let (xwing_ciphertext, xwing_secret) = xwing_public.encapsulate()?;
    let xwing_decapsulated = xwing_private.decapsulate(&xwing_ciphertext)?;

    let xwing_success = xwing_secret == xwing_decapsulated;
    println!("   Shared secret length: {} bytes", xwing_secret.len());
    println!(
        "   Hybrid KEM: {}",
        if xwing_success { "Success" } else { "Failed" }
    );

    // ML-DSA65 Digital Signature Algorithm
    println!("\nML-DSA65 (Quantum-resistant signatures):");
    let dsa_private = MLDsa65::generate_private_key()?;
    let dsa_public = dsa_private.public_key();

    let pq_message = b"Hello, post-quantum world!";
    let pq_signature = dsa_private.sign(pq_message)?;
    let pq_valid = dsa_public.verify(pq_message, &pq_signature)?;

    println!("   Message: {}", String::from_utf8_lossy(pq_message));
    println!("   Signature length: {} bytes", pq_signature.len());
    println!(
        "   Signature verification: {}\n",
        if pq_valid { "Valid" } else { "Invalid" }
    );

    Ok(())
}

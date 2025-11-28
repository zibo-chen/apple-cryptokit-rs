//! # Apple CryptoKit for Rust - Simple Usage Examples
//!
//! This example demonstrates the basic usage of cryptographic functions
//! provided by the apple-cryptokit-rs library.

use apple_cryptokit::{
    Result,
    // HMAC Authentication
    authentication::hmac_sha256,
    // Hashing
    hashing::{HashFunction, SHA256, sha256_hash},
    // Key Derivation
    key_derivation::hkdf_sha256_derive,
    // Symmetric Encryption
    symmetric::aes::{aes_gcm_decrypt, aes_gcm_encrypt},
    symmetric::chacha::{chacha20poly1305_encrypt, chacha20poly1305_decrypt, ChaChaKey, ChaChaPolyNonce, ChaChaPoly},
    symmetric::AuthenticatedCipher,
};

fn main() -> Result<()> {
    println!("Apple CryptoKit for Rust - Simple Usage Examples");
    println!("====================================================\n");

    // 1. Hashing Examples
    hashing_examples()?;

    // 2. Message Authentication Examples
    authentication_examples()?;

    // 3. Symmetric Encryption Examples (AES-GCM)
    symmetric_encryption_examples()?;

    // 4. ChaCha20-Poly1305 Examples
    chacha20poly1305_examples()?;

    // 5. Key Derivation Examples
    key_derivation_examples()?;

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
    println!("Data: {}", String::from_utf8_lossy(data));
    println!("SHA256 hash (hex): {:02x?}", &hash[..8]); // Show first 8 bytes

    // Using trait interface
    let hash_trait = SHA256::hash(data);
    println!("SHA256 (trait): {:02x?}", &hash_trait[..8]);

    println!("Hash length: {} bytes\n", hash.len());

    Ok(())
}

/// Demonstrates HMAC message authentication
fn authentication_examples() -> Result<()> {
    println!("Message Authentication Examples");
    println!("----------------------------------");

    let key = b"my-secret-authentication-key";
    let message = b"Important message to authenticate";

    let mac = hmac_sha256(key, message)?;
    println!("Message: {}", String::from_utf8_lossy(message));
    println!("HMAC-SHA256: {:02x?}", &mac[..8]); // Show first 8 bytes

    // Verify HMAC by computing again
    let verify_mac = hmac_sha256(key, message)?;
    let is_valid = mac == verify_mac;
    println!(
        "HMAC verification: {}\n",
        if is_valid { "Valid" } else { "Invalid" }
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
    println!("Ciphertext: {:02x?}...", &ciphertext[..16]); // Show first 16 bytes

    // Decrypt
    let decrypted = aes_gcm_decrypt(key, nonce, &ciphertext)?;
    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));

    let success = plaintext == decrypted.as_slice();
    println!(
        "Encryption/Decryption: {}",
        if success { "Success" } else { "Failed" }
    );
    println!(
        "Ciphertext length: {} bytes (including authentication tag)\n",
        ciphertext.len()
    );

    Ok(())
}

/// Demonstrates ChaCha20-Poly1305 authenticated encryption
fn chacha20poly1305_examples() -> Result<()> {
    println!("ChaCha20-Poly1305 Examples");
    println!("-----------------------------");

    // Using convenience functions
    let key = b"0123456789abcdef0123456789abcdef"; // 32-byte key
    let nonce = b"unique12byte"; // 12-byte nonce
    let plaintext = b"Hello, ChaCha20-Poly1305!";

    let ciphertext = chacha20poly1305_encrypt(key, nonce, plaintext)?;
    println!("Plaintext: {}", String::from_utf8_lossy(plaintext));
    println!("Ciphertext: {:02x?}...", &ciphertext[..16]);

    let decrypted = chacha20poly1305_decrypt(key, nonce, &ciphertext)?;
    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));

    let success = plaintext == decrypted.as_slice();
    println!(
        "Encryption/Decryption: {}",
        if success { "Success" } else { "Failed" }
    );

    // Using typed structs with random key generation
    let random_key = ChaChaKey::generate()?;
    let random_nonce = ChaChaPolyNonce::generate()?;
    let message = b"Secure message with generated key";

    let sealed = ChaChaPoly::seal(&random_key, &random_nonce, message)?;
    let opened = ChaChaPoly::open(&random_key, &random_nonce, &sealed)?;

    println!("Random key generation: Success");
    println!(
        "Seal/Open with generated key: {}\n",
        if message == opened.as_slice() { "Success" } else { "Failed" }
    );

    Ok(())
}

/// Demonstrates key derivation using HKDF
fn key_derivation_examples() -> Result<()> {
    println!("Key Derivation Examples");
    println!("--------------------------");

    let input_key_material = b"shared-secret-from-key-exchange";
    let salt = b"random-salt-value";
    let info = b"application-specific-context";
    let output_length = 32; // 256 bits

    let derived_key = hkdf_sha256_derive(input_key_material, salt, info, output_length)?;
    println!(
        "Input key material: {}",
        String::from_utf8_lossy(input_key_material)
    );
    println!("Salt: {}", String::from_utf8_lossy(salt));
    println!("Info: {}", String::from_utf8_lossy(info));
    println!("Derived key (32 bytes): {:02x?}...", &derived_key[..8]); // Show first 8 bytes
    println!("Full derived key length: {} bytes\n", derived_key.len());

    Ok(())
}

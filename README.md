# Apple CryptoKit for Rust

A Rust wrapper around Apple's native CryptoKit framework, designed to provide cryptographic functionality while maintaining App Store compliance.

## Why This Library?

When submitting apps to the App Store, Apple requires specific handling of cryptographic functionality. Apps that use encryption must either:

1. Use only standard cryptographic algorithms provided by Apple's operating systems, or
2. Provide additional export compliance documentation

This library solves this problem by:
- **Wrapping Apple's native CryptoKit**: Uses only the cryptographic algorithms provided by Apple's operating system
- **Maintaining App Store compliance**: Qualifies for cryptographic export compliance exemptions
- **Providing Rust-safe interfaces**: Offers memory-safe, ergonomic Rust APIs over the Swift CryptoKit

By using this library, your Rust applications can leverage Apple's optimized cryptographic implementations while avoiding the need for additional export compliance paperwork.

## Features

### Traditional Cryptography
- **Symmetric Encryption**: AES-GCM, ChaCha20-Poly1305
- **Hashing**: SHA-256, SHA-384, SHA-512
- **Message Authentication**: HMAC-SHA256, HMAC-SHA384, HMAC-SHA512  
- **Key Derivation**: HKDF (HMAC-based Key Derivation Function)
- **Asymmetric Cryptography**: P-256, P-384, P-521, Curve25519

### Post-Quantum Cryptography
- **Key Encapsulation**: ML-KEM-768, X-Wing (ML-KEM-768 + X25519)
- **Digital Signatures**: ML-DSA-65

### Platform Support
- **macOS**: 10.15+ (macOS Catalina and later)
- **iOS**: 13.0+ (when building for iOS targets)
- **Additional Apple platforms**: As supported by CryptoKit

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
apple-cryptokit-rs = "0.1.0"
```

## Quick Start

### Hashing
```rust
use apple_cryptokit::hashing::{sha256_hash, SHA256, HashFunction};

fn main() -> apple_cryptokit::Result<()> {
    let data = b"Hello, World!";
    
    // Direct function call
    let hash1 = sha256_hash(data);
    
    // Using trait
    let hash2 = SHA256::hash(data);
    
    println!("SHA-256: {}", hex::encode(hash1));
    Ok(())
}
```

### Message Authentication (HMAC)
```rust
use apple_cryptokit::authentication::{hmac_sha256, HMACSHA256};

fn main() -> apple_cryptokit::Result<()> {
    let key = b"my-secret-key";
    let message = b"important message";
    
    let mac = hmac_sha256(key, message)?;
    println!("HMAC-SHA256: {}", hex::encode(mac));
    Ok(())
}
```

### Symmetric Encryption
```rust
use apple_cryptokit::symmetric::aes::{aes_gcm_encrypt, aes_gcm_decrypt};

fn main() -> apple_cryptokit::Result<()> {
    let key = b"0123456789abcdef0123456789abcdef"; // 32-byte key
    let nonce = b"cdef01234567"; // 12-byte nonce
    let plaintext = b"Secret message";
    
    // Encrypt
    let ciphertext = aes_gcm_encrypt(key, nonce, plaintext)?;
    
    // Decrypt
    let decrypted = aes_gcm_decrypt(key, nonce, &ciphertext)?;
    
    assert_eq!(plaintext, &decrypted[..]);
    Ok(())
}
```

### Asymmetric Cryptography (Elliptic Curves)
```rust
use apple_cryptokit::asymmetric::p256::{P256PrivateKey, P256PublicKey};

fn main() -> apple_cryptokit::Result<()> {
    // Generate key pair
    let private_key = P256PrivateKey::new()?;
    let public_key = private_key.public_key()?;
    
    // Create shared secret (ECDH)
    let other_private = P256PrivateKey::new()?;
    let other_public = other_private.public_key()?;
    
    let shared_secret = private_key.shared_secret_from_key_agreement(&other_public)?;
    
    println!("Shared secret established");
    Ok(())
}
```

### Post-Quantum Key Encapsulation
```rust
use apple_cryptokit::quantum::{MLKem768, KEMPrivateKey, KEMPublicKey};

fn main() -> apple_cryptokit::Result<()> {
    // Generate ML-KEM-768 key pair
    let private_key = MLKem768::generate_private_key()?;
    let public_key = private_key.public_key()?;
    
    // Encapsulation (sender side)
    let (ciphertext, shared_secret1) = public_key.encapsulate()?;
    
    // Decapsulation (receiver side)
    let shared_secret2 = private_key.decapsulate(&ciphertext)?;
    
    // Both parties now have the same shared secret
    assert_eq!(shared_secret1, shared_secret2);
    Ok(())
}
```

### Post-Quantum Digital Signatures
```rust
use apple_cryptokit::quantum::{MLDsa65, SignaturePrivateKey, SignaturePublicKey};

fn main() -> apple_cryptokit::Result<()> {
    // Generate ML-DSA-65 key pair
    let private_key = MLDsa65::generate_private_key()?;
    let public_key = private_key.public_key()?;
    
    let message = b"Document to sign";
    
    // Sign
    let signature = private_key.sign(message)?;
    
    // Verify
    let is_valid = public_key.verify(message, &signature)?;
    assert!(is_valid);
    
    println!("Signature verified!");
    Ok(())
}
```

## Architecture

This library consists of two main components:

1. **Swift CryptoKit Wrapper** (`swift/` directory): A Swift package that provides C-compatible interfaces to Apple's CryptoKit framework
2. **Rust Bindings** (`src/` directory): Safe Rust wrappers around the Swift interfaces

### Build Process
The build process uses a custom `build.rs` script that:
1. Compiles the Swift package into a static library
2. Generates appropriate linking flags for the Rust crate
3. Ensures proper integration between Swift CryptoKit and Rust code

## App Store Compliance

### Export Administration Regulations (EAR) Compliance

This library is designed to help maintain compliance with U.S. Export Administration Regulations when distributing apps through the App Store. By using only Apple's provided cryptographic implementations, apps using this library may qualify for certain exemptions.

**Important**: Always consult with legal counsel regarding export compliance requirements for your specific application and use case.

### Required Info.plist Configuration

When using this library in an iOS/macOS app, you may need to add the following to your app's `Info.plist`:

```xml
<key>ITSAppUsesNonExemptEncryption</key>
<false/>
```

Or if your app does use encryption but qualifies for exemptions:

```xml
<key>ITSAppUsesNonExemptEncryption</key>
<true/>
<key>ITSEncryptionExportComplianceCode</key>
<string>your-compliance-code-here</string>
```

## Supported Algorithms

### Hashing
- SHA-256, SHA-384, SHA-512, SHA-1

### Message Authentication Codes
- HMAC-SHA256, HMAC-SHA384, HMAC-SHA512, HMAC-SHA1

### Symmetric Encryption
- AES-GCM (128, 192, 256-bit keys)
- ChaCha20-Poly1305

### Asymmetric Cryptography
- P-256 (secp256r1)
- P-384 (secp384r1)  
- P-521 (secp521r1)
- Curve25519

### Key Derivation
- HKDF-SHA256, HKDF-SHA384, HKDF-SHA512

### Post-Quantum Cryptography
- **ML-KEM-768**: NIST standardized key encapsulation mechanism
- **X-Wing**: Hybrid ML-KEM-768 + X25519 for transition security
- **ML-DSA-65**: NIST standardized digital signature algorithm

## Requirements

- **macOS**: 10.15+ (Catalina) for development
- **Xcode**: 12.0+ with Swift 5.3+
- **Rust**: 1.75+ (2024 edition)

## Development

### Building
```bash
cargo build
```

### Testing
```bash
cargo test
```

### Running Examples
```bash
cargo run --example basic_usage
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Guidelines
- Follow Rust's standard coding conventions
- Ensure all tests pass
- Add tests for new functionality
- Update documentation as needed

## Acknowledgments

This project was inspired by [oml-cryptokit-rs](https://crates.io/crates/oml-cryptokit-rs), which pioneered the approach of wrapping Apple's CryptoKit to maintain App Store export compliance. We are grateful for their innovative solution and have built upon their work.

Special thanks to the oml-cryptokit-rs project for:
- Demonstrating how to bridge Apple's CryptoKit with Rust
- Providing the foundation for our `build.rs` implementation
- Showing the path to App Store compliance through native cryptographic APIs

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This library wraps Apple's CryptoKit framework and is intended to help with App Store compliance. However, export compliance requirements can be complex and may vary based on your specific use case, target markets, and implementation details.

**Always consult with qualified legal counsel regarding export compliance requirements for your specific application.**

## Related Projects

- [Apple CryptoKit Documentation](https://developer.apple.com/documentation/cryptokit)

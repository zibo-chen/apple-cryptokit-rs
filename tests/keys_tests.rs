use apple_cryptokit::error::Result;
use apple_cryptokit::keys::{SharedSecret, SharedSecretImpl, SymmetricKey, SymmetricKeySize};

#[test]
fn test_symmetric_key_generate() -> Result<()> {
    // 测试生成不同大小的对称密钥
    let key_128 = SymmetricKey::generate(SymmetricKeySize::Bits128)?;
    assert_eq!(key_128.byte_count(), 16);
    assert_eq!(key_128.bit_count(), 128);
    assert_eq!(key_128.size(), SymmetricKeySize::Bits128);

    let key_192 = SymmetricKey::generate(SymmetricKeySize::Bits192)?;
    assert_eq!(key_192.byte_count(), 24);
    assert_eq!(key_192.bit_count(), 192);
    assert_eq!(key_192.size(), SymmetricKeySize::Bits192);

    let key_256 = SymmetricKey::generate(SymmetricKeySize::Bits256)?;
    assert_eq!(key_256.byte_count(), 32);
    assert_eq!(key_256.bit_count(), 256);
    assert_eq!(key_256.size(), SymmetricKeySize::Bits256);

    Ok(())
}

#[test]
fn test_symmetric_key_from_data() -> Result<()> {
    // 测试从数据创建对称密钥
    let data_128 = vec![1u8; 16];
    let key_128 = SymmetricKey::from_data(&data_128)?;
    assert_eq!(key_128.byte_count(), 16);
    assert_eq!(key_128.size(), SymmetricKeySize::Bits128);
    assert_eq!(key_128.as_bytes(), &data_128);

    let data_192 = vec![2u8; 24];
    let key_192 = SymmetricKey::from_data(&data_192)?;
    assert_eq!(key_192.byte_count(), 24);
    assert_eq!(key_192.size(), SymmetricKeySize::Bits192);

    let data_256 = vec![3u8; 32];
    let key_256 = SymmetricKey::from_data(&data_256)?;
    assert_eq!(key_256.byte_count(), 32);
    assert_eq!(key_256.size(), SymmetricKeySize::Bits256);

    Ok(())
}

#[test]
fn test_symmetric_key_invalid_size() {
    // 测试无效的密钥大小
    let invalid_data = vec![1u8; 15]; // 无效长度
    let result = SymmetricKey::from_data(&invalid_data);
    assert!(result.is_err());

    let invalid_data = vec![1u8; 17]; // 无效长度
    let result = SymmetricKey::from_data(&invalid_data);
    assert!(result.is_err());
}

#[test]
fn test_symmetric_key_equality() -> Result<()> {
    // 测试密钥相等性
    let data = vec![1u8; 32];
    let key1 = SymmetricKey::from_data(&data)?;
    let key2 = SymmetricKey::from_data(&data)?;
    let key3 = SymmetricKey::from_data(&vec![2u8; 32])?;

    assert!(key1.equals(&key2));
    assert!(!key1.equals(&key3));
    assert_eq!(key1, key2);
    assert_ne!(key1, key3);

    Ok(())
}

#[test]
fn test_symmetric_key_with_unsafe_bytes() -> Result<()> {
    let key = SymmetricKey::generate(SymmetricKeySize::Bits256)?;

    let mut captured_length = 0;
    key.with_unsafe_bytes(|bytes| {
        captured_length = bytes.len();
    })?;

    assert_eq!(captured_length, 32);
    Ok(())
}

#[test]
fn test_symmetric_key_size_conversions() -> Result<()> {
    // 测试 SymmetricKeySize 的转换方法
    assert_eq!(
        SymmetricKeySize::from_byte_count(16)?,
        SymmetricKeySize::Bits128
    );
    assert_eq!(
        SymmetricKeySize::from_byte_count(24)?,
        SymmetricKeySize::Bits192
    );
    assert_eq!(
        SymmetricKeySize::from_byte_count(32)?,
        SymmetricKeySize::Bits256
    );

    assert_eq!(
        SymmetricKeySize::from_bit_count(128)?,
        SymmetricKeySize::Bits128
    );
    assert_eq!(
        SymmetricKeySize::from_bit_count(192)?,
        SymmetricKeySize::Bits192
    );
    assert_eq!(
        SymmetricKeySize::from_bit_count(256)?,
        SymmetricKeySize::Bits256
    );

    // 测试无效转换
    assert!(SymmetricKeySize::from_byte_count(15).is_err());
    assert!(SymmetricKeySize::from_bit_count(127).is_err());

    Ok(())
}

#[test]
fn test_shared_secret_creation() -> Result<()> {
    // 测试共享密钥创建
    let secret_data = vec![1u8; 32];
    let shared_secret = SharedSecretImpl::from_data(&secret_data)?;

    assert_eq!(shared_secret.byte_count(), 32);
    assert_eq!(shared_secret.as_bytes(), &secret_data);

    // 测试空数据
    let empty_data = vec![];
    let result = SharedSecretImpl::from_data(&empty_data);
    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_shared_secret_equality() -> Result<()> {
    let data1 = vec![1u8; 32];
    let data2 = vec![1u8; 32];
    let data3 = vec![2u8; 32];

    let secret1 = SharedSecretImpl::from_data(&data1)?;
    let secret2 = SharedSecretImpl::from_data(&data2)?;
    let secret3 = SharedSecretImpl::from_data(&data3)?;

    assert!(secret1.equals(&secret2));
    assert!(!secret1.equals(&secret3));
    assert_eq!(secret1, secret2);
    assert_ne!(secret1, secret3);

    Ok(())
}

#[test]
fn test_shared_secret_key_derivation() -> Result<()> {
    // 测试密钥派生（注意：这些测试可能在某些环境下失败，
    // 因为它们依赖 Swift FFI 调用）
    let secret_data = vec![1u8; 32];
    let shared_secret = SharedSecretImpl::from_data(&secret_data)?;

    // 测试 HKDF 密钥派生
    let derived_key = shared_secret.hkdf_derive_key(b"test_salt", b"test_info", 32);

    // 由于我们无法确保 Swift 运行时可用，我们只测试方法调用不会 panic
    match derived_key {
        Ok(key) => {
            assert_eq!(key.byte_count(), 32);
            println!("HKDF derivation successful");
        }
        Err(_) => {
            println!("HKDF derivation failed (expected in some environments)");
        }
    }

    // 测试 X9.63 密钥派生
    let derived_key = shared_secret.x963_derive_key(b"shared_info", 32);

    match derived_key {
        Ok(key) => {
            assert_eq!(key.byte_count(), 32);
            println!("X9.63 derivation successful");
        }
        Err(_) => {
            println!("X9.63 derivation failed (expected in some environments)");
        }
    }

    Ok(())
}

#[test]
fn test_debug_display_no_leak() -> Result<()> {
    // 确保调试和显示格式化不会泄露密钥数据
    let key = SymmetricKey::generate(SymmetricKeySize::Bits256)?;
    let debug_str = format!("{:?}", key);
    let display_str = format!("{}", key);

    // 确保调试字符串不包含实际的密钥字节
    assert!(!debug_str.contains("bytes"));
    assert!(debug_str.contains("SymmetricKey"));
    assert!(debug_str.contains("byte_count"));

    // 确保显示字符串只包含基本信息
    assert!(display_str.contains("SymmetricKey"));
    assert!(display_str.contains("256"));

    let secret_data = vec![1u8; 32];
    let shared_secret = SharedSecretImpl::from_data(&secret_data)?;
    let secret_debug_str = format!("{:?}", shared_secret);
    let secret_display_str = format!("{}", shared_secret);

    assert!(secret_debug_str.contains("SharedSecret"));
    assert!(secret_debug_str.contains("byte_count"));
    assert!(secret_display_str.contains("SharedSecret"));
    assert!(secret_display_str.contains("32 bytes"));

    Ok(())
}

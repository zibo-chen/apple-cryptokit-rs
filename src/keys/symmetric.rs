use crate::error::{CryptoKitError, Result};

// 对称密钥管理 Swift FFI 声明
extern "C" {
    #[link_name = "symmetric_key_generate"]
    fn swift_symmetric_key_generate(size: i32, output: *mut u8) -> i32;

    #[link_name = "symmetric_key_from_data"]
    fn swift_symmetric_key_from_data(data: *const u8, len: i32, output: *mut u8) -> i32;
}

/// 对称密钥大小枚举
///
/// 支持常用的对称密钥长度，与 Apple CryptoKit 的 SymmetricKeySize 对应
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymmetricKeySize {
    /// 128位 (16字节) - 适用于 AES-128
    Bits128,
    /// 192位 (24字节) - 适用于 AES-192  
    Bits192,
    /// 256位 (32字节) - 适用于 AES-256, ChaCha20
    Bits256,
}

impl SymmetricKeySize {
    /// 获取密钥长度（字节）
    pub fn byte_count(&self) -> usize {
        match self {
            SymmetricKeySize::Bits128 => 16,
            SymmetricKeySize::Bits192 => 24,
            SymmetricKeySize::Bits256 => 32,
        }
    }

    /// 获取密钥长度（位）
    pub fn bit_count(&self) -> usize {
        self.byte_count() * 8
    }

    /// 从字节长度创建 SymmetricKeySize
    pub fn from_byte_count(bytes: usize) -> Result<Self> {
        match bytes {
            16 => Ok(SymmetricKeySize::Bits128),
            24 => Ok(SymmetricKeySize::Bits192),
            32 => Ok(SymmetricKeySize::Bits256),
            _ => Err(CryptoKitError::InvalidLength),
        }
    }

    /// 从位长度创建 SymmetricKeySize
    pub fn from_bit_count(bits: usize) -> Result<Self> {
        match bits {
            128 => Ok(SymmetricKeySize::Bits128),
            192 => Ok(SymmetricKeySize::Bits192),
            256 => Ok(SymmetricKeySize::Bits256),
            _ => Err(CryptoKitError::InvalidLength),
        }
    }
}

/// 对称密钥包装器
///
/// 提供安全的对称密钥管理，与 Apple CryptoKit 的 SymmetricKey 对应
#[derive(Clone)]
pub struct SymmetricKey {
    bytes: Vec<u8>,
    size: SymmetricKeySize,
}

impl SymmetricKey {
    /// 生成指定大小的随机对称密钥
    ///
    /// # Arguments
    /// * `size` - 密钥大小
    ///
    /// # Returns
    /// 新的随机对称密钥
    pub fn generate(size: SymmetricKeySize) -> Result<Self> {
        let byte_count = size.byte_count();

        unsafe {
            let mut output = vec![0u8; byte_count];
            let result = swift_symmetric_key_generate(byte_count as i32, output.as_mut_ptr());

            if result == 0 {
                Ok(Self {
                    bytes: output,
                    size,
                })
            } else {
                Err(CryptoKitError::KeyGenerationFailed)
            }
        }
    }

    /// 从字节数据创建对称密钥
    ///
    /// # Arguments
    /// * `data` - 密钥数据字节
    ///
    /// # Returns
    /// 新的对称密钥
    pub fn from_data(data: &[u8]) -> Result<Self> {
        let size = SymmetricKeySize::from_byte_count(data.len())?;

        unsafe {
            let mut output = vec![0u8; data.len()];
            let result = swift_symmetric_key_from_data(
                data.as_ptr(),
                data.len() as i32,
                output.as_mut_ptr(),
            );

            if result == 0 {
                Ok(Self {
                    bytes: output,
                    size,
                })
            } else {
                Err(CryptoKitError::InvalidKey)
            }
        }
    }

    /// 获取密钥字节数据的引用
    ///
    /// 注意：此方法返回密钥的原始字节，使用时需要格外小心避免泄露
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// 获取密钥大小枚举值
    pub fn size(&self) -> SymmetricKeySize {
        self.size
    }

    /// 获取密钥长度（字节）
    pub fn byte_count(&self) -> usize {
        self.bytes.len()
    }

    /// 获取密钥长度（位）
    pub fn bit_count(&self) -> usize {
        self.bytes.len() * 8
    }

    /// 安全地访问密钥字节数据
    ///
    /// 提供一个回调函数来访问密钥字节，类似于 Apple CryptoKit 的 withUnsafeBytes
    ///
    /// # Arguments
    /// * `callback` - 处理密钥字节的回调函数
    pub fn with_unsafe_bytes<F, R>(&self, callback: F) -> Result<R>
    where
        F: FnOnce(&[u8]) -> R,
    {
        // 直接调用回调函数，因为我们已经有了字节数据
        Ok(callback(&self.bytes))
    }

    /// 比较两个密钥是否相等
    ///
    /// 使用常数时间比较避免时序攻击
    pub fn equals(&self, other: &Self) -> bool {
        if self.bytes.len() != other.bytes.len() {
            return false;
        }

        // 常数时间比较
        let mut result = 0u8;
        for (a, b) in self.bytes.iter().zip(other.bytes.iter()) {
            result |= a ^ b;
        }
        result == 0
    }
}

impl PartialEq for SymmetricKey {
    fn eq(&self, other: &Self) -> bool {
        self.equals(other)
    }
}

impl Eq for SymmetricKey {}

impl std::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SymmetricKey")
            .field("size", &self.size)
            .field("byte_count", &self.byte_count())
            .finish_non_exhaustive() // 不显示实际密钥数据，防止意外泄露
    }
}

// 防止密钥数据意外泄露
impl Drop for SymmetricKey {
    fn drop(&mut self) {
        // 清零密钥数据
        for byte in &mut self.bytes {
            *byte = 0;
        }
    }
}

// 确保密钥不能被意外显示
impl std::fmt::Display for SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SymmetricKey({})", self.size.bit_count())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symmetric_key_size() {
        assert_eq!(SymmetricKeySize::Bits128.byte_count(), 16);
        assert_eq!(SymmetricKeySize::Bits192.byte_count(), 24);
        assert_eq!(SymmetricKeySize::Bits256.byte_count(), 32);

        assert_eq!(SymmetricKeySize::Bits128.bit_count(), 128);
        assert_eq!(SymmetricKeySize::Bits192.bit_count(), 192);
        assert_eq!(SymmetricKeySize::Bits256.bit_count(), 256);
    }

    #[test]
    fn test_symmetric_key_size_from_bytes() {
        assert_eq!(
            SymmetricKeySize::from_byte_count(16).unwrap(),
            SymmetricKeySize::Bits128
        );
        assert_eq!(
            SymmetricKeySize::from_byte_count(24).unwrap(),
            SymmetricKeySize::Bits192
        );
        assert_eq!(
            SymmetricKeySize::from_byte_count(32).unwrap(),
            SymmetricKeySize::Bits256
        );

        assert!(SymmetricKeySize::from_byte_count(15).is_err());
        assert!(SymmetricKeySize::from_byte_count(17).is_err());
    }

    #[test]
    fn test_symmetric_key_size_from_bits() {
        assert_eq!(
            SymmetricKeySize::from_bit_count(128).unwrap(),
            SymmetricKeySize::Bits128
        );
        assert_eq!(
            SymmetricKeySize::from_bit_count(192).unwrap(),
            SymmetricKeySize::Bits192
        );
        assert_eq!(
            SymmetricKeySize::from_bit_count(256).unwrap(),
            SymmetricKeySize::Bits256
        );

        assert!(SymmetricKeySize::from_bit_count(127).is_err());
        assert!(SymmetricKeySize::from_bit_count(129).is_err());
    }
}

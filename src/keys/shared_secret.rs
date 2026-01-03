use crate::error::{CryptoKitError, Result};
use crate::keys::symmetric::{SymmetricKey, SymmetricKeySize};

// 共享密钥 Swift FFI 声明
extern "C" {
    #[link_name = "shared_secret_hkdf_derive_key"]
    fn swift_shared_secret_hkdf_derive_key(
        secret: *const u8,
        secret_len: i32,
        salt: *const u8,
        salt_len: i32,
        info: *const u8,
        info_len: i32,
        output_len: i32,
        output: *mut u8,
    ) -> i32;

    #[link_name = "shared_secret_x963_derive_key"]
    fn swift_shared_secret_x963_derive_key(
        secret: *const u8,
        secret_len: i32,
        shared_info: *const u8,
        shared_info_len: i32,
        output_len: i32,
        output: *mut u8,
    ) -> i32;
}

/// 共享密钥特性定义
///
/// 定义共享密钥应该具备的基本功能
pub trait SharedSecret {
    /// 使用 HKDF-SHA256 从共享密钥派生对称密钥
    fn hkdf_derive_key(
        &self,
        salt: &[u8],
        info: &[u8],
        output_byte_count: usize,
    ) -> Result<SymmetricKey>;

    /// 使用 X9.63 KDF 从共享密钥派生对称密钥
    fn x963_derive_key(&self, shared_info: &[u8], output_byte_count: usize)
    -> Result<SymmetricKey>;

    /// 获取共享密钥的字节表示
    fn as_bytes(&self) -> &[u8];
}

/// 共享密钥的具体实现
///
/// 与 Apple CryptoKit 的 SharedSecret 对应，通常从密钥交换算法获得
#[derive(Clone)]
pub struct SharedSecretImpl {
    bytes: Vec<u8>,
}

impl SharedSecretImpl {
    /// 从字节数据创建共享密钥
    ///
    /// # Arguments
    /// * `data` - 共享密钥的字节数据
    ///
    /// # Returns
    /// 新的共享密钥实例
    pub fn from_data(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(CryptoKitError::InvalidInput(
                "Shared secret data cannot be empty".to_string(),
            ));
        }

        Ok(Self {
            bytes: data.to_vec(),
        })
    }

    /// 获取共享密钥的字节长度
    pub fn byte_count(&self) -> usize {
        self.bytes.len()
    }

    /// 比较两个共享密钥是否相等
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

impl SharedSecret for SharedSecretImpl {
    /// 使用 HKDF-SHA256 从共享密钥派生对称密钥
    ///
    /// # Arguments
    /// * `salt` - 盐值（可以为空）
    /// * `info` - 上下文信息（可以为空）
    /// * `output_byte_count` - 输出密钥的字节长度
    ///
    /// # Returns
    /// 派生得到的对称密钥
    fn hkdf_derive_key(
        &self,
        salt: &[u8],
        info: &[u8],
        output_byte_count: usize,
    ) -> Result<SymmetricKey> {
        // 验证输出长度
        let _size = SymmetricKeySize::from_byte_count(output_byte_count)?;

        unsafe {
            let mut output = vec![0u8; output_byte_count];

            let result = swift_shared_secret_hkdf_derive_key(
                self.bytes.as_ptr(),
                self.bytes.len() as i32,
                salt.as_ptr(),
                salt.len() as i32,
                info.as_ptr(),
                info.len() as i32,
                output_byte_count as i32,
                output.as_mut_ptr(),
            );

            if result == 0 {
                SymmetricKey::from_data(&output)
            } else {
                Err(CryptoKitError::DerivationFailed)
            }
        }
    }

    /// 使用 X9.63 KDF 从共享密钥派生对称密钥
    ///
    /// # Arguments
    /// * `shared_info` - 共享信息（可以为空）
    /// * `output_byte_count` - 输出密钥的字节长度
    ///
    /// # Returns
    /// 派生得到的对称密钥
    fn x963_derive_key(
        &self,
        shared_info: &[u8],
        output_byte_count: usize,
    ) -> Result<SymmetricKey> {
        // 验证输出长度
        let _size = SymmetricKeySize::from_byte_count(output_byte_count)?;

        unsafe {
            let mut output = vec![0u8; output_byte_count];

            let result = swift_shared_secret_x963_derive_key(
                self.bytes.as_ptr(),
                self.bytes.len() as i32,
                shared_info.as_ptr(),
                shared_info.len() as i32,
                output_byte_count as i32,
                output.as_mut_ptr(),
            );

            if result == 0 {
                SymmetricKey::from_data(&output)
            } else {
                Err(CryptoKitError::DerivationFailed)
            }
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl PartialEq for SharedSecretImpl {
    fn eq(&self, other: &Self) -> bool {
        self.equals(other)
    }
}

impl Eq for SharedSecretImpl {}

impl std::fmt::Debug for SharedSecretImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedSecret")
            .field("byte_count", &self.byte_count())
            .finish_non_exhaustive() // 不显示实际密钥数据，防止意外泄露
    }
}

// 防止密钥数据意外泄露
impl Drop for SharedSecretImpl {
    fn drop(&mut self) {
        // 清零密钥数据
        for byte in &mut self.bytes {
            *byte = 0;
        }
    }
}

// 确保共享密钥不能被意外显示
impl std::fmt::Display for SharedSecretImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SharedSecret({} bytes)", self.byte_count())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shared_secret_creation() {
        let data = vec![1u8; 32];
        let secret = SharedSecretImpl::from_data(&data).unwrap();
        assert_eq!(secret.byte_count(), 32);
        assert_eq!(secret.as_bytes(), &data);
    }

    #[test]
    fn test_shared_secret_empty_data() {
        let empty_data = vec![];
        let result = SharedSecretImpl::from_data(&empty_data);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            CryptoKitError::InvalidInput("Shared secret data cannot be empty".to_string())
        );
    }

    #[test]
    fn test_shared_secret_equality() {
        let data1 = vec![1u8; 32];
        let data2 = vec![1u8; 32];
        let data3 = vec![2u8; 32];

        let secret1 = SharedSecretImpl::from_data(&data1).unwrap();
        let secret2 = SharedSecretImpl::from_data(&data2).unwrap();
        let secret3 = SharedSecretImpl::from_data(&data3).unwrap();

        assert!(secret1.equals(&secret2));
        assert!(!secret1.equals(&secret3));
        assert_eq!(secret1, secret2);
        assert_ne!(secret1, secret3);
    }
}

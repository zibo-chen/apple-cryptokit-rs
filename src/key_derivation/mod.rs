use crate::error::{CryptoKitError, Result};

pub mod hkdf_sha256;
pub mod hkdf_sha384;
pub mod hkdf_sha512;

/// 哈希算法枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA256 哈希算法
    SHA256,
    /// SHA384 哈希算法
    SHA384,
    /// SHA512 哈希算法
    SHA512,
}

impl HashAlgorithm {
    /// 获取哈希算法的输出长度（字节）
    pub fn output_length(&self) -> usize {
        match self {
            HashAlgorithm::SHA256 => 32,
            HashAlgorithm::SHA384 => 48,
            HashAlgorithm::SHA512 => 64,
        }
    }

    /// 获取HKDF的最大输出长度（255 * hash_length）
    pub fn max_hkdf_output_length(&self) -> usize {
        255 * self.output_length()
    }
}

/// 密钥派生算法的通用trait
pub trait KeyDerivationFunction {
    /// 从输入密钥材料派生密钥
    fn derive(
        input_key_material: &[u8],
        salt: &[u8],
        info: &[u8],
        output_length: usize,
    ) -> Result<Vec<u8>>;
}

/// 通用HKDF实现
pub struct HKDF;

impl HKDF {
    /// 使用指定的哈希算法进行HKDF密钥派生
    ///
    /// # 参数
    /// * `algorithm` - 使用的哈希算法
    /// * `input_key_material` - 输入密钥材料（IKM）
    /// * `salt` - 可选的盐值，建议使用随机值
    /// * `info` - 可选的上下文和应用特定信息
    /// * `output_length` - 期望的输出密钥长度
    ///
    /// # 返回
    /// 派生的密钥数据
    ///
    /// # 错误
    /// * `CryptoKitError::InvalidInput` - 如果输入密钥材料为空
    /// * `CryptoKitError::InvalidLength` - 如果输出长度无效
    /// * `CryptoKitError::DerivationFailed` - 如果密钥派生失败
    ///
    /// # 示例
    /// ```rust,no_run
    /// use apple_cryptokit::key_derivation::{HKDF, HashAlgorithm};
    ///
    /// let ikm = b"input key material";
    /// let salt = b"optional salt";
    /// let info = b"application context";
    ///
    /// let derived_key = HKDF::derive_key(
    ///     HashAlgorithm::SHA256,
    ///     ikm,
    ///     salt,
    ///     info,
    ///     32
    /// ).unwrap();
    /// ```
    pub fn derive_key(
        algorithm: HashAlgorithm,
        input_key_material: &[u8],
        salt: &[u8],
        info: &[u8],
        output_length: usize,
    ) -> Result<Vec<u8>> {
        // 验证输入参数
        if input_key_material.is_empty() {
            return Err(CryptoKitError::InvalidInput(
                "Input key material cannot be empty".to_string(),
            ));
        }

        if output_length == 0 || output_length > algorithm.max_hkdf_output_length() {
            return Err(CryptoKitError::InvalidLength);
        }

        match algorithm {
            HashAlgorithm::SHA256 => {
                hkdf_sha256::HKDF_SHA256::derive(input_key_material, salt, info, output_length)
            }
            HashAlgorithm::SHA384 => {
                hkdf_sha384::HKDF_SHA384::derive(input_key_material, salt, info, output_length)
            }
            HashAlgorithm::SHA512 => {
                hkdf_sha512::HKDF_SHA512::derive(input_key_material, salt, info, output_length)
            }
        }
    }

    /// 便利方法：使用SHA256进行HKDF密钥派生
    pub fn derive_key_sha256(
        input_key_material: &[u8],
        salt: &[u8],
        info: &[u8],
        output_length: usize,
    ) -> Result<Vec<u8>> {
        Self::derive_key(
            HashAlgorithm::SHA256,
            input_key_material,
            salt,
            info,
            output_length,
        )
    }

    /// 便利方法：使用SHA384进行HKDF密钥派生
    pub fn derive_key_sha384(
        input_key_material: &[u8],
        salt: &[u8],
        info: &[u8],
        output_length: usize,
    ) -> Result<Vec<u8>> {
        Self::derive_key(
            HashAlgorithm::SHA384,
            input_key_material,
            salt,
            info,
            output_length,
        )
    }

    /// 便利方法：使用SHA512进行HKDF密钥派生
    pub fn derive_key_sha512(
        input_key_material: &[u8],
        salt: &[u8],
        info: &[u8],
        output_length: usize,
    ) -> Result<Vec<u8>> {
        Self::derive_key(
            HashAlgorithm::SHA512,
            input_key_material,
            salt,
            info,
            output_length,
        )
    }

    /// 从共享密钥派生对称密钥
    ///
    /// 这是一个便利方法，用于从椭圆曲线密钥协商等操作得到的共享密钥派生对称加密密钥
    ///
    /// # 参数
    /// * `shared_secret` - 共享密钥数据
    /// * `algorithm` - 哈希算法
    /// * `salt` - 可选盐值
    /// * `info` - 应用上下文信息
    /// * `output_length` - 输出密钥长度
    pub fn derive_symmetric_key(
        shared_secret: &[u8],
        algorithm: HashAlgorithm,
        salt: Option<&[u8]>,
        info: &[u8],
        output_length: usize,
    ) -> Result<Vec<u8>> {
        let salt = salt.unwrap_or(&[]);
        Self::derive_key(algorithm, shared_secret, salt, info, output_length)
    }
}

/// HKDF-SHA256 密钥派生实现（重新导出）
pub use hkdf_sha256::HKDF_SHA256;

/// HKDF-SHA384 密钥派生实现（重新导出）
pub use hkdf_sha384::HKDF_SHA384;

/// HKDF-SHA512 密钥派生实现（重新导出）
pub use hkdf_sha512::HKDF_SHA512;

// ============================================================================
// 便利函数
// ============================================================================

/// 便利函数：HKDF-SHA256 密钥派生
///
/// # 参数
/// * `input_key_material` - 输入密钥材料
/// * `salt` - 盐值（可选，建议使用）
/// * `info` - 应用特定信息（可选）
/// * `output_length` - 输出密钥长度
///
/// # 示例
/// ```rust,no_run
/// use apple_cryptokit::key_derivation::hkdf_sha256_derive;
///
/// let ikm = b"input key material";
/// let salt = b"optional salt";
/// let info = b"application context";
///
/// let derived_key = hkdf_sha256_derive(ikm, salt, info, 32).unwrap();
/// ```
pub fn hkdf_sha256_derive(
    input_key_material: &[u8],
    salt: &[u8],
    info: &[u8],
    output_length: usize,
) -> Result<Vec<u8>> {
    hkdf_sha256::hkdf_sha256_derive(input_key_material, salt, info, output_length)
}

/// 便利函数：HKDF-SHA384 密钥派生
///
/// # 参数
/// * `input_key_material` - 输入密钥材料
/// * `salt` - 盐值（可选，建议使用）
/// * `info` - 应用特定信息（可选）
/// * `output_length` - 输出密钥长度
pub fn hkdf_sha384_derive(
    input_key_material: &[u8],
    salt: &[u8],
    info: &[u8],
    output_length: usize,
) -> Result<Vec<u8>> {
    hkdf_sha384::hkdf_sha384_derive(input_key_material, salt, info, output_length)
}

/// 便利函数：HKDF-SHA512 密钥派生
///
/// # 参数
/// * `input_key_material` - 输入密钥材料
/// * `salt` - 盐值（可选，建议使用）
/// * `info` - 应用特定信息（可选）
/// * `output_length` - 输出密钥长度
pub fn hkdf_sha512_derive(
    input_key_material: &[u8],
    salt: &[u8],
    info: &[u8],
    output_length: usize,
) -> Result<Vec<u8>> {
    hkdf_sha512::hkdf_sha512_derive(input_key_material, salt, info, output_length)
}

// ============================================================================
// 预定义的常用密钥长度
// ============================================================================

/// 常用的对称密钥长度定义
pub mod key_sizes {
    /// AES-128 密钥长度（16字节）
    pub const AES_128: usize = 16;
    /// AES-192 密钥长度（24字节）
    pub const AES_192: usize = 24;
    /// AES-256 密钥长度（32字节）
    pub const AES_256: usize = 32;
    /// ChaCha20 密钥长度（32字节）
    pub const CHACHA20: usize = 32;
    /// HMAC-SHA256 推荐密钥长度（32字节）
    pub const HMAC_SHA256: usize = 32;
    /// HMAC-SHA384 推荐密钥长度（48字节）
    pub const HMAC_SHA384: usize = 48;
    /// HMAC-SHA512 推荐密钥长度（64字节）
    pub const HMAC_SHA512: usize = 64;
}

// ============================================================================
// 测试模块
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_algorithm_properties() {
        assert_eq!(HashAlgorithm::SHA256.output_length(), 32);
        assert_eq!(HashAlgorithm::SHA384.output_length(), 48);
        assert_eq!(HashAlgorithm::SHA512.output_length(), 64);

        assert_eq!(HashAlgorithm::SHA256.max_hkdf_output_length(), 255 * 32);
        assert_eq!(HashAlgorithm::SHA384.max_hkdf_output_length(), 255 * 48);
        assert_eq!(HashAlgorithm::SHA512.max_hkdf_output_length(), 255 * 64);
    }

    #[test]
    fn test_invalid_input_validation() {
        // 测试空输入密钥材料
        let result = HKDF::derive_key(HashAlgorithm::SHA256, &[], b"salt", b"info", 32);
        assert!(matches!(result, Err(CryptoKitError::InvalidInput(_))));

        // 测试零输出长度
        let result = HKDF::derive_key(HashAlgorithm::SHA256, b"ikm", b"salt", b"info", 0);
        assert!(matches!(result, Err(CryptoKitError::InvalidLength)));

        // 测试过大的输出长度
        let result = HKDF::derive_key(
            HashAlgorithm::SHA256,
            b"ikm",
            b"salt",
            b"info",
            255 * 32 + 1,
        );
        assert!(matches!(result, Err(CryptoKitError::InvalidLength)));
    }
}

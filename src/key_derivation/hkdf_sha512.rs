use super::KeyDerivationFunction;
use crate::error::{CryptoKitError, Result};

// HKDF-SHA512 Swift FFI 声明
extern "C" {
    #[link_name = "hkdf_sha512_derive"]
    fn swift_hkdf_sha512_derive(
        input_key: *const u8,
        input_key_len: i32,
        salt: *const u8,
        salt_len: i32,
        info: *const u8,
        info_len: i32,
        output_length: i32,
        output: *mut u8,
    ) -> i32;
}

/// HKDF-SHA512 密钥派生实现
#[allow(non_camel_case_types)]
pub struct HKDF_SHA512;

impl HKDF_SHA512 {
    /// 从输入密钥材料派生密钥，使用SHA512哈希算法
    ///
    /// # 参数
    /// * `input_key_material` - 输入密钥材料
    /// * `salt` - 盐值（可选，建议使用）
    /// * `info` - 应用特定信息（可选）
    /// * `output_length` - 输出密钥长度
    ///
    /// # 返回
    /// 派生的密钥数据
    ///
    /// # 错误
    /// 如果密钥派生失败，返回 `CryptoKitError::DerivationFailed`
    ///
    /// # 示例
    /// ```rust,no_run
    /// use apple_cryptokit::key_derivation::hkdf_sha512::HKDF_SHA512;
    /// use apple_cryptokit::key_derivation::KeyDerivationFunction;
    ///
    /// let ikm = b"input key material";
    /// let salt = b"optional salt";
    /// let info = b"application context";
    ///
    /// let derived_key = HKDF_SHA512::derive(ikm, salt, info, 64).unwrap();
    /// ```
    pub fn derive_key(
        input_key_material: &[u8],
        salt: &[u8],
        info: &[u8],
        output_length: usize,
    ) -> Result<Vec<u8>> {
        Self::derive(input_key_material, salt, info, output_length)
    }
}

impl KeyDerivationFunction for HKDF_SHA512 {
    fn derive(
        input_key_material: &[u8],
        salt: &[u8],
        info: &[u8],
        output_length: usize,
    ) -> Result<Vec<u8>> {
        if input_key_material.is_empty() {
            return Err(CryptoKitError::InvalidInput(
                "Input key material cannot be empty".to_string(),
            ));
        }

        if output_length == 0 || output_length > 255 * 64 {
            // SHA512输出64字节，最大255个输出块
            return Err(CryptoKitError::InvalidLength);
        }

        unsafe {
            let mut output = vec![0u8; output_length];

            let result = swift_hkdf_sha512_derive(
                input_key_material.as_ptr(),
                input_key_material.len() as i32,
                salt.as_ptr(),
                salt.len() as i32,
                info.as_ptr(),
                info.len() as i32,
                output_length as i32,
                output.as_mut_ptr(),
            );

            if result == 0 {
                Ok(output)
            } else {
                Err(CryptoKitError::DerivationFailed)
            }
        }
    }
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
    HKDF_SHA512::derive(input_key_material, salt, info, output_length)
}

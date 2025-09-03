use crate::error::{CryptoKitError, Result};

/// HMAC 算法trait，为不同HMAC算法提供统一接口
pub trait HMAC {
    type Output;

    /// 计算HMAC
    fn authenticate(key: &[u8], data: &[u8]) -> Result<Self::Output>;

    /// 获取输出大小
    fn output_size() -> usize;
}

/// 消息认证码验证
pub fn verify_hmac<T: AsRef<[u8]>>(expected: T, computed: T) -> bool {
    let expected_bytes = expected.as_ref();
    let computed_bytes = computed.as_ref();

    if expected_bytes.len() != computed_bytes.len() {
        return false;
    }

    // 使用常量时间比较防止时序攻击
    constant_time_eq(expected_bytes, computed_bytes)
}

/// 常量时间字节比较
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// HMAC 算法枚举
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HmacAlgorithm {
    /// SHA-1 (不安全，仅用于兼容性)
    Sha1,
    /// SHA-256
    Sha256,
    /// SHA-384
    Sha384,
    /// SHA-512
    Sha512,
}

impl HmacAlgorithm {
    /// 获取输出长度
    pub fn output_size(&self) -> usize {
        match self {
            HmacAlgorithm::Sha1 => 20,
            HmacAlgorithm::Sha256 => 32,
            HmacAlgorithm::Sha384 => 48,
            HmacAlgorithm::Sha512 => 64,
        }
    }

    /// 计算HMAC
    pub fn compute(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        match self {
            HmacAlgorithm::Sha1 => {
                use crate::authentication::sha1::hmac_sha1;
                Ok(hmac_sha1(key, data)?.to_vec())
            }
            HmacAlgorithm::Sha256 => {
                use crate::authentication::sha256::hmac_sha256;
                Ok(hmac_sha256(key, data)?.to_vec())
            }
            HmacAlgorithm::Sha384 => {
                use crate::authentication::sha384::hmac_sha384;
                Ok(hmac_sha384(key, data)?.to_vec())
            }
            HmacAlgorithm::Sha512 => {
                use crate::authentication::sha512::hmac_sha512;
                Ok(hmac_sha512(key, data)?.to_vec())
            }
        }
    }

    /// 验证HMAC
    pub fn verify(&self, key: &[u8], data: &[u8], expected_hmac: &[u8]) -> Result<bool> {
        let computed = self.compute(key, data)?;
        Ok(constant_time_eq(&computed, expected_hmac))
    }
}

/// HMAC 构建器
pub struct HmacBuilder {
    algorithm: HmacAlgorithm,
    key: Vec<u8>,
}

impl HmacBuilder {
    /// 创建新的HMAC构建器
    pub fn new(algorithm: HmacAlgorithm) -> Self {
        Self {
            algorithm,
            key: Vec::new(),
        }
    }

    /// 设置密钥
    pub fn key(mut self, key: &[u8]) -> Self {
        self.key = key.to_vec();
        self
    }

    /// 计算HMAC
    pub fn compute(&self, data: &[u8]) -> Result<Vec<u8>> {
        if self.key.is_empty() {
            return Err(CryptoKitError::InvalidKey);
        }
        self.algorithm.compute(&self.key, data)
    }

    /// 验证HMAC
    pub fn verify(&self, data: &[u8], expected_hmac: &[u8]) -> Result<bool> {
        let computed = self.compute(data)?;
        Ok(constant_time_eq(&computed, expected_hmac))
    }
}

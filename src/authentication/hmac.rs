use crate::error::{CryptoKitError, Result};

/// HMAC 算法trait，为不同HMAC算法提供统一接口
pub trait HMAC {
    /// HMAC 输出大小（字节）
    const OUTPUT_SIZE: usize;

    /// 计算HMAC
    fn authenticate(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let mut output = vec![0u8; Self::OUTPUT_SIZE];
        Self::authenticate_to(key, data, &mut output)?;
        Ok(output)
    }

    /// 计算HMAC到提供的缓冲区（零分配）
    ///
    /// # 参数
    /// - `output`: 必须至少有 `OUTPUT_SIZE` 字节
    ///
    /// # 返回
    /// - `Ok(())`: 成功
    /// - `Err`: 认证失败
    fn authenticate_to(key: &[u8], data: &[u8], output: &mut [u8]) -> Result<()>;

    /// 获取输出大小（弃用，使用 OUTPUT_SIZE 常量）
    fn output_size() -> usize {
        Self::OUTPUT_SIZE
    }
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
        let mut output = vec![0u8; self.output_size()];
        self.compute_to(key, data, &mut output)?;
        Ok(output)
    }

    /// 计算HMAC到提供的缓冲区（零分配）
    ///
    /// # 参数
    /// - `output`: 必须至少有 `output_size()` 字节
    pub fn compute_to(&self, key: &[u8], data: &[u8], output: &mut [u8]) -> Result<()> {
        assert!(
            output.len() >= self.output_size(),
            "Output buffer too small: {} < {}",
            output.len(),
            self.output_size()
        );
        match self {
            HmacAlgorithm::Sha1 => {
                use crate::authentication::sha1::hmac_sha1_to;
                hmac_sha1_to(key, data, output)
            }
            HmacAlgorithm::Sha256 => {
                use crate::authentication::sha256::hmac_sha256_to;
                hmac_sha256_to(key, data, output)
            }
            HmacAlgorithm::Sha384 => {
                use crate::authentication::sha384::hmac_sha384_to;
                hmac_sha384_to(key, data, output)
            }
            HmacAlgorithm::Sha512 => {
                use crate::authentication::sha512::hmac_sha512_to;
                hmac_sha512_to(key, data, output)
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

    /// 计算HMAC到提供的缓冲区（零分配）
    pub fn compute_to(&self, data: &[u8], output: &mut [u8]) -> Result<()> {
        if self.key.is_empty() {
            return Err(CryptoKitError::InvalidKey);
        }
        self.algorithm.compute_to(&self.key, data, output)
    }

    /// 验证HMAC
    pub fn verify(&self, data: &[u8], expected_hmac: &[u8]) -> Result<bool> {
        let computed = self.compute(data)?;
        Ok(constant_time_eq(&computed, expected_hmac))
    }

    /// 获取输出大小
    pub fn output_size(&self) -> usize {
        self.algorithm.output_size()
    }
}

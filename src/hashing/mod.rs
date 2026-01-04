// 模块声明
pub mod sha1;
pub mod sha256;
pub mod sha384;
pub mod sha512;

// 重新导出主要类型和函数
pub use sha1::{sha1_hash, sha1_hash_to, SHA1};
pub use sha256::{sha256_hash, sha256_hash_to, Sha256, SHA256};
pub use sha384::{sha384_hash, sha384_hash_to, Sha384, SHA384};
pub use sha512::{sha512_hash, sha512_hash_to, Sha512, SHA512};

/// 哈希算法trait，为不同哈希算法提供统一接口
pub trait HashFunction {
    /// 哈希输出大小（字节）
    const OUTPUT_SIZE: usize;

    /// 一次性计算哈希
    fn hash(data: &[u8]) -> Vec<u8> {
        let mut output = vec![0u8; Self::OUTPUT_SIZE];
        Self::hash_to(data, &mut output);
        output
    }

    /// 计算哈希到提供的缓冲区（零分配）
    ///
    /// # 参数
    /// - `output`: 必须至少有 `OUTPUT_SIZE` 字节
    ///
    /// # Panics
    /// 如果 output 缓冲区太小会 panic
    fn hash_to(data: &[u8], output: &mut [u8]);
}

/// 哈希算法枚举，支持动态选择
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    /// 获取哈希算法的输出长度
    pub fn output_size(&self) -> usize {
        match self {
            HashAlgorithm::Sha1 => 20,
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
        }
    }

    /// 计算哈希
    pub fn compute(&self, data: &[u8]) -> Vec<u8> {
        match self {
            HashAlgorithm::Sha1 => sha1_hash(data).to_vec(),
            HashAlgorithm::Sha256 => sha256_hash(data).to_vec(),
            HashAlgorithm::Sha384 => sha384_hash(data).to_vec(),
            HashAlgorithm::Sha512 => sha512_hash(data).to_vec(),
        }
    }

    /// 计算哈希到提供的缓冲区（零分配）
    ///
    /// # 参数
    /// - `output`: 必须至少有 `output_size()` 字节
    ///
    /// # Panics
    /// 如果 output 缓冲区太小会 panic
    pub fn compute_to(&self, data: &[u8], output: &mut [u8]) {
        assert!(
            output.len() >= self.output_size(),
            "Output buffer too small: {} < {}",
            output.len(),
            self.output_size()
        );
        match self {
            HashAlgorithm::Sha1 => sha1_hash_to(data, output),
            HashAlgorithm::Sha256 => sha256_hash_to(data, output),
            HashAlgorithm::Sha384 => sha384_hash_to(data, output),
            HashAlgorithm::Sha512 => sha512_hash_to(data, output),
        }
    }
}

/// 通用哈希构建器
pub struct HashBuilder {
    algorithm: HashAlgorithm,
}

impl HashBuilder {
    /// 创建新的哈希构建器
    pub fn new(algorithm: HashAlgorithm) -> Self {
        Self { algorithm }
    }

    /// 计算哈希
    pub fn compute(&self, data: &[u8]) -> Vec<u8> {
        self.algorithm.compute(data)
    }

    /// 计算哈希到提供的缓冲区（零分配）
    pub fn compute_to(&self, data: &[u8], output: &mut [u8]) {
        self.algorithm.compute_to(data, output)
    }

    /// 获取输出大小
    pub fn output_size(&self) -> usize {
        self.algorithm.output_size()
    }
}

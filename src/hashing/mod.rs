// 模块声明
pub mod sha1;
pub mod sha256;
pub mod sha384;
pub mod sha512;

// 重新导出主要类型和函数
pub use sha1::{SHA1, sha1_hash};
pub use sha256::{SHA256, Sha256, sha256_hash};
pub use sha384::{SHA384, Sha384, sha384_hash};
pub use sha512::{SHA512, Sha512, sha512_hash};

/// 哈希算法trait，为不同哈希算法提供统一接口
pub trait HashFunction {
    type Output;

    /// 一次性计算哈希
    fn hash(data: &[u8]) -> Self::Output;
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

    /// 获取输出大小
    pub fn output_size(&self) -> usize {
        self.algorithm.output_size()
    }
}

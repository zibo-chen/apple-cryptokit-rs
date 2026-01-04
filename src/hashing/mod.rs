// Module declarations
pub mod sha1;
pub mod sha256;
pub mod sha384;
pub mod sha512;

// Re-export main types and functions
pub use sha1::{sha1_hash, sha1_hash_to, SHA1};
pub use sha256::{sha256_hash, sha256_hash_to, Sha256, SHA256};
pub use sha384::{sha384_hash, sha384_hash_to, Sha384, SHA384};
pub use sha512::{sha512_hash, sha512_hash_to, Sha512, SHA512};

/// Hash algorithm trait providing a unified interface for different hash algorithms
pub trait HashFunction {
    /// Hash output size (in bytes)
    const OUTPUT_SIZE: usize;

    /// Compute hash in one operation
    fn hash(data: &[u8]) -> Vec<u8> {
        let mut output = vec![0u8; Self::OUTPUT_SIZE];
        Self::hash_to(data, &mut output);
        output
    }

    /// Compute hash to provided buffer (zero-allocation)
    ///
    /// # Parameters
    /// - `output`: Must be at least `OUTPUT_SIZE` bytes
    ///
    /// # Panics
    /// Panics if output buffer is too small
    fn hash_to(data: &[u8], output: &mut [u8]);
}

/// Hash algorithm enumeration, supporting dynamic selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    /// Get the output length of the hash algorithm
    pub fn output_size(&self) -> usize {
        match self {
            HashAlgorithm::Sha1 => 20,
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
        }
    }

    /// Compute hash
    pub fn compute(&self, data: &[u8]) -> Vec<u8> {
        match self {
            HashAlgorithm::Sha1 => sha1_hash(data).to_vec(),
            HashAlgorithm::Sha256 => sha256_hash(data).to_vec(),
            HashAlgorithm::Sha384 => sha384_hash(data).to_vec(),
            HashAlgorithm::Sha512 => sha512_hash(data).to_vec(),
        }
    }

    /// Compute hash to provided buffer (zero-allocation)
    ///
    /// # Parameters
    /// - `output`: Must be at least `output_size()` bytes
    ///
    /// # Panics
    /// Panics if output buffer is too small
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

/// Generic hash builder
pub struct HashBuilder {
    algorithm: HashAlgorithm,
}

impl HashBuilder {
    /// Create a new hash builder
    pub fn new(algorithm: HashAlgorithm) -> Self {
        Self { algorithm }
    }

    /// Compute hash
    pub fn compute(&self, data: &[u8]) -> Vec<u8> {
        self.algorithm.compute(data)
    }

    /// Compute hash to provided buffer (zero-allocation)
    pub fn compute_to(&self, data: &[u8], output: &mut [u8]) {
        self.algorithm.compute_to(data, output)
    }

    /// Get output size
    pub fn output_size(&self) -> usize {
        self.algorithm.output_size()
    }
}

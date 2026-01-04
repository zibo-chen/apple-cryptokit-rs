use crate::error::{CryptoKitError, Result};

/// HMAC algorithm trait providing a unified interface for different HMAC algorithms
pub trait HMAC {
    /// HMAC output size (bytes)
    const OUTPUT_SIZE: usize;

    /// Calculate HMAC
    fn authenticate(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let mut output = vec![0u8; Self::OUTPUT_SIZE];
        Self::authenticate_to(key, data, &mut output)?;
        Ok(output)
    }

    /// Calculate HMAC to the provided buffer (zero-allocation)
    ///
    /// # Parameters
    /// - `output`: Must be at least `OUTPUT_SIZE` bytes
    ///
    /// # Returns
    /// - `Ok(())`: Success
    /// - `Err`: Authentication failed
    fn authenticate_to(key: &[u8], data: &[u8], output: &mut [u8]) -> Result<()>;

    /// Get output size (deprecated, use OUTPUT_SIZE constant instead)
    fn output_size() -> usize {
        Self::OUTPUT_SIZE
    }
}

/// Message authentication code verification
pub fn verify_hmac<T: AsRef<[u8]>>(expected: T, computed: T) -> bool {
    let expected_bytes = expected.as_ref();
    let computed_bytes = computed.as_ref();

    if expected_bytes.len() != computed_bytes.len() {
        return false;
    }

    // Use constant-time comparison to prevent timing attacks
    constant_time_eq(expected_bytes, computed_bytes)
}

/// Constant-time byte comparison
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

/// HMAC algorithm enumeration
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HmacAlgorithm {
    /// SHA-1 (insecure, for compatibility only)
    Sha1,
    /// SHA-256
    Sha256,
    /// SHA-384
    Sha384,
    /// SHA-512
    Sha512,
}

impl HmacAlgorithm {
    /// Get output length
    pub fn output_size(&self) -> usize {
        match self {
            HmacAlgorithm::Sha1 => 20,
            HmacAlgorithm::Sha256 => 32,
            HmacAlgorithm::Sha384 => 48,
            HmacAlgorithm::Sha512 => 64,
        }
    }

    /// Calculate HMAC
    pub fn compute(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let mut output = vec![0u8; self.output_size()];
        self.compute_to(key, data, &mut output)?;
        Ok(output)
    }

    /// Calculate HMAC to the provided buffer (zero-allocation)
    ///
    /// # Parameters
    /// - `output`: Must be at least `output_size()` bytes
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

    /// Verify HMAC
    pub fn verify(&self, key: &[u8], data: &[u8], expected_hmac: &[u8]) -> Result<bool> {
        let computed = self.compute(key, data)?;
        Ok(constant_time_eq(&computed, expected_hmac))
    }
}

/// HMAC builder
pub struct HmacBuilder {
    algorithm: HmacAlgorithm,
    key: Vec<u8>,
}

impl HmacBuilder {
    /// Create a new HMAC builder
    pub fn new(algorithm: HmacAlgorithm) -> Self {
        Self {
            algorithm,
            key: Vec::new(),
        }
    }

    /// Set the key
    pub fn key(mut self, key: &[u8]) -> Self {
        self.key = key.to_vec();
        self
    }

    /// Calculate HMAC
    pub fn compute(&self, data: &[u8]) -> Result<Vec<u8>> {
        if self.key.is_empty() {
            return Err(CryptoKitError::InvalidKey);
        }
        self.algorithm.compute(&self.key, data)
    }

    /// Calculate HMAC to the provided buffer (zero-allocation)
    pub fn compute_to(&self, data: &[u8], output: &mut [u8]) -> Result<()> {
        if self.key.is_empty() {
            return Err(CryptoKitError::InvalidKey);
        }
        self.algorithm.compute_to(&self.key, data, output)
    }

    /// Verify HMAC
    pub fn verify(&self, data: &[u8], expected_hmac: &[u8]) -> Result<bool> {
        let computed = self.compute(data)?;
        Ok(constant_time_eq(&computed, expected_hmac))
    }

    /// Get output size
    pub fn output_size(&self) -> usize {
        self.algorithm.output_size()
    }
}

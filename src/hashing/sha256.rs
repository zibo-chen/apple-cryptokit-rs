// SHA-256 hash algorithm implementation

use super::HashFunction;
use std::ffi::c_void;

/// SHA-256 output size
pub const SHA256_OUTPUT_SIZE: usize = 32;

// SHA256 Swift FFI declarations
extern "C" {
    #[link_name = "sha256_hash"]
    fn swift_sha256_hash(data: *const u8, length: i32, out_hash: *mut u8);

    #[link_name = "sha256_init"]
    fn swift_sha256_init() -> *mut c_void;

    #[link_name = "sha256_update"]
    fn swift_sha256_update(ptr: *mut c_void, data: *const u8, len: i32);

    #[link_name = "sha256_finalize"]
    fn swift_sha256_finalize(ptr: *mut c_void, out: *mut u8);

    #[link_name = "sha256_free"]
    fn swift_sha256_free(ptr: *mut c_void);
}

/// SHA256 one-shot hash computation
pub fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    sha256_hash_to(data, &mut output);
    output
}

/// SHA256 hash computation to provided buffer (zero allocation)
///
/// # Arguments
/// - `output`: must be at least 32 bytes
///
/// # Panics
/// Panics if output buffer is too small
pub fn sha256_hash_to(data: &[u8], output: &mut [u8]) {
    assert!(
        output.len() >= SHA256_OUTPUT_SIZE,
        "Output buffer too small: {} < {}",
        output.len(),
        SHA256_OUTPUT_SIZE
    );
    unsafe {
        swift_sha256_hash(data.as_ptr(), data.len() as i32, output.as_mut_ptr());
    }
}

/// SHA256 streaming hash state
pub struct Sha256 {
    ptr: *mut c_void,
}

impl Sha256 {
    /// Create a new SHA256 hash state
    pub fn new() -> Self {
        let ptr = unsafe { swift_sha256_init() };
        Self { ptr }
    }

    /// Update hash state
    pub fn update(&mut self, data: &[u8]) {
        unsafe {
            swift_sha256_update(self.ptr, data.as_ptr(), data.len() as i32);
        }
    }

    /// Finalize hash computation and return result
    pub fn finalize(self) -> [u8; 32] {
        let mut hash = [0u8; 32];
        unsafe {
            swift_sha256_finalize(self.ptr, hash.as_mut_ptr());
        }
        hash
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Sha256 {
    fn drop(&mut self) {
        unsafe {
            swift_sha256_free(self.ptr);
        }
    }
}

/// SHA256 hash algorithm implementation
pub struct SHA256;

impl HashFunction for SHA256 {
    const OUTPUT_SIZE: usize = SHA256_OUTPUT_SIZE;

    fn hash_to(data: &[u8], output: &mut [u8]) {
        sha256_hash_to(data, output)
    }
}

// Re-export
pub use SHA256 as Sha256Algorithm;

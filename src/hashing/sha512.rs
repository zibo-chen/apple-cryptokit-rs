// SHA-512 hash algorithm implementation

use super::HashFunction;
use std::ffi::c_void;

/// SHA-512 output size
pub const SHA512_OUTPUT_SIZE: usize = 64;

// SHA512 Swift FFI declarations
extern "C" {
    #[link_name = "sha512_hash"]
    fn swift_sha512_hash(data: *const u8, length: i32, out_hash: *mut u8);

    #[link_name = "sha512_init"]
    fn swift_sha512_init() -> *mut c_void;

    #[link_name = "sha512_update"]
    fn swift_sha512_update(ptr: *mut c_void, data: *const u8, len: i32);

    #[link_name = "sha512_finalize"]
    fn swift_sha512_finalize(ptr: *mut c_void, out: *mut u8);

    #[link_name = "sha512_free"]
    fn swift_sha512_free(ptr: *mut c_void);
}

/// SHA512 one-shot hash computation
pub fn sha512_hash(data: &[u8]) -> [u8; 64] {
    let mut output = [0u8; 64];
    sha512_hash_to(data, &mut output);
    output
}

/// SHA512 hash computation to provided buffer (zero allocation)
///
/// # Arguments
/// - `output`: must be at least 64 bytes
///
/// # Panics
/// Panics if output buffer is too small
pub fn sha512_hash_to(data: &[u8], output: &mut [u8]) {
    assert!(
        output.len() >= SHA512_OUTPUT_SIZE,
        "Output buffer too small: {} < {}",
        output.len(),
        SHA512_OUTPUT_SIZE
    );
    unsafe {
        swift_sha512_hash(data.as_ptr(), data.len() as i32, output.as_mut_ptr());
    }
}

/// SHA512 streaming hash state
pub struct Sha512 {
    ptr: *mut c_void,
}

impl Sha512 {
    /// Create a new SHA512 hash state
    pub fn new() -> Self {
        let ptr = unsafe { swift_sha512_init() };
        Self { ptr }
    }

    /// Update hash state
    pub fn update(&mut self, data: &[u8]) {
        unsafe {
            swift_sha512_update(self.ptr, data.as_ptr(), data.len() as i32);
        }
    }

    /// Finalize hash computation and return result
    pub fn finalize(self) -> [u8; 64] {
        self.snapshot()
    }

    pub fn snapshot(&self) -> [u8; 64] {
        let mut hash = [0u8; 64];
        unsafe {
            swift_sha512_finalize(self.ptr, hash.as_mut_ptr());
        }
        hash
    }
}

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Sha512 {
    fn drop(&mut self) {
        unsafe {
            swift_sha512_free(self.ptr);
        }
    }
}

/// SHA512 hash algorithm implementation
pub struct SHA512;

impl HashFunction for SHA512 {
    const OUTPUT_SIZE: usize = SHA512_OUTPUT_SIZE;

    fn hash_to(data: &[u8], output: &mut [u8]) {
        sha512_hash_to(data, output)
    }
}

// Re-export
pub use SHA512 as Sha512Algorithm;

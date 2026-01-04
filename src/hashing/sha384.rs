// SHA-384 hash algorithm implementation

use super::HashFunction;
use std::ffi::c_void;

/// SHA-384 output size
pub const SHA384_OUTPUT_SIZE: usize = 48;

// SHA384 Swift FFI declarations
unsafe extern "C" {
    #[link_name = "sha384_hash"]
    fn swift_sha384_hash(data: *const u8, length: i32, out_hash: *mut u8);

    #[link_name = "sha384_init"]
    fn swift_sha384_init() -> *mut c_void;

    #[link_name = "sha384_update"]
    fn swift_sha384_update(ptr: *mut c_void, data: *const u8, len: i32);

    #[link_name = "sha384_finalize"]
    fn swift_sha384_finalize(ptr: *mut c_void, out: *mut u8);

    #[link_name = "sha384_free"]
    fn swift_sha384_free(ptr: *mut c_void);
}

/// SHA384 one-shot hash computation
pub fn sha384_hash(data: &[u8]) -> [u8; 48] {
    let mut output = [0u8; 48];
    sha384_hash_to(data, &mut output);
    output
}

/// SHA384 hash computation to provided buffer (zero allocation)
///
/// # Arguments
/// - `output`: must be at least 48 bytes
///
/// # Panics
/// Panics if output buffer is too small
pub fn sha384_hash_to(data: &[u8], output: &mut [u8]) {
    assert!(
        output.len() >= SHA384_OUTPUT_SIZE,
        "Output buffer too small: {} < {}",
        output.len(),
        SHA384_OUTPUT_SIZE
    );
    unsafe {
        swift_sha384_hash(data.as_ptr(), data.len() as i32, output.as_mut_ptr());
    }
}

/// SHA384 streaming hash state
pub struct Sha384 {
    ptr: *mut c_void,
}

impl Sha384 {
    /// Create a new SHA384 hash state
    pub fn new() -> Self {
        let ptr = unsafe { swift_sha384_init() };
        Self { ptr }
    }

    /// Update hash state
    pub fn update(&mut self, data: &[u8]) {
        unsafe {
            swift_sha384_update(self.ptr, data.as_ptr(), data.len() as i32);
        }
    }

    /// Finalize hash computation and return result
    pub fn finalize(self) -> [u8; 48] {
        let mut hash = [0u8; 48];
        unsafe {
            swift_sha384_finalize(self.ptr, hash.as_mut_ptr());
        }
        hash
    }
}

impl Default for Sha384 {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Sha384 {
    fn drop(&mut self) {
        unsafe {
            swift_sha384_free(self.ptr);
        }
    }
}

/// SHA384 hash algorithm implementation
pub struct SHA384;

impl HashFunction for SHA384 {
    const OUTPUT_SIZE: usize = SHA384_OUTPUT_SIZE;

    fn hash_to(data: &[u8], output: &mut [u8]) {
        sha384_hash_to(data, output)
    }
}

// Re-export
pub use SHA384 as Sha384Algorithm;

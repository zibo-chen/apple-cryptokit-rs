// SHA-1 hash algorithm implementation (insecure, for compatibility only)

use super::HashFunction;

/// SHA-1 output size
pub const SHA1_OUTPUT_SIZE: usize = 20;

// SHA-1 Swift FFI declarations
unsafe extern "C" {
    #[link_name = "sha1_hash"]
    fn swift_sha1_hash(data: *const u8, length: i32, out_hash: *mut u8);
}

/// SHA-1 one-shot hash computation (insecure, for compatibility only)
pub fn sha1_hash(data: &[u8]) -> [u8; 20] {
    let mut output = [0u8; 20];
    sha1_hash_to(data, &mut output);
    output
}

/// SHA-1 hash computation to provided buffer (zero allocation)
///
/// # Arguments
/// - `output`: must be at least 20 bytes
///
/// # Panics
/// Panics if output buffer is too small
pub fn sha1_hash_to(data: &[u8], output: &mut [u8]) {
    assert!(
        output.len() >= SHA1_OUTPUT_SIZE,
        "Output buffer too small: {} < {}",
        output.len(),
        SHA1_OUTPUT_SIZE
    );
    unsafe {
        swift_sha1_hash(data.as_ptr(), data.len() as i32, output.as_mut_ptr());
    }
}

/// SHA-1 hash algorithm implementation
pub struct SHA1;

impl HashFunction for SHA1 {
    const OUTPUT_SIZE: usize = SHA1_OUTPUT_SIZE;

    fn hash_to(data: &[u8], output: &mut [u8]) {
        sha1_hash_to(data, output)
    }
}

// Re-export
pub use SHA1 as Sha1Algorithm;

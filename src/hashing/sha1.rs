// SHA-1 哈希算法实现（不安全，仅用于兼容性）

use super::HashFunction;

/// SHA-1 输出大小
pub const SHA1_OUTPUT_SIZE: usize = 20;

// SHA-1 Swift FFI 声明
unsafe extern "C" {
    #[link_name = "sha1_hash"]
    fn swift_sha1_hash(data: *const u8, length: i32, out_hash: *mut u8);
}

/// SHA-1 一次性哈希计算（不安全，仅用于兼容性）
pub fn sha1_hash(data: &[u8]) -> [u8; 20] {
    let mut output = [0u8; 20];
    sha1_hash_to(data, &mut output);
    output
}

/// SHA-1 哈希计算到提供的缓冲区（零分配）
///
/// # 参数
/// - `output`: 必须至少有 20 字节
///
/// # Panics
/// 如果 output 缓冲区太小会 panic
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

/// SHA-1 哈希算法实现
pub struct SHA1;

impl HashFunction for SHA1 {
    const OUTPUT_SIZE: usize = SHA1_OUTPUT_SIZE;

    fn hash_to(data: &[u8], output: &mut [u8]) {
        sha1_hash_to(data, output)
    }
}

// Re-export
pub use SHA1 as Sha1Algorithm;

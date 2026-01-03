// SHA-1 哈希算法实现（不安全，仅用于兼容性）

use super::HashFunction;

// SHA-1 Swift FFI 声明
extern "C" {
    #[link_name = "sha1_hash"]
    fn swift_sha1_hash(data: *const u8, length: i32, out_hash: *mut u8);
}

/// SHA-1 一次性哈希计算（不安全，仅用于兼容性）
pub fn sha1_hash(data: &[u8]) -> [u8; 20] {
    unsafe {
        let mut output_hash = [0u8; 20];
        swift_sha1_hash(data.as_ptr(), data.len() as i32, output_hash.as_mut_ptr());
        output_hash
    }
}

/// SHA-1 哈希算法实现
pub struct SHA1;

impl HashFunction for SHA1 {
    type Output = [u8; 20];

    fn hash(data: &[u8]) -> Self::Output {
        sha1_hash(data)
    }
}

// Re-export
pub use SHA1 as Sha1Algorithm;

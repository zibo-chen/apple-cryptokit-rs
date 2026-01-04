// SHA-512 哈希算法实现

use super::HashFunction;
use std::ffi::c_void;

/// SHA-512 输出大小
pub const SHA512_OUTPUT_SIZE: usize = 64;

// SHA512 Swift FFI 声明
unsafe extern "C" {
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

/// SHA512 一次性哈希计算
pub fn sha512_hash(data: &[u8]) -> [u8; 64] {
    let mut output = [0u8; 64];
    sha512_hash_to(data, &mut output);
    output
}

/// SHA512 哈希计算到提供的缓冲区（零分配）
///
/// # 参数
/// - `output`: 必须至少有 64 字节
///
/// # Panics
/// 如果 output 缓冲区太小会 panic
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

/// SHA512 流式哈希状态
pub struct Sha512 {
    ptr: *mut c_void,
}

impl Sha512 {
    /// 创建新的SHA512哈希状态
    pub fn new() -> Self {
        let ptr = unsafe { swift_sha512_init() };
        Self { ptr }
    }

    /// 更新哈希状态
    pub fn update(&mut self, data: &[u8]) {
        unsafe {
            swift_sha512_update(self.ptr, data.as_ptr(), data.len() as i32);
        }
    }

    /// 完成哈希计算并返回结果
    pub fn finalize(self) -> [u8; 64] {
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

/// SHA512 哈希算法实现
pub struct SHA512;

impl HashFunction for SHA512 {
    const OUTPUT_SIZE: usize = SHA512_OUTPUT_SIZE;

    fn hash_to(data: &[u8], output: &mut [u8]) {
        sha512_hash_to(data, output)
    }
}

// Re-export
pub use SHA512 as Sha512Algorithm;

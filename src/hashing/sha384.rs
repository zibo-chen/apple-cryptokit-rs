// SHA-384 哈希算法实现

use super::HashFunction;
use std::ffi::c_void;

// SHA384 Swift FFI 声明
extern "C" {
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

/// SHA384 一次性哈希计算
pub fn sha384_hash(data: &[u8]) -> [u8; 48] {
    unsafe {
        let mut output_hash = [0u8; 48];
        swift_sha384_hash(data.as_ptr(), data.len() as i32, output_hash.as_mut_ptr());
        output_hash
    }
}

/// SHA384 流式哈希状态
pub struct Sha384 {
    ptr: *mut c_void,
}

impl Sha384 {
    /// 创建新的SHA384哈希状态
    pub fn new() -> Self {
        let ptr = unsafe { swift_sha384_init() };
        Self { ptr }
    }

    /// 更新哈希状态
    pub fn update(&mut self, data: &[u8]) {
        unsafe {
            swift_sha384_update(self.ptr, data.as_ptr(), data.len() as i32);
        }
    }

    /// 完成哈希计算并返回结果
    pub fn finalize(self) -> [u8; 48] {
        self.snapshot()
    }

    pub fn snapshot(&self) -> [u8; 48] {
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

/// SHA384 哈希算法实现
pub struct SHA384;

impl HashFunction for SHA384 {
    type Output = [u8; 48];

    fn hash(data: &[u8]) -> Self::Output {
        sha384_hash(data)
    }
}

// Re-export
pub use SHA384 as Sha384Algorithm;

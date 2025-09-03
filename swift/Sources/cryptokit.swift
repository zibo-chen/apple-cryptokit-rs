import CryptoKit
import Foundation

// MARK: - Apple CryptoKit Swift 模块入口
// 这个文件作为所有模块的统一入口点，确保所有函数都被正确导出

// 重新导出所有模块的公共接口，以便C FFI可以访问
// 注意：由于Swift的模块系统限制，我们需要在这里重新声明或导入所有@_cdecl函数

// 从各个模块导入功能
// 由于Swift的编译器限制，我们不能直接import子模块
// 所以所有的实现都需要在同一个target中

// 这个文件的目的是提供一个清晰的概述，展示库的整体架构
// 实际的函数实现分布在各个专门的文件中

/*
模块结构概述:

1. Hashing/ - 哈希算法
   - Hashing.swift: SHA256, SHA384, SHA512, MD5等

2. Authentication/ - 消息认证
   - HMAC.swift: HMAC-SHA256, HMAC-SHA1, HMAC-SHA384, HMAC-SHA512

3. Symmetric/ - 对称加密
   - AES.swift: AES-GCM加密/解密
   - ChaCha20Poly1305.swift: ChaCha20-Poly1305加密/解密

4. KeyDerivation/ - 密钥派生
   - HKDF.swift: HKDF-SHA256, HKDF-SHA384, HKDF-SHA512

5. Keys/ - 密钥管理
   - SymmetricKeys.swift: 对称密钥生成和管理

6. Asymmetric/ - 非对称加密
   - Curve25519.swift: Ed25519签名, X25519密钥交换
   - P256.swift: P-256 ECDSA签名和ECDH密钥交换
   - P384.swift: P-384 ECDSA签名和ECDH密钥交换
   - P521.swift: P-521 ECDSA签名和ECDH密钥交换

这种模块化设计与Rust端的结构完全对应，便于维护和扩展。
*/

// 版本信息
public let APPLE_CRYPTOKIT_SWIFT_VERSION = "0.1.0"
public let SUPPORTED_ALGORITHMS = [
   "SHA256", "SHA384", "SHA512", "MD5",
   "HMAC-SHA256", "HMAC-SHA1", "HMAC-SHA384", "HMAC-SHA512",
   "AES-GCM", "ChaCha20-Poly1305",
   "HKDF-SHA256", "HKDF-SHA384", "HKDF-SHA512",
   "Ed25519", "X25519", "P256", "P384", "P521",
]

// 获取库版本信息的函数
@_cdecl("get_library_version")
func get_library_version() -> UnsafePointer<CChar>? {
   return APPLE_CRYPTOKIT_SWIFT_VERSION.withCString { ptr in
      return UnsafePointer(ptr)
   }
}

// 检查算法支持情况
@_cdecl("is_algorithm_supported")
func is_algorithm_supported(_ algorithm: UnsafePointer<CChar>) -> Int32 {
   guard let algoString = String(cString: algorithm, encoding: .utf8) else {
      return 0  // Invalid algorithm name
   }

   return SUPPORTED_ALGORITHMS.contains(algoString) ? 1 : 0
}

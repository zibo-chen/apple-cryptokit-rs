import CryptoKit
import Foundation

// MARK: - 哈希算法模块

// SHA-1 相关函数（不安全，仅用于兼容性）
@_cdecl("sha1_hash")
func sha1_hash(
    _ input: UnsafePointer<UInt8>,
    _ input_len: Int32,
    _ output: UnsafeMutablePointer<UInt8>
) {
    let data = Data(bytes: input, count: Int(input_len))
    let hash = Insecure.SHA1.hash(data: data)
    hash.withUnsafeBytes { hashBytes in
        output.update(from: hashBytes.baseAddress!.assumingMemoryBound(to: UInt8.self), count: 20)
    }
}

// SHA256 相关函数
@_cdecl("sha256_hash")
func sha256_hash(
    _ input: UnsafePointer<UInt8>,
    _ input_len: Int32,
    _ output: UnsafeMutablePointer<UInt8>
) {
    let data = Data(bytes: input, count: Int(input_len))
    let hash = SHA256.hash(data: data)
    hash.withUnsafeBytes { hashBytes in
        output.update(from: hashBytes.baseAddress!.assumingMemoryBound(to: UInt8.self), count: 32)
    }
}

@_cdecl("sha384_hash")
func sha384_hash(
    _ input: UnsafePointer<UInt8>,
    _ input_len: Int32,
    _ output: UnsafeMutablePointer<UInt8>
) {
    let data = Data(bytes: input, count: Int(input_len))
    let hash = SHA384.hash(data: data)
    hash.withUnsafeBytes { hashBytes in
        output.update(from: hashBytes.baseAddress!.assumingMemoryBound(to: UInt8.self), count: 48)
    }
}

@_cdecl("sha512_hash")
func sha512_hash(
    _ input: UnsafePointer<UInt8>,
    _ input_len: Int32,
    _ output: UnsafeMutablePointer<UInt8>
) {
    let data = Data(bytes: input, count: Int(input_len))
    let hash = SHA512.hash(data: data)
    hash.withUnsafeBytes { hashBytes in
        output.update(from: hashBytes.baseAddress!.assumingMemoryBound(to: UInt8.self), count: 64)
    }
}

// SHA256 流式哈希相关函数
@_cdecl("sha256_init")
func sha256_init() -> UnsafeMutableRawPointer {
    let sha256_box = Sha256Box()
    return Unmanaged.passRetained(sha256_box).toOpaque()
}

@_cdecl("sha256_update")
func sha256_update(_ ptr: UnsafeMutableRawPointer, _ data: UnsafePointer<UInt8>, _ len: Int32) {
    let sha256_box = Unmanaged<Sha256Box>.fromOpaque(ptr).takeUnretainedValue()
    let buffer = UnsafeRawBufferPointer(start: data, count: Int(len))
    sha256_box.update(bufferPointer: buffer)
}

@_cdecl("sha256_finalize")
func sha256_finalize(_ ptr: UnsafeMutableRawPointer, _ output: UnsafeMutablePointer<UInt8>) {
    let sha256_box = Unmanaged<Sha256Box>.fromOpaque(ptr).takeUnretainedValue()
    let digest = sha256_box.finalize()
    digest.withUnsafeBytes {
        output.update(from: $0.baseAddress!.assumingMemoryBound(to: UInt8.self), count: 32)
    }
}

@_cdecl("sha256_free")
func sha256_free(_ ptr: UnsafeMutableRawPointer) {
    Unmanaged<Sha256Box>.fromOpaque(ptr).release()
}

// SHA384 流式哈希相关函数
@_cdecl("sha384_init")
func sha384_init() -> UnsafeMutableRawPointer {
    let sha384_box = Sha384Box()
    return Unmanaged.passRetained(sha384_box).toOpaque()
}

@_cdecl("sha384_update")
func sha384_update(_ ptr: UnsafeMutableRawPointer, _ data: UnsafePointer<UInt8>, _ len: Int32) {
    let sha384_box = Unmanaged<Sha384Box>.fromOpaque(ptr).takeUnretainedValue()
    let buffer = UnsafeRawBufferPointer(start: data, count: Int(len))
    sha384_box.update(bufferPointer: buffer)
}

@_cdecl("sha384_finalize")
func sha384_finalize(_ ptr: UnsafeMutableRawPointer, _ output: UnsafeMutablePointer<UInt8>) {
    let sha384_box = Unmanaged<Sha384Box>.fromOpaque(ptr).takeUnretainedValue()
    let digest = sha384_box.finalize()
    digest.withUnsafeBytes {
        output.update(from: $0.baseAddress!.assumingMemoryBound(to: UInt8.self), count: 48)
    }
}

@_cdecl("sha384_free")
func sha384_free(_ ptr: UnsafeMutableRawPointer) {
    Unmanaged<Sha384Box>.fromOpaque(ptr).release()
}

// SHA512 流式哈希相关函数
@_cdecl("sha512_init")
func sha512_init() -> UnsafeMutableRawPointer {
    let sha512_box = Sha512Box()
    return Unmanaged.passRetained(sha512_box).toOpaque()
}

@_cdecl("sha512_update")
func sha512_update(_ ptr: UnsafeMutableRawPointer, _ data: UnsafePointer<UInt8>, _ len: Int32) {
    let sha512_box = Unmanaged<Sha512Box>.fromOpaque(ptr).takeUnretainedValue()
    let buffer = UnsafeRawBufferPointer(start: data, count: Int(len))
    sha512_box.update(bufferPointer: buffer)
}

@_cdecl("sha512_finalize")
func sha512_finalize(_ ptr: UnsafeMutableRawPointer, _ output: UnsafeMutablePointer<UInt8>) {
    let sha512_box = Unmanaged<Sha512Box>.fromOpaque(ptr).takeUnretainedValue()
    let digest = sha512_box.finalize()
    digest.withUnsafeBytes {
        output.update(from: $0.baseAddress!.assumingMemoryBound(to: UInt8.self), count: 64)
    }
}

@_cdecl("sha512_free")
func sha512_free(_ ptr: UnsafeMutableRawPointer) {
    Unmanaged<Sha512Box>.fromOpaque(ptr).release()
}

// MD5 (不安全，仅用于兼容性)
@_cdecl("md5_hash")
func md5_hash(
    _ input: UnsafePointer<UInt8>,
    _ input_len: Int32,
    _ output: UnsafeMutablePointer<UInt8>
) {
    let data = Data(bytes: input, count: Int(input_len))
    let hash = Insecure.MD5.hash(data: data)
    hash.withUnsafeBytes { hashBytes in
        output.update(from: hashBytes.baseAddress!.assumingMemoryBound(to: UInt8.self), count: 16)
    }
}

// MARK: - 流式哈希状态管理类

// SHA256 流式哈希状态管理类
public class Sha256Box {
    private var sha256 = SHA256()

    func update(bufferPointer: UnsafeRawBufferPointer) {
        sha256.update(bufferPointer: bufferPointer)
    }

    func finalize() -> SHA256Digest {
        return sha256.finalize()
    }
}

// SHA384 流式哈希状态管理类
public class Sha384Box {
    private var sha384 = SHA384()

    func update(bufferPointer: UnsafeRawBufferPointer) {
        sha384.update(bufferPointer: bufferPointer)
    }

    func finalize() -> SHA384Digest {
        return sha384.finalize()
    }
}

// SHA512 流式哈希状态管理类
public class Sha512Box {
    private var sha512 = SHA512()

    func update(bufferPointer: UnsafeRawBufferPointer) {
        sha512.update(bufferPointer: bufferPointer)
    }

    func finalize() -> SHA512Digest {
        return sha512.finalize()
    }
}

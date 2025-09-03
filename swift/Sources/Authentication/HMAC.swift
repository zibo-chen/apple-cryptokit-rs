import CryptoKit
import Foundation

// MARK: - HMAC (Hash-based Message Authentication Code) 模块

@_cdecl("hmac_sha256")
func hmac_sha256(
    _ key: UnsafePointer<UInt8>,
    _ key_len: Int32,
    _ data: UnsafePointer<UInt8>,
    _ data_len: Int32,
    _ output: UnsafeMutablePointer<UInt8>
) -> Int32 {
    let keyData = Data(bytes: key, count: Int(key_len))
    let messageData = Data(bytes: data, count: Int(data_len))

    guard let symmetricKey = SymmetricKey(data: keyData) as SymmetricKey? else {
        return -1  // Error: Invalid key
    }

    let hmac = HMAC<SHA256>.authenticationCode(for: messageData, using: symmetricKey)
    hmac.withUnsafeBytes { hmacBytes in
        output.update(from: hmacBytes.baseAddress!.assumingMemoryBound(to: UInt8.self), count: 32)
    }
    return 32  // Success, return output length
}

@_cdecl("hmac_sha1")
func hmac_sha1(
    _ key: UnsafePointer<UInt8>,
    _ key_len: Int32,
    _ data: UnsafePointer<UInt8>,
    _ data_len: Int32,
    _ output: UnsafeMutablePointer<UInt8>
) -> Int32 {
    let keyData = Data(bytes: key, count: Int(key_len))
    let messageData = Data(bytes: data, count: Int(data_len))

    guard let symmetricKey = SymmetricKey(data: keyData) as SymmetricKey? else {
        return -1  // Error: Invalid key
    }

    let hmac = HMAC<Insecure.SHA1>.authenticationCode(for: messageData, using: symmetricKey)
    hmac.withUnsafeBytes { hmacBytes in
        output.update(from: hmacBytes.baseAddress!.assumingMemoryBound(to: UInt8.self), count: 20)
    }
    return 20  // Success, return output length
}

@_cdecl("hmac_sha384")
func hmac_sha384(
    _ key: UnsafePointer<UInt8>,
    _ key_len: Int32,
    _ data: UnsafePointer<UInt8>,
    _ data_len: Int32,
    _ output: UnsafeMutablePointer<UInt8>
) -> Int32 {
    let keyData = Data(bytes: key, count: Int(key_len))
    let messageData = Data(bytes: data, count: Int(data_len))

    guard let symmetricKey = SymmetricKey(data: keyData) as SymmetricKey? else {
        return -1  // Error: Invalid key
    }

    let hmac = HMAC<SHA384>.authenticationCode(for: messageData, using: symmetricKey)
    hmac.withUnsafeBytes { hmacBytes in
        output.update(from: hmacBytes.baseAddress!.assumingMemoryBound(to: UInt8.self), count: 48)
    }
    return 48  // Success, return output length
}

@_cdecl("hmac_sha512")
func hmac_sha512(
    _ key: UnsafePointer<UInt8>,
    _ key_len: Int32,
    _ data: UnsafePointer<UInt8>,
    _ data_len: Int32,
    _ output: UnsafeMutablePointer<UInt8>
) -> Int32 {
    let keyData = Data(bytes: key, count: Int(key_len))
    let messageData = Data(bytes: data, count: Int(data_len))

    guard let symmetricKey = SymmetricKey(data: keyData) as SymmetricKey? else {
        return -1  // Error: Invalid key
    }

    let hmac = HMAC<SHA512>.authenticationCode(for: messageData, using: symmetricKey)
    hmac.withUnsafeBytes { hmacBytes in
        output.update(from: hmacBytes.baseAddress!.assumingMemoryBound(to: UInt8.self), count: 64)
    }
    return 64  // Success, return output length
}

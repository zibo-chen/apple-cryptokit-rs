import CryptoKit
import Foundation

// MARK: - 密钥派生功能模块 (HKDF)

@_cdecl("hkdf_sha256_derive")
func hkdf_sha256_derive(
    _ input_key: UnsafePointer<UInt8>,
    _ input_key_len: Int32,
    _ salt: UnsafePointer<UInt8>,
    _ salt_len: Int32,
    _ info: UnsafePointer<UInt8>,
    _ info_len: Int32,
    _ output_length: Int32,
    _ output: UnsafeMutablePointer<UInt8>
) -> Int32 {
    guard #available(macOS 11.0, iOS 14.0, watchOS 7.0, tvOS 14.0, *) else {
        return -1  // HKDF not available on this platform
    }

    let inputKeyData = Data(bytes: input_key, count: Int(input_key_len))
    let saltData = Data(bytes: salt, count: Int(salt_len))
    let infoData = Data(bytes: info, count: Int(info_len))

    let inputKey = SymmetricKey(data: inputKeyData)

    let derivedKey = HKDF<SHA256>.deriveKey(
        inputKeyMaterial: inputKey,
        salt: saltData,
        info: infoData,
        outputByteCount: Int(output_length)
    )

    derivedKey.withUnsafeBytes { keyBytes in
        output.update(
            from: keyBytes.baseAddress!.assumingMemoryBound(to: UInt8.self),
            count: Int(output_length)
        )
    }

    return 0  // Success
}

@_cdecl("hkdf_sha384_derive")
func hkdf_sha384_derive(
    _ input_key: UnsafePointer<UInt8>,
    _ input_key_len: Int32,
    _ salt: UnsafePointer<UInt8>,
    _ salt_len: Int32,
    _ info: UnsafePointer<UInt8>,
    _ info_len: Int32,
    _ output_length: Int32,
    _ output: UnsafeMutablePointer<UInt8>
) -> Int32 {
    guard #available(macOS 11.0, iOS 14.0, watchOS 7.0, tvOS 14.0, *) else {
        return -1  // HKDF not available on this platform
    }

    let inputKeyData = Data(bytes: input_key, count: Int(input_key_len))
    let saltData = Data(bytes: salt, count: Int(salt_len))
    let infoData = Data(bytes: info, count: Int(info_len))

    let inputKey = SymmetricKey(data: inputKeyData)

    let derivedKey = HKDF<SHA384>.deriveKey(
        inputKeyMaterial: inputKey,
        salt: saltData,
        info: infoData,
        outputByteCount: Int(output_length)
    )

    derivedKey.withUnsafeBytes { keyBytes in
        output.update(
            from: keyBytes.baseAddress!.assumingMemoryBound(to: UInt8.self),
            count: Int(output_length)
        )
    }

    return 0  // Success
}

@_cdecl("hkdf_sha512_derive")
func hkdf_sha512_derive(
    _ input_key: UnsafePointer<UInt8>,
    _ input_key_len: Int32,
    _ salt: UnsafePointer<UInt8>,
    _ salt_len: Int32,
    _ info: UnsafePointer<UInt8>,
    _ info_len: Int32,
    _ output_length: Int32,
    _ output: UnsafeMutablePointer<UInt8>
) -> Int32 {
    guard #available(macOS 11.0, iOS 14.0, watchOS 7.0, tvOS 14.0, *) else {
        return -1  // HKDF not available on this platform
    }

    let inputKeyData = Data(bytes: input_key, count: Int(input_key_len))
    let saltData = Data(bytes: salt, count: Int(salt_len))
    let infoData = Data(bytes: info, count: Int(info_len))

    let inputKey = SymmetricKey(data: inputKeyData)

    let derivedKey = HKDF<SHA512>.deriveKey(
        inputKeyMaterial: inputKey,
        salt: saltData,
        info: infoData,
        outputByteCount: Int(output_length)
    )

    derivedKey.withUnsafeBytes { keyBytes in
        output.update(
            from: keyBytes.baseAddress!.assumingMemoryBound(to: UInt8.self),
            count: Int(output_length)
        )
    }

    return 0  // Success
}

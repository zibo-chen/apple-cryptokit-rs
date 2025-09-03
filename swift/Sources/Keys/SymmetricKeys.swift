import CryptoKit
import Foundation

// MARK: - 密钥管理模块

@_cdecl("symmetric_key_generate")
func symmetric_key_generate(
    _ size: Int32,
    _ output: UnsafeMutablePointer<UInt8>
) -> Int32 {
    let keySize = SymmetricKeySize.init(bitCount: Int(size) * 8)
    let symmetricKey = SymmetricKey(size: keySize)

    symmetricKey.withUnsafeBytes { keyBytes in
        output.update(
            from: keyBytes.baseAddress!.assumingMemoryBound(to: UInt8.self),
            count: Int(size)
        )
    }

    return 0  // Success
}

@_cdecl("symmetric_key_from_data")
func symmetric_key_from_data(
    _ data: UnsafePointer<UInt8>,
    _ len: Int32,
    _ output: UnsafeMutablePointer<UInt8>
) -> Int32 {
    let keyData = Data(bytes: data, count: Int(len))
    let symmetricKey = SymmetricKey(data: keyData)

    symmetricKey.withUnsafeBytes { keyBytes in
        output.update(
            from: keyBytes.baseAddress!.assumingMemoryBound(to: UInt8.self),
            count: Int(len)
        )
    }

    return 0  // Success
}

// MARK: - 共享密钥管理

@_cdecl("shared_secret_hkdf_derive_key")
func shared_secret_hkdf_derive_key(
    _ secret: UnsafePointer<UInt8>,
    _ secretLen: Int32,
    _ salt: UnsafePointer<UInt8>,
    _ saltLen: Int32,
    _ info: UnsafePointer<UInt8>,
    _ infoLen: Int32,
    _ outputLen: Int32,
    _ output: UnsafeMutablePointer<UInt8>
) -> Int32 {
    let secretData = Data(bytes: secret, count: Int(secretLen))
    let saltData = saltLen > 0 ? Data(bytes: salt, count: Int(saltLen)) : Data()
    let infoData = infoLen > 0 ? Data(bytes: info, count: Int(infoLen)) : Data()

    // 使用 HKDF-SHA256 直接派生密钥
    if #available(macOS 11.0, iOS 14.0, tvOS 14.0, watchOS 7.0, *) {
        let derivedKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: secretData),
            salt: saltData,
            info: infoData,
            outputByteCount: Int(outputLen)
        )

        // 复制派生的密钥到输出缓冲区
        derivedKey.withUnsafeBytes { keyBytes in
            output.update(
                from: keyBytes.baseAddress!.assumingMemoryBound(to: UInt8.self),
                count: Int(outputLen)
            )
        }

        return 0  // Success
    } else {
        // 对于不支持 HKDF 的旧版本，返回错误
        return -1  // Error: Unsupported on this OS version
    }
}

@_cdecl("shared_secret_x963_derive_key")
func shared_secret_x963_derive_key(
    _ secret: UnsafePointer<UInt8>,
    _ secretLen: Int32,
    _ sharedInfo: UnsafePointer<UInt8>,
    _ sharedInfoLen: Int32,
    _ outputLen: Int32,
    _ output: UnsafeMutablePointer<UInt8>
) -> Int32 {
    let secretData = Data(bytes: secret, count: Int(secretLen))
    let sharedInfoData =
        sharedInfoLen > 0 ? Data(bytes: sharedInfo, count: Int(sharedInfoLen)) : Data()

    // 模拟 X9.63 KDF，实际上 Apple CryptoKit 通过 SharedSecret 提供此功能
    // 这里我们直接使用 HKDF 来模拟，因为 X9.63 KDF 通常在密钥交换时使用
    if #available(macOS 11.0, iOS 14.0, tvOS 14.0, watchOS 7.0, *) {
        let derivedKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: secretData),
            salt: Data(),  // X9.63 通常不使用盐
            info: sharedInfoData,
            outputByteCount: Int(outputLen)
        )

        // 复制派生的密钥到输出缓冲区
        derivedKey.withUnsafeBytes { keyBytes in
            output.update(
                from: keyBytes.baseAddress!.assumingMemoryBound(to: UInt8.self),
                count: Int(outputLen)
            )
        }

        return 0  // Success
    } else {
        // 对于不支持 HKDF 的旧版本，返回错误
        return -1  // Error: Unsupported on this OS version
    }
}

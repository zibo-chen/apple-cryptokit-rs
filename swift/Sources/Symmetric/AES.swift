import CryptoKit
import Foundation

// MARK: - AES-GCM 对称加密模块

@_cdecl("aes_gcm_encrypt")
func aes_gcm_encrypt(
    _ key: UnsafePointer<UInt8>,
    _ key_len: Int32,
    _ nonce: UnsafePointer<UInt8>,
    _ nonce_len: Int32,
    _ plaintext: UnsafePointer<UInt8>,
    _ plaintext_len: Int32,
    _ ciphertext: UnsafeMutablePointer<UInt8>,
    _ ciphertext_len: UnsafeMutablePointer<Int32>
) -> Int32 {
    let keyData = Data(bytes: key, count: Int(key_len))
    let nonceData = Data(bytes: nonce, count: Int(nonce_len))
    let plaintextData = Data(bytes: plaintext, count: Int(plaintext_len))

    guard let symmetricKey = SymmetricKey(data: keyData) as SymmetricKey?,
        let gcmNonce = try? AES.GCM.Nonce(data: nonceData)
    else {
        return -1  // Error: Invalid key or nonce
    }

    do {
        let encrypted = try AES.GCM.seal(plaintextData, using: symmetricKey, nonce: gcmNonce)
        let combinedData = encrypted.ciphertext + encrypted.tag

        combinedData.withUnsafeBytes { bytes in
            ciphertext.update(
                from: bytes.baseAddress!.assumingMemoryBound(to: UInt8.self),
                count: combinedData.count)
        }
        ciphertext_len.pointee = Int32(combinedData.count)
        return 0  // Success
    } catch {
        return -1  // Encryption failed
    }
}

@_cdecl("aes_gcm_decrypt")
func aes_gcm_decrypt(
    _ key: UnsafePointer<UInt8>,
    _ key_len: Int32,
    _ nonce: UnsafePointer<UInt8>,
    _ nonce_len: Int32,
    _ ciphertext: UnsafePointer<UInt8>,
    _ ciphertext_len: Int32,
    _ plaintext: UnsafeMutablePointer<UInt8>,
    _ plaintext_len: UnsafeMutablePointer<Int32>
) -> Int32 {
    let keyData = Data(bytes: key, count: Int(key_len))
    let nonceData = Data(bytes: nonce, count: Int(nonce_len))
    let ciphertextData = Data(bytes: ciphertext, count: Int(ciphertext_len))

    guard let symmetricKey = SymmetricKey(data: keyData) as SymmetricKey?,
        let gcmNonce = try? AES.GCM.Nonce(data: nonceData),
        ciphertextData.count >= 16
    else {
        return -1  // Error: Invalid key, nonce, or ciphertext too short
    }

    // 分离密文和标签（最后16字节是标签）
    let tagSize = 16
    let actualCiphertext = ciphertextData.dropLast(tagSize)
    let tag = ciphertextData.suffix(tagSize)

    do {
        let sealedBox = try AES.GCM.SealedBox(
            nonce: gcmNonce, ciphertext: actualCiphertext, tag: tag)
        let decrypted = try AES.GCM.open(sealedBox, using: symmetricKey)

        decrypted.withUnsafeBytes { bytes in
            plaintext.update(
                from: bytes.baseAddress!.assumingMemoryBound(to: UInt8.self),
                count: decrypted.count
            )
        }
        plaintext_len.pointee = Int32(decrypted.count)
        return 0  // Success
    } catch {
        return -1  // Decryption failed
    }
}

@_cdecl("aes_gcm_encrypt_with_aad")
func aes_gcm_encrypt_with_aad(
    _ key: UnsafePointer<UInt8>,
    _ key_len: Int32,
    _ nonce: UnsafePointer<UInt8>,
    _ nonce_len: Int32,
    _ plaintext: UnsafePointer<UInt8>,
    _ plaintext_len: Int32,
    _ aad: UnsafePointer<UInt8>,
    _ aad_len: Int32,
    _ ciphertext: UnsafeMutablePointer<UInt8>,
    _ ciphertext_len: UnsafeMutablePointer<Int32>
) -> Int32 {
    let keyData = Data(bytes: key, count: Int(key_len))
    let nonceData = Data(bytes: nonce, count: Int(nonce_len))
    let plaintextData = Data(bytes: plaintext, count: Int(plaintext_len))
    let aadData = Data(bytes: aad, count: Int(aad_len))

    guard let symmetricKey = SymmetricKey(data: keyData) as SymmetricKey?,
        let gcmNonce = try? AES.GCM.Nonce(data: nonceData)
    else {
        return -1  // Error: Invalid key or nonce
    }

    do {
        let encrypted = try AES.GCM.seal(
            plaintextData,
            using: symmetricKey,
            nonce: gcmNonce,
            authenticating: aadData
        )
        let combinedData = encrypted.ciphertext + encrypted.tag

        combinedData.withUnsafeBytes { bytes in
            ciphertext.update(
                from: bytes.baseAddress!.assumingMemoryBound(to: UInt8.self),
                count: combinedData.count)
        }
        ciphertext_len.pointee = Int32(combinedData.count)
        return 0  // Success
    } catch {
        return -1  // Encryption failed
    }
}

@_cdecl("aes_gcm_decrypt_with_aad")
func aes_gcm_decrypt_with_aad(
    _ key: UnsafePointer<UInt8>,
    _ key_len: Int32,
    _ nonce: UnsafePointer<UInt8>,
    _ nonce_len: Int32,
    _ ciphertext: UnsafePointer<UInt8>,
    _ ciphertext_len: Int32,
    _ aad: UnsafePointer<UInt8>,
    _ aad_len: Int32,
    _ plaintext: UnsafeMutablePointer<UInt8>,
    _ plaintext_len: UnsafeMutablePointer<Int32>
) -> Int32 {
    let keyData = Data(bytes: key, count: Int(key_len))
    let nonceData = Data(bytes: nonce, count: Int(nonce_len))
    let ciphertextData = Data(bytes: ciphertext, count: Int(ciphertext_len))
    let aadData = Data(bytes: aad, count: Int(aad_len))

    guard let symmetricKey = SymmetricKey(data: keyData) as SymmetricKey?,
        let gcmNonce = try? AES.GCM.Nonce(data: nonceData),
        ciphertextData.count >= 16
    else {
        return -1  // Error: Invalid key, nonce, or ciphertext too short
    }

    // 分离密文和标签
    let tagSize = 16
    let actualCiphertext = ciphertextData.dropLast(tagSize)
    let tag = ciphertextData.suffix(tagSize)

    do {
        let sealedBox = try AES.GCM.SealedBox(
            nonce: gcmNonce,
            ciphertext: actualCiphertext,
            tag: tag
        )
        let decrypted = try AES.GCM.open(sealedBox, using: symmetricKey, authenticating: aadData)

        decrypted.withUnsafeBytes { bytes in
            plaintext.update(
                from: bytes.baseAddress!.assumingMemoryBound(to: UInt8.self),
                count: decrypted.count
            )
        }
        plaintext_len.pointee = Int32(decrypted.count)
        return 0  // Success
    } catch {
        return -1  // Decryption failed
    }
}

@_cdecl("generate_symmetric_key")
func generate_symmetric_key(
    _ size_bits: Int32,
    _ key_data: UnsafeMutablePointer<UInt8>
) -> Int32 {
    let size_bytes = Int(size_bits / 8)
    guard size_bytes == 16 || size_bytes == 24 || size_bytes == 32 else {
        return -1  // Invalid key size
    }
    
    let symmetricKey = SymmetricKey(size: .init(bitCount: Int(size_bits)))
    symmetricKey.withUnsafeBytes { bytes in
        key_data.update(
            from: bytes.baseAddress!.assumingMemoryBound(to: UInt8.self),
            count: size_bytes
        )
    }
    return 0  // Success
}

@_cdecl("generate_aes_gcm_nonce")
func generate_aes_gcm_nonce(
    _ nonce_data: UnsafeMutablePointer<UInt8>
) -> Int32 {
    let nonce = AES.GCM.Nonce()
    nonce.withUnsafeBytes { bytes in
        nonce_data.update(
            from: bytes.baseAddress!.assumingMemoryBound(to: UInt8.self),
            count: 12
        )
    }
    return 0  // Success
}

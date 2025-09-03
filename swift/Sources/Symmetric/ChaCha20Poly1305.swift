import CryptoKit
import Foundation

// MARK: - ChaCha20-Poly1305 对称加密模块

@_cdecl("chacha20poly1305_encrypt")
func chacha20poly1305_encrypt(
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
        let chachaNonce = try? ChaChaPoly.Nonce(data: nonceData)
    else {
        return -1  // Error: Invalid key or nonce
    }

    do {
        let encrypted = try ChaChaPoly.seal(plaintextData, using: symmetricKey, nonce: chachaNonce)
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

@_cdecl("chacha20poly1305_decrypt")
func chacha20poly1305_decrypt(
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
        let chachaNonce = try? ChaChaPoly.Nonce(data: nonceData),
        ciphertextData.count >= 16
    else {
        return -1  // Error: Invalid key, nonce, or ciphertext too short
    }

    // 分离密文和标签（最后16字节是标签）
    let tagSize = 16
    let actualCiphertext = ciphertextData.dropLast(tagSize)
    let tag = ciphertextData.suffix(tagSize)

    do {
        let sealedBox = try ChaChaPoly.SealedBox(
            nonce: chachaNonce, ciphertext: actualCiphertext, tag: tag)
        let decrypted = try ChaChaPoly.open(sealedBox, using: symmetricKey)

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

@_cdecl("chacha20poly1305_encrypt_with_aad")
func chacha20poly1305_encrypt_with_aad(
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
        let chachaNonce = try? ChaChaPoly.Nonce(data: nonceData)
    else {
        return -1  // Error: Invalid key or nonce
    }

    do {
        let encrypted = try ChaChaPoly.seal(
            plaintextData,
            using: symmetricKey,
            nonce: chachaNonce,
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

@_cdecl("chacha20poly1305_decrypt_with_aad")
func chacha20poly1305_decrypt_with_aad(
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
        let chachaNonce = try? ChaChaPoly.Nonce(data: nonceData),
        ciphertextData.count >= 16
    else {
        return -1  // Error: Invalid key, nonce, or ciphertext too short
    }

    // 分离密文和标签
    let tagSize = 16
    let actualCiphertext = ciphertextData.dropLast(tagSize)
    let tag = ciphertextData.suffix(tagSize)

    do {
        let sealedBox = try ChaChaPoly.SealedBox(
            nonce: chachaNonce,
            ciphertext: actualCiphertext,
            tag: tag
        )
        let decrypted = try ChaChaPoly.open(sealedBox, using: symmetricKey, authenticating: aadData)

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

@_cdecl("generate_chacha20poly1305_key")
func generate_chacha20poly1305_key(
    _ key_data: UnsafeMutablePointer<UInt8>
) -> Int32 {
    let symmetricKey = SymmetricKey(size: .bits256) // ChaCha20 uses 32-byte keys
    symmetricKey.withUnsafeBytes { bytes in
        key_data.update(
            from: bytes.baseAddress!.assumingMemoryBound(to: UInt8.self),
            count: 32
        )
    }
    return 0  // Success
}

@_cdecl("generate_chacha20poly1305_nonce")
func generate_chacha20poly1305_nonce(
    _ nonce_data: UnsafeMutablePointer<UInt8>
) -> Int32 {
    let nonce = ChaChaPoly.Nonce()
    nonce.withUnsafeBytes { bytes in
        nonce_data.update(
            from: bytes.baseAddress!.assumingMemoryBound(to: UInt8.self),
            count: 12
        )
    }
    return 0  // Success
}

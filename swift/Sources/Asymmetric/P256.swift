import CryptoKit
import Foundation

// MARK: - P-256 椭圆曲线密码学模块

/*
P-256 (NIST P-256, secp256r1) 实现:

1. P256 数字签名
   - p256_generate_keypair
   - p256_sign
   - p256_verify

2. P256 密钥交换 (ECDH)
   - p256_key_agreement
*/

// P256 数字签名实现
@_cdecl("swift_p256_generate_keypair")
func swift_p256_generate_keypair(
    _ private_key: UnsafeMutablePointer<UInt8>,
    _ public_key: UnsafeMutablePointer<UInt8>
) -> Int32 {
    let privateKey = P256.Signing.PrivateKey()
    let publicKey = privateKey.publicKey

    // 导出私钥（32字节）
    let privateKeyData = privateKey.rawRepresentation
    privateKeyData.withUnsafeBytes { bytes in
        private_key.initialize(from: bytes.bindMemory(to: UInt8.self).baseAddress!, count: 32)
    }

    // 导出公钥（64字节）
    let uncompressedPublicKeyData = publicKey.rawRepresentation

    // 确保使用正确的格式（64字节）
    uncompressedPublicKeyData.withUnsafeBytes { bytes in
        public_key.initialize(from: bytes.bindMemory(to: UInt8.self).baseAddress!, count: 64)
    }

    return 0  // Success
}

@_cdecl("swift_p256_sign")
func swift_p256_sign(
    _ private_key: UnsafePointer<UInt8>,
    _ data: UnsafePointer<UInt8>,
    _ data_len: Int32,
    _ signature: UnsafeMutablePointer<UInt8>
) -> Int32 {
    do {
        // 从原始字节重建私钥
        let privateKeyData = Data(bytes: private_key, count: 32)
        let privateKey = try P256.Signing.PrivateKey(rawRepresentation: privateKeyData)

        // 准备数据进行签名
        let messageData = Data(bytes: data, count: Int(data_len))

        // 执行签名 - P256签名返回DER格式，但我们需要固定64字节格式(r+s)
        let ecdsaSignature = try privateKey.signature(for: messageData)

        // 将ECDSA签名转换为64字节的r+s格式
        let signatureData = ecdsaSignature.rawRepresentation

        // 确保签名长度正确（64字节：r(32) + s(32)）
        guard signatureData.count == 64 else {
            return -1  // Invalid signature size
        }

        signatureData.withUnsafeBytes { bytes in
            signature.initialize(from: bytes.bindMemory(to: UInt8.self).baseAddress!, count: 64)
        }

        return 0  // Success
    } catch {
        return -1  // Error
    }
}

@_cdecl("swift_p256_verify")
func swift_p256_verify(
    _ public_key: UnsafePointer<UInt8>,
    _ signature: UnsafePointer<UInt8>,
    _ data: UnsafePointer<UInt8>,
    _ data_len: Int32
) -> Int32 {
    do {
        // 从原始字节重建公钥（64字节格式）
        let publicKeyData = Data(bytes: public_key, count: 64)
        let publicKey = try P256.Signing.PublicKey(rawRepresentation: publicKeyData)

        // 准备签名数据（64字节r+s格式）
        let signatureData = Data(bytes: signature, count: 64)
        let ecdsaSignature = try P256.Signing.ECDSASignature(rawRepresentation: signatureData)

        // 准备消息数据
        let messageData = Data(bytes: data, count: Int(data_len))

        // 验证签名
        let isValid = publicKey.isValidSignature(ecdsaSignature, for: messageData)

        return isValid ? 1 : 0
    } catch {
        return -1  // Error
    }
}

@_cdecl("swift_p256_key_agreement")
func swift_p256_key_agreement(
    _ private_key: UnsafePointer<UInt8>,
    _ public_key: UnsafePointer<UInt8>,
    _ shared_secret: UnsafeMutablePointer<UInt8>
) -> Int32 {
    do {
        // 从原始字节重建私钥
        let privateKeyData = Data(bytes: private_key, count: 32)
        let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)

        // 从原始字节重建公钥（64字节格式）
        let publicKeyData = Data(bytes: public_key, count: 64)
        let publicKey = try P256.KeyAgreement.PublicKey(rawRepresentation: publicKeyData)

        // 执行密钥交换
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)

        // 导出共享密钥（32字节）
        sharedSecret.withUnsafeBytes { bytes in
            shared_secret.initialize(from: bytes.bindMemory(to: UInt8.self).baseAddress!, count: 32)
        }

        return 0  // Success
    } catch {
        return -1  // Error
    }
}

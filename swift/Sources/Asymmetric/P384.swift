import CryptoKit
import Foundation

// MARK: - P-384 椭圆曲线密码学模块

/*
P-384 (NIST P-384, secp384r1) 实现:

1. P384 数字签名
   - p384_generate_keypair
   - p384_sign
   - p384_verify

2. P384 密钥交换 (ECDH)
   - p384_key_agreement
*/

// P384 数字签名实现
@_cdecl("swift_p384_generate_keypair")
func swift_p384_generate_keypair(
    _ private_key: UnsafeMutablePointer<UInt8>,
    _ public_key: UnsafeMutablePointer<UInt8>
) -> Int32 {
    let privateKey = P384.Signing.PrivateKey()
    let publicKey = privateKey.publicKey

    // 导出私钥（48字节）
    let privateKeyData = privateKey.rawRepresentation
    privateKeyData.withUnsafeBytes { bytes in
        private_key.initialize(from: bytes.bindMemory(to: UInt8.self).baseAddress!, count: 48)
    }

    // 导出公钥（96字节）
    let publicKeyData = publicKey.rawRepresentation
    publicKeyData.withUnsafeBytes { bytes in
        public_key.initialize(from: bytes.bindMemory(to: UInt8.self).baseAddress!, count: 96)
    }

    return 0  // Success
}

@_cdecl("swift_p384_sign")
func swift_p384_sign(
    _ private_key: UnsafePointer<UInt8>,
    _ data: UnsafePointer<UInt8>,
    _ data_len: Int32,
    _ signature: UnsafeMutablePointer<UInt8>
) -> Int32 {
    do {
        // 从原始字节重建私钥
        let privateKeyData = Data(bytes: private_key, count: 48)
        let privateKey = try P384.Signing.PrivateKey(rawRepresentation: privateKeyData)

        // 准备数据进行签名
        let messageData = Data(bytes: data, count: Int(data_len))

        // 执行签名 - P384签名返回固定96字节格式(r+s)
        let ecdsaSignature = try privateKey.signature(for: messageData)

        // 将ECDSA签名转换为96字节的r+s格式
        let signatureData = ecdsaSignature.rawRepresentation

        // 确保签名长度正确（96字节：r(48) + s(48)）
        guard signatureData.count == 96 else {
            return -1  // Invalid signature size
        }

        signatureData.withUnsafeBytes { bytes in
            signature.initialize(from: bytes.bindMemory(to: UInt8.self).baseAddress!, count: 96)
        }

        return 0  // Success
    } catch {
        return -1  // Error
    }
}

@_cdecl("swift_p384_verify")
func swift_p384_verify(
    _ public_key: UnsafePointer<UInt8>,
    _ signature: UnsafePointer<UInt8>,
    _ data: UnsafePointer<UInt8>,
    _ data_len: Int32
) -> Int32 {
    do {
        // 从原始字节重建公钥（96字节格式）
        let publicKeyData = Data(bytes: public_key, count: 96)
        let publicKey = try P384.Signing.PublicKey(rawRepresentation: publicKeyData)

        // 准备签名数据（96字节r+s格式）
        let signatureData = Data(bytes: signature, count: 96)
        let ecdsaSignature = try P384.Signing.ECDSASignature(rawRepresentation: signatureData)

        // 准备消息数据
        let messageData = Data(bytes: data, count: Int(data_len))

        // 验证签名
        let isValid = publicKey.isValidSignature(ecdsaSignature, for: messageData)

        return isValid ? 1 : 0
    } catch {
        return -1  // Error
    }
}

@_cdecl("swift_p384_key_agreement")
func swift_p384_key_agreement(
    _ private_key: UnsafePointer<UInt8>,
    _ public_key: UnsafePointer<UInt8>,
    _ shared_secret: UnsafeMutablePointer<UInt8>
) -> Int32 {
    do {
        // 从原始字节重建私钥
        let privateKeyData = Data(bytes: private_key, count: 48)
        let privateKey = try P384.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)

        // 从原始字节重建公钥（96字节格式）
        let publicKeyData = Data(bytes: public_key, count: 96)
        let publicKey = try P384.KeyAgreement.PublicKey(rawRepresentation: publicKeyData)

        // 执行密钥交换
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)

        // 导出共享密钥（48字节）
        sharedSecret.withUnsafeBytes { bytes in
            shared_secret.initialize(from: bytes.bindMemory(to: UInt8.self).baseAddress!, count: 48)
        }

        return 0  // Success
    } catch {
        return -1  // Error
    }
}

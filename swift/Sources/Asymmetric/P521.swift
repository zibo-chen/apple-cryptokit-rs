import CryptoKit
import Foundation

// MARK: - P-521 椭圆曲线密码学模块

/*
P-521 (NIST P-521, secp521r1) 实现:

1. P521 数字签名
   - p521_generate_keypair
   - p521_sign
   - p521_verify

2. P521 密钥交换 (ECDH)
   - p521_key_agreement
*/

// P521 数字签名实现
@_cdecl("swift_p521_generate_keypair")
func swift_p521_generate_keypair(
    _ private_key: UnsafeMutablePointer<UInt8>,
    _ public_key: UnsafeMutablePointer<UInt8>
) -> Int32 {
    let privateKey = P521.Signing.PrivateKey()
    let publicKey = privateKey.publicKey

    // 导出私钥（66字节）
    let privateKeyData = privateKey.rawRepresentation
    privateKeyData.withUnsafeBytes { bytes in
        private_key.initialize(from: bytes.bindMemory(to: UInt8.self).baseAddress!, count: 66)
    }

    // 导出公钥（132字节）
    let publicKeyData = publicKey.rawRepresentation
    publicKeyData.withUnsafeBytes { bytes in
        public_key.initialize(from: bytes.bindMemory(to: UInt8.self).baseAddress!, count: 132)
    }

    return 0  // Success
}

@_cdecl("swift_p521_sign")
func swift_p521_sign(
    _ private_key: UnsafePointer<UInt8>,
    _ data: UnsafePointer<UInt8>,
    _ data_len: Int32,
    _ signature: UnsafeMutablePointer<UInt8>
) -> Int32 {
    do {
        // 从原始字节重建私钥
        let privateKeyData = Data(bytes: private_key, count: 66)
        let privateKey = try P521.Signing.PrivateKey(rawRepresentation: privateKeyData)

        // 准备数据进行签名
        let messageData = Data(bytes: data, count: Int(data_len))

        // 执行签名 - P521签名返回固定132字节格式(r+s)
        let ecdsaSignature = try privateKey.signature(for: messageData)

        // 将ECDSA签名转换为132字节的r+s格式
        let signatureData = ecdsaSignature.rawRepresentation

        // 确保签名长度正确（132字节：r(66) + s(66)）
        guard signatureData.count == 132 else {
            return -1  // Invalid signature size
        }

        signatureData.withUnsafeBytes { bytes in
            signature.initialize(from: bytes.bindMemory(to: UInt8.self).baseAddress!, count: 132)
        }

        return 0  // Success
    } catch {
        return -1  // Error
    }
}

@_cdecl("swift_p521_verify")
func swift_p521_verify(
    _ public_key: UnsafePointer<UInt8>,
    _ signature: UnsafePointer<UInt8>,
    _ data: UnsafePointer<UInt8>,
    _ data_len: Int32
) -> Int32 {
    do {
        // 从原始字节重建公钥（132字节格式）
        let publicKeyData = Data(bytes: public_key, count: 132)
        let publicKey = try P521.Signing.PublicKey(rawRepresentation: publicKeyData)

        // 准备签名数据（132字节r+s格式）
        let signatureData = Data(bytes: signature, count: 132)
        let ecdsaSignature = try P521.Signing.ECDSASignature(rawRepresentation: signatureData)

        // 准备消息数据
        let messageData = Data(bytes: data, count: Int(data_len))

        // 验证签名
        let isValid = publicKey.isValidSignature(ecdsaSignature, for: messageData)

        return isValid ? 1 : 0
    } catch {
        return -1  // Error
    }
}

@_cdecl("swift_p521_key_agreement")
func swift_p521_key_agreement(
    _ private_key: UnsafePointer<UInt8>,
    _ public_key: UnsafePointer<UInt8>,
    _ shared_secret: UnsafeMutablePointer<UInt8>
) -> Int32 {
    do {
        // 从原始字节重建私钥
        let privateKeyData = Data(bytes: private_key, count: 66)
        let privateKey = try P521.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)

        // 从原始字节重建公钥（132字节格式）
        let publicKeyData = Data(bytes: public_key, count: 132)
        let publicKey = try P521.KeyAgreement.PublicKey(rawRepresentation: publicKeyData)

        // 执行密钥交换
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)

        // 导出共享密钥（66字节）
        sharedSecret.withUnsafeBytes { bytes in
            shared_secret.initialize(from: bytes.bindMemory(to: UInt8.self).baseAddress!, count: 66)
        }

        return 0  // Success
    } catch {
        return -1  // Error
    }
}

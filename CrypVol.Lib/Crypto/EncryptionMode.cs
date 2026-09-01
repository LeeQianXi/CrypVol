namespace CrypVol.Lib.Crypto;

/// 密钥保护模式枚举
public enum EncryptionMode
{
    /// 无加密：数据为明文或仅经 GZip 压缩，不生成 .cvk 文件
    None,

    /// 裸密钥文件：CEK 明文存储在 .cvk 中，解密仅需文件本身
    PlainKey,

    /// 密码包裹：CEK 经 Argon2id + AES-GCM 加密存储在 .cvk，解密需密码
    Password,

    /// 公钥包裹：CEK 经 RSA 公钥加密存储在 .cvk，解密需对应私钥
    Asymmetric,

    /// ECC 公钥包裹：CEK 经 P-256 ECDH 派生密钥封装，需对应 EC 私钥解密
    Ecc
}

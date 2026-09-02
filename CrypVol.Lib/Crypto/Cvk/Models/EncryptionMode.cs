namespace CrypVol.Lib.Crypto;

/// <summary>CVK 中 CEK 的保护模式；不表示数据加密算法。</summary>
public enum EncryptionMode
{
    /// 无加密：数据为明文或仅经 GZip 压缩，不生成 .cvk 文件
    None,

    /// 裸密钥文件：CEK 明文存储在 .cvk 中，解密仅需文件本身
    PlainKey,

    /// 密码包裹：CEK 经 Argon2id + AES-GCM 加密存储在 .cvk，解密需密码
    Password,

    /// 公钥包裹：CEK 经公钥加密存储在 .cvk，解密需对应私钥
    Asymmetric,
}

/// <summary>CVK 使用的密码学算法；与 CEK 保护模式正交。</summary>
public enum EncryptionAlgorithm
{
    /// <summary>AES-256-GCM，对称数据加密。</summary>
    AesGcm,

    /// <summary>P-256 ECDH，用于公钥密钥体封装。</summary>
    Ecc
}

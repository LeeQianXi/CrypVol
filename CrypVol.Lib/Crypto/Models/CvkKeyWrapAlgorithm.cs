using System.Text.Json.Serialization;

namespace CrypVol.Lib.Crypto.Models;

/// <summary>保护 CEK 或包装密钥时采用的密钥派生/密钥包装算法。</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum CvkKeyWrapAlgorithm : byte
{
    /// <summary>不进行包装，适用于 Plain 模式。</summary>
    None = 0,

    /// <summary>PBKDF2-HMAC-SHA256 密码派生。</summary>
    PasswordPbkdf2Sha256 = 1,

    /// <summary>Argon2id 密码派生。</summary>
    PasswordArgon2Id = 2,

    /// <summary>RSA-OAEP-SHA256。</summary>
    RsaOaepSha256 = 10,

    /// <summary>RSA-OAEP-SHA384。</summary>
    RsaOaepSha384 = 11,

    /// <summary>RSA-OAEP-SHA512。</summary>
    RsaOaepSha512 = 12,

    /// <summary>ECDH P-256。</summary>
    EcdhP256 = 20,

    /// <summary>ECDH P-384。</summary>
    EcdhP384 = 21,

    /// <summary>ECDH P-521。</summary>
    EcdhP521 = 22
}
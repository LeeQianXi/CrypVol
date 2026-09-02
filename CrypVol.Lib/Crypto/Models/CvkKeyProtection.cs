using System.Text.Json.Serialization;

namespace CrypVol.Lib.Crypto.Models;

/// <summary>CVK 中 CEK 的保护方式。</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum CvkKeyProtection : byte
{
    /// <summary>CEK 明文保存，仅适用于明确选择的无保护场景。</summary>
    Plain = 0,

    /// <summary>使用密码派生密钥保护 CEK。</summary>
    Password = 1,

    /// <summary>使用一个或多个公钥保护 CEK。</summary>
    PublicKey = 2
}
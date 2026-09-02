using System.Security.Cryptography;

namespace CrypVol.Lib.Crypto.Keys;

/// <summary>非对称密钥文件格式或密码错误。</summary>
public sealed class AsymmetricKeyFileFormatException : CryptographicException
{
    /// <summary>初始化异常。</summary>
    public AsymmetricKeyFileFormatException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }
}
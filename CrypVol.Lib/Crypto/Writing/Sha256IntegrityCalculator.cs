using System.Security.Cryptography;
using System.Text;

namespace CrypVol.Lib.Crypto.Writing;

/// <summary>按 JWT 的签名输入规则计算 CVK 第三段。</summary>
/// <remarks>
///     第三段计算输入为 <c>base64url(HeaderJson) + "." + base64url(KeyBody)</c>，
///     再取 SHA-256 原始摘要。容器仍以二进制保存摘要，避免引入文本编码歧义；
///     密钥体自身的 AEAD 认证负责解封后的机密性与真实性校验。
/// </remarks>
public sealed class Sha256IntegrityCalculator : ICvkIntegrityCalculator
{
    /// <inheritdoc />
    public ReadOnlyMemory<byte> Compute(ReadOnlyMemory<byte> headerJson, ReadOnlyMemory<byte> keyBody)
    {
        var header = Base64Url.Encode(headerJson.Span);
        var body = Base64Url.Encode(keyBody.Span);
        var signingInput = Encoding.ASCII.GetBytes($"{header}.{body}");
        return SHA256.HashData(signingInput);
    }
}

internal static class Base64Url
{
    public static string Encode(ReadOnlySpan<byte> value)
    {
        return Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
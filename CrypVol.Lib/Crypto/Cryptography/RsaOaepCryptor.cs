using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using CrypVol.Lib.Crypto.Keys;
using CrypVol.Lib.Crypto.Models;

namespace CrypVol.Lib.Crypto.Cryptography;

/// <summary>RSA-OAEP 系列 CVK 处理器的公共实现。</summary>
public abstract class RsaOaepCryptorBase : CvkAlgorithmCryptorBase
{
    private const int KeySize = 32;
    private const int NonceSize = 12;
    private const int TagSize = 16;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly IReadOnlyDictionary<string, AsymmetricPrivateKeyMaterial> _privateKeys;

    /// <summary>初始化 RSA 处理器。</summary>
    protected RsaOaepCryptorBase(CvkKeyWrapAlgorithm algorithm,
        IReadOnlyDictionary<string, AsymmetricPrivateKeyMaterial>? privateKeys = null)
        : base(CvkKeyProtection.PublicKey, algorithm)
    {
        _privateKeys = privateKeys ?? new Dictionary<string, AsymmetricPrivateKeyMaterial>();
    }

    /// <summary>当前 OAEP 摘要算法。</summary>
    protected abstract HashAlgorithmName HashAlgorithm { get; }

    private RSAEncryptionPadding Padding => WrapAlgorithm switch
    {
        CvkKeyWrapAlgorithm.RsaOaepSha256 => RSAEncryptionPadding.OaepSHA256,
        CvkKeyWrapAlgorithm.RsaOaepSha384 => RSAEncryptionPadding.OaepSHA384,
        CvkKeyWrapAlgorithm.RsaOaepSha512 => RSAEncryptionPadding.OaepSHA512,
        _ => throw new InvalidOperationException()
    };

    protected override ValueTask<ReadOnlyMemory<byte>> ProtectCoreAsync(CvkHeader header, CvkPayload payload,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (payload.RecipientKeys.Count == 0) throw new InvalidDataException("RSA 模式至少需要一个接收者。");
        var dataKey = RandomNumberGenerator.GetBytes(KeySize);
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var plain = CvkPayloadCodec.Encode(payload);
        var cipher = new byte[plain.Length];
        var tag = new byte[TagSize];
        using (var aes = new AesGcm(dataKey, TagSize))
        {
            aes.Encrypt(nonce, plain, cipher, tag, CvkPayloadCodec.EncodeHeader(header));
        }

        var wrapped = new List<RsaWrappedRecipient>();
        foreach (var recipient in payload.RecipientKeys)
        {
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(recipient.PublicKeyBytes.Span, out _);
            wrapped.Add(new RsaWrappedRecipient(recipient.KeyId, Convert.ToBase64String(rsa.Encrypt(dataKey, Padding)),
                recipient));
        }

        CryptographicOperations.ZeroMemory(dataKey);
        return ValueTask.FromResult<ReadOnlyMemory<byte>>(JsonSerializer.SerializeToUtf8Bytes(
            new RsaKeyBody(Convert.ToBase64String(nonce), Convert.ToBase64String(tag), Convert.ToBase64String(cipher),
                wrapped), JsonOptions));
    }

    protected override ValueTask<CvkPayload> UnprotectCoreAsync(CvkHeader header, ReadOnlyMemory<byte> keyBody,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RsaKeyBody body;
        try
        {
            using var document = JsonDocument.Parse(keyBody.ToArray());
            ValidateBody(document.RootElement);
            body = JsonSerializer.Deserialize<RsaKeyBody>(document.RootElement.GetRawText(), JsonOptions) ??
                   throw new InvalidDataException("RSA 密钥体为空。");
        }
        catch (JsonException ex) { throw new InvalidDataException("RSA 密钥体格式无效。", ex); }

        byte[]? dataKey = null;
        foreach (var recipient in body.Recipients)
        {
            if (recipient is null) continue;
            if (!_privateKeys.TryGetValue(recipient.KeyId, out var material) || material.Key is not RSA rsa) continue;
            try
            {
                dataKey = rsa.Decrypt(Convert.FromBase64String(recipient.WrappedKey), Padding);
                break;
            }
            catch (Exception ex) when (ex is CryptographicException or FormatException or ArgumentException) { }
        }

        if (dataKey is null) throw new CryptographicException("没有可用的 RSA 私钥接收者。");
        try
        {
            var nonce = Convert.FromBase64String(body.Nonce);
            var tag = Convert.FromBase64String(body.Tag);
            var cipher = Convert.FromBase64String(body.Ciphertext);
            var plain = new byte[cipher.Length];
            using var aes = new AesGcm(dataKey, TagSize);
            aes.Decrypt(nonce, cipher, tag, plain, CvkPayloadCodec.EncodeHeader(header));
            return ValueTask.FromResult(CvkPayloadCodec.Decode(plain));
        }
        finally { CryptographicOperations.ZeroMemory(dataKey); }
    }

    private static void ValidateBody(JsonElement root)
    {
        ValidateObject(root, ["nonce", "tag", "ciphertext", "recipients"]);
        foreach (var name in new[] { "nonce", "tag", "ciphertext" })
            if (root.GetProperty(name).ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(root.GetProperty(name).GetString()))
                throw new InvalidDataException($"RSA 密钥体字段无效：{name}。");
        var recipients = root.GetProperty("recipients");
        if (recipients.ValueKind != JsonValueKind.Array || recipients.GetArrayLength() == 0)
            throw new InvalidDataException("RSA 密钥体缺少接收者。");
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in recipients.EnumerateArray())
        {
            if (item.ValueKind == JsonValueKind.Null) continue;
            ValidateObject(item, ["keyId", "wrappedKey", "recipient"]);
            var id = RequireString(item, "keyId");
            if (string.IsNullOrWhiteSpace(id) || !ids.Add(id)) throw new InvalidDataException("RSA 接收者 KeyId 为空或重复。");
            if (string.IsNullOrWhiteSpace(RequireString(item, "wrappedKey"))) throw new InvalidDataException("RSA wrappedKey 为空。");
            var embedded = item.GetProperty("recipient");
            ValidateObject(embedded, ["keyId", "algorithm", "publicKey", "comment"]);
            if (RequireString(embedded, "keyId") != id || RequireString(embedded, "algorithm") != "RSA" || string.IsNullOrWhiteSpace(RequireString(embedded, "publicKey")))
                throw new InvalidDataException("RSA 嵌入接收者元数据无效。");
        }
    }

    private static string RequireString(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String)
            throw new InvalidDataException($"RSA 密钥体字段缺失或类型无效：{name}。");
        return value.GetString()!;
    }

    private static void ValidateObject(JsonElement element, string[] allowed)
    {
        if (element.ValueKind != JsonValueKind.Object) throw new InvalidDataException("RSA 密钥体对象无效。");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject())
        {
            if (!seen.Add(property.Name) || !allowed.Contains(property.Name, StringComparer.Ordinal))
                throw new InvalidDataException($"RSA 密钥体字段无效：{property.Name}。");
        }
    }

    private sealed record RsaKeyBody(string Nonce,
        string Tag,
        string Ciphertext,
        IReadOnlyList<RsaWrappedRecipient> Recipients);

    private sealed record RsaWrappedRecipient(string KeyId, string WrappedKey, AsymmetricRecipientKey Recipient);
}

/// <summary>RSA-OAEP-SHA256 处理器。</summary>
public sealed class RsaOaepSha256Cryptor(IReadOnlyDictionary<string, AsymmetricPrivateKeyMaterial>? privateKeys = null)
    : RsaOaepCryptorBase(CvkKeyWrapAlgorithm.RsaOaepSha256, privateKeys)
{
    protected override HashAlgorithmName HashAlgorithm => HashAlgorithmName.SHA256;
}

/// <summary>RSA-OAEP-SHA384 处理器。</summary>
public sealed class RsaOaepSha384Cryptor(IReadOnlyDictionary<string, AsymmetricPrivateKeyMaterial>? privateKeys = null)
    : RsaOaepCryptorBase(CvkKeyWrapAlgorithm.RsaOaepSha384, privateKeys)
{
    protected override HashAlgorithmName HashAlgorithm => HashAlgorithmName.SHA384;
}

/// <summary>RSA-OAEP-SHA512 处理器。</summary>
public sealed class RsaOaepSha512Cryptor(IReadOnlyDictionary<string, AsymmetricPrivateKeyMaterial>? privateKeys = null)
    : RsaOaepCryptorBase(CvkKeyWrapAlgorithm.RsaOaepSha512, privateKeys)
{
    protected override HashAlgorithmName HashAlgorithm => HashAlgorithmName.SHA512;
}

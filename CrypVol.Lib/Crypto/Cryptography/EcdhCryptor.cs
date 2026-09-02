using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using CrypVol.Lib.Crypto.Keys;
using CrypVol.Lib.Crypto.Models;

namespace CrypVol.Lib.Crypto.Cryptography;

/// <summary>ECDH + HKDF-SHA256 的 CVK 混合封装处理器。</summary>
public abstract class EcdhCryptorBase : CvkAlgorithmCryptorBase
{
    private const int DataKeySize = 32;
    private const int NonceSize = 12;
    private const int TagSize = 16;

    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly IReadOnlyDictionary<string, AsymmetricPrivateKeyMaterial> _privateKeys;

    protected EcdhCryptorBase(CvkKeyWrapAlgorithm algorithm,
        IReadOnlyDictionary<string, AsymmetricPrivateKeyMaterial>? privateKeys = null)
        : base(CvkKeyProtection.PublicKey, algorithm)
    {
        _privateKeys = privateKeys ?? new Dictionary<string, AsymmetricPrivateKeyMaterial>();
    }

    protected abstract ECCurve Curve { get; }

    protected override ValueTask<ReadOnlyMemory<byte>> ProtectCoreAsync(CvkHeader header, CvkPayload payload,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (payload.RecipientKeys.Count == 0) throw new InvalidDataException("ECDH 模式至少需要一个接收者。");
        var dataKey = RandomNumberGenerator.GetBytes(DataKeySize);
        var dataNonce = RandomNumberGenerator.GetBytes(NonceSize);
        var dataTag = new byte[TagSize];
        var plain = CvkPayloadCodec.Encode(payload);
        var cipher = new byte[plain.Length];
        using (var aes = new AesGcm(dataKey, TagSize))
        {
            aes.Encrypt(dataNonce, plain, cipher, dataTag, CvkPayloadCodec.EncodeHeader(header));
        }

        var recipients = new List<EcdhWrappedRecipient>();
        foreach (var recipient in payload.RecipientKeys)
        {
            using var ephemeral = ECDiffieHellman.Create(Curve);
            using var target = ECDiffieHellman.Create();
            target.ImportSubjectPublicKeyInfo(recipient.PublicKeyBytes.Span, out _);
            var shared = ephemeral.DeriveKeyMaterial(target.PublicKey);
            var wrapKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, shared, DataKeySize, null, "CrypVol CVK ECDH"u8.ToArray());
            var nonce = RandomNumberGenerator.GetBytes(NonceSize);
            var tag = new byte[TagSize];
            var wrapped = new byte[DataKeySize];
            using (var aes = new AesGcm(wrapKey, TagSize))
            {
                aes.Encrypt(nonce, dataKey, wrapped, tag);
            }

            recipients.Add(new EcdhWrappedRecipient(recipient.KeyId,
                Convert.ToBase64String(ephemeral.ExportSubjectPublicKeyInfo()), Convert.ToBase64String(nonce),
                Convert.ToBase64String(tag), Convert.ToBase64String(wrapped), recipient));
            CryptographicOperations.ZeroMemory(shared);
            CryptographicOperations.ZeroMemory(wrapKey);
        }

        CryptographicOperations.ZeroMemory(dataKey);
        return ValueTask.FromResult<ReadOnlyMemory<byte>>(JsonSerializer.SerializeToUtf8Bytes(
            new EcdhKeyBody(Convert.ToBase64String(dataNonce), Convert.ToBase64String(dataTag),
                Convert.ToBase64String(cipher), recipients), Options));
    }

    protected override ValueTask<CvkPayload> UnprotectCoreAsync(CvkHeader header, ReadOnlyMemory<byte> keyBody,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        EcdhKeyBody body;
        try
        {
            body = JsonSerializer.Deserialize<EcdhKeyBody>(keyBody.Span, Options) ??
                   throw new InvalidDataException("ECDH 密钥体为空。");
        }
        catch (JsonException ex) { throw new InvalidDataException("ECDH 密钥体格式无效。", ex); }

        byte[]? dataKey = null;
        foreach (var recipient in body.Recipients)
        {
            if (!_privateKeys.TryGetValue(recipient.KeyId, out var material) ||
                material.Key is not ECDiffieHellman privateKey) continue;
            try
            {
                using var ephemeral = ECDiffieHellman.Create();
                ephemeral.ImportSubjectPublicKeyInfo(Convert.FromBase64String(recipient.EphemeralPublicKey), out _);
                var shared = privateKey.DeriveKeyMaterial(ephemeral.PublicKey);
                var wrapKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, shared, DataKeySize, null,
                    "CrypVol CVK ECDH"u8.ToArray());
                dataKey = new byte[DataKeySize];
                using var aes = new AesGcm(wrapKey, TagSize);
                aes.Decrypt(Convert.FromBase64String(recipient.Nonce), Convert.FromBase64String(recipient.WrappedKey),
                    Convert.FromBase64String(recipient.Tag), dataKey);
                CryptographicOperations.ZeroMemory(shared);
                CryptographicOperations.ZeroMemory(wrapKey);
                break;
            }
            catch (CryptographicException) { dataKey = null; }
        }

        if (dataKey is null) throw new CryptographicException("没有可用的 ECDH 私钥接收者。");
        try
        {
            var cipher = Convert.FromBase64String(body.Ciphertext);
            var plain = new byte[cipher.Length];
            using var aes = new AesGcm(dataKey, TagSize);
            aes.Decrypt(Convert.FromBase64String(body.DataNonce), cipher, Convert.FromBase64String(body.DataTag), plain,
                CvkPayloadCodec.EncodeHeader(header));
            return ValueTask.FromResult(CvkPayloadCodec.Decode(plain));
        }
        finally { CryptographicOperations.ZeroMemory(dataKey); }
    }

    private sealed record EcdhKeyBody(string DataNonce,
        string DataTag,
        string Ciphertext,
        IReadOnlyList<EcdhWrappedRecipient> Recipients);

    private sealed record EcdhWrappedRecipient(string KeyId,
        string EphemeralPublicKey,
        string Nonce,
        string Tag,
        string WrappedKey,
        AsymmetricRecipientKey Recipient);
}

/// <summary>ECDH-P256 处理器。</summary>
public sealed class EcdhP256Cryptor(IReadOnlyDictionary<string, AsymmetricPrivateKeyMaterial>? privateKeys = null)
    : EcdhCryptorBase(CvkKeyWrapAlgorithm.EcdhP256, privateKeys)
{
    protected override ECCurve Curve => ECCurve.NamedCurves.nistP256;
}

/// <summary>ECDH-P384 处理器。</summary>
public sealed class EcdhP384Cryptor(IReadOnlyDictionary<string, AsymmetricPrivateKeyMaterial>? privateKeys = null)
    : EcdhCryptorBase(CvkKeyWrapAlgorithm.EcdhP384, privateKeys)
{
    protected override ECCurve Curve => ECCurve.NamedCurves.nistP384;
}

/// <summary>ECDH-P521 处理器。</summary>
public sealed class EcdhP521Cryptor(IReadOnlyDictionary<string, AsymmetricPrivateKeyMaterial>? privateKeys = null)
    : EcdhCryptorBase(CvkKeyWrapAlgorithm.EcdhP521, privateKeys)
{
    protected override ECCurve Curve => ECCurve.NamedCurves.nistP521;
}
using System.Security.Cryptography;
using System.Text.Json;
using CrypVol.Lib.Crypto.Cryptography;
using CrypVol.Lib.Crypto.Keys;
using CrypVol.Lib.Crypto.Models;
using CrypVol.Lib.Crypto.Reading;
using CrypVol.Lib.Crypto.Writing;
using Microsoft.Extensions.Logging;

namespace CrypVol.Lib.Crypto;

/// <summary>CVK 文档的显式创建、加载、写入和凭据转换操作。</summary>
public static class CvkOperations
{
    /// <summary>创建 CVK 文档，可选使用调用方指定的 32 字节 CEK。</summary>
    public static CvkDocument CreateNew(CvkKeyProtection protection, CvkKeyWrapAlgorithm algorithm,
        ReadOnlyMemory<byte>? cek = null)
    {
        CvkEncapsulationRoute.Resolve(protection, algorithm);
        if (cek is { } supplied && supplied.Length != 32)
            throw new ArgumentException("CEK 必须恰好为 32 字节。", nameof(cek));
        return new CvkDocument
        {
            Cek = cek?.ToArray() ?? RandomNumberGenerator.GetBytes(32),
            KeyProtection = protection,
            KeyWrapAlgorithm = algorithm,
            CreatedAt = DateTimeOffset.UtcNow,
            Generator = "CrypVol"
        };
    }

    /// <summary>将公钥文件材料加入文档。</summary>
    public static void AddPublicKey(CvkDocument document, FileInfo file, string? keyId = null)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(file);
        var route = CvkEncapsulationRoute.Resolve(document.KeyProtection, document.KeyWrapAlgorithm);
        if (!AsymmetricKeyLoaderManager.Instance.LoadPublicKey(file, out var material, keyId))
            throw new AsymmetricKeyFileFormatException($"无法解析公钥文件：{file.FullName}");
        using (material)
        {
            if (!route.RequiresRecipients)
                throw new InvalidOperationException("只有 PublicKey 保护模式才能添加公钥接收者。");
            ValidateRecipientAlgorithm(route.Algorithm, material);
            if (document.RecipientKeys.Any(x =>
                    string.Equals(x.KeyId, material.KeyId, StringComparison.Ordinal)))
                throw new InvalidOperationException($"接收者 KeyId 已存在：{material.KeyId}。");
            document.RecipientKeys.Add(
                new AsymmetricRecipientKey(material.KeyId, material.Algorithm, material.PublicKeyBytes));
        }
    }

    /// <summary>校验公钥材料与文档声明的封装算法匹配。</summary>
    private static void ValidateRecipientAlgorithm(CvkKeyWrapAlgorithm algorithm, AsymmetricPublicKeyMaterial material)
    {
        if (algorithm is CvkKeyWrapAlgorithm.RsaOaepSha256
            or CvkKeyWrapAlgorithm.RsaOaepSha384
            or CvkKeyWrapAlgorithm.RsaOaepSha512)
        {
            if (!string.Equals(material.Algorithm, "RSA", StringComparison.Ordinal))
                throw new InvalidOperationException("RSA 封装算法必须使用 RSA 公钥。");
            return;
        }

        if (algorithm is CvkKeyWrapAlgorithm.EcdhP256 or CvkKeyWrapAlgorithm.EcdhP384 or CvkKeyWrapAlgorithm.EcdhP521)
        {
            if (!string.Equals(material.Algorithm, "ECDH", StringComparison.Ordinal) ||
                material.Key is not ECDiffieHellman ecdh)
                throw new InvalidOperationException("ECDH 封装算法必须使用 ECDH 公钥。");
            var expectedBits = algorithm switch
            {
                CvkKeyWrapAlgorithm.EcdhP256 => 256,
                CvkKeyWrapAlgorithm.EcdhP384 => 384,
                _ => 521
            };
            if (ecdh.KeySize != expectedBits)
                throw new InvalidOperationException($"ECDH 公钥曲线与封装算法不匹配，需要 P-{expectedBits}。");
            return;
        }

        throw new InvalidOperationException("当前文档不是非对称公钥封装路由。");
    }

    /// <summary>从路径加入公钥。</summary>
    public static void AddPublicKey(CvkDocument document, string file)
    {
        AddPublicKey(document, new FileInfo(file));
    }

    /// <summary>将文档转换为引擎运行凭据。</summary>
    public static CvkCredentials ToCredentials(CvkDocument document)
    {
        return new CvkCredentials(document.KeyProtection, document.Cek, document.KeyWrapAlgorithm);
    }

    /// <summary>写入 CVK 文件。</summary>
    public static async Task WriteAsync(CvkDocument document, FileInfo file, string? password = null,
        CancellationToken token = default)
    {
        var registry = string.IsNullOrEmpty(password)
            ? CvkPayloadCryptorRegistry.CreateDefault()
            : CvkPayloadCryptorRegistry.CreateDefault(password);
        var cryptor = registry.Resolve(new CvkHeader(document.Version, document.KeyProtection, document.KeyWrapAlgorithm,
            document.Label, document.Description, document.Comment, document.CreatedAt, document.Generator));
        await new CvkWriter(new CvkPayloadProtectorAdapter(cryptor)).WriteAsync(document, file, token);
    }

    /// <summary>使用默认凭据写入 CVK。</summary>
    public static Task WriteAsync(CvkDocument document, FileInfo file, CancellationToken token)
    {
        return WriteAsync(document, file, null, token);
    }

    /// <summary>校验、解封并加载 CVK 文档。</summary>
    public static async Task<CvkDocument> LoadAsync(FileInfo file, string? password = null, CancellationToken token = default)
    {
        var registry = string.IsNullOrEmpty(password)
            ? CvkPayloadCryptorRegistry.CreateDefault()
            : CvkPayloadCryptorRegistry.CreateDefault(password);
        var parsed = await new CvkReader(new Sha256IntegrityCalculator()).ReadAsync(file, token);
        var cryptor = registry.Resolve(parsed.Header);
        return await new CvkReader(new Sha256IntegrityCalculator(), new CvkPayloadUnprotectorAdapter(cryptor))
            .ReadDocumentAsync(file, token);
    }

    /// <summary>兼容 CLI 的扩展加载参数；私钥参数由对应非对称处理器消费。</summary>
    public static Task<CvkDocument> LoadAsync(FileInfo file, string? password, FileInfo? privateKeyFile,
        string? privateKeyPassword, CancellationToken token, ILogger? logger = null)
    {
        return LoadCoreAsync(file, password, privateKeyFile, privateKeyPassword, token, logger);
    }

    /// <summary>按文件头选择解封器，并为公钥保护模式加载指定私钥。</summary>
    private static async Task<CvkDocument> LoadCoreAsync(FileInfo file, string? password,
        FileInfo? privateKeyFile, string? privateKeyPassword, CancellationToken token, ILogger? logger)
    {
        ArgumentNullException.ThrowIfNull(file);
        var parsed = await new CvkReader(new Sha256IntegrityCalculator()).ReadAsync(file, token);
        var registry = string.IsNullOrEmpty(password)
            ? CvkPayloadCryptorRegistry.CreateDefault()
            : CvkPayloadCryptorRegistry.CreateDefault(password);

        if (parsed.Header.KeyProtection == CvkKeyProtection.PublicKey && privateKeyFile is null)
        {
            Exception? last = null;
            foreach (var candidate in AsymmetricKeyLoaderManager.Instance.DiscoverPrivateKeyFiles())
            {
                logger?.LogInformation("已自动发现并尝试使用 SSH 私钥 {PrivateKeyFile}", candidate.FullName);
                try
                {
                    return await LoadWithPrivateKeyAsync(file, parsed, registry, candidate,
                        privateKeyPassword, token, logger);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    last = ex;
                    logger?.LogDebug(ex, "SSH 私钥 {PrivateKeyFile} 无法解封当前 CVK", candidate.FullName);
                }
            }

            throw new InvalidOperationException(
                last is null ? "未找到能够解封当前 CVK 的成对 SSH 私钥。" :
                    $"未找到能够解封当前 CVK 的成对 SSH 私钥。最近一次尝试失败：{last.Message}", last);
        }

        return await LoadWithPrivateKeyAsync(file, parsed, registry, privateKeyFile,
            privateKeyPassword, token, logger);
    }

    private static async Task<CvkDocument> LoadWithPrivateKeyAsync(FileInfo file, CvkParsedFile parsed,
        CvkPayloadCryptorRegistry registry, FileInfo? privateKeyFile, string? privateKeyPassword,
        CancellationToken token, ILogger? logger)
    {
        AsymmetricPrivateKeyMaterial? privateMaterial = null;
        try
        {
            if (parsed.Header.KeyProtection == CvkKeyProtection.PublicKey)
            {
                if (privateKeyFile is null)
                    throw new ArgumentNullException(nameof(privateKeyFile), "公钥保护模式必须提供私钥文件。");
                if (!AsymmetricKeyLoaderManager.Instance.LoadPrivateKey(privateKeyFile, out privateMaterial,
                        privateKeyPassword))
                    throw new AsymmetricKeyFileFormatException($"无法解析私钥文件：{privateKeyFile.FullName}");
                var keys = new Dictionary<string, AsymmetricPrivateKeyMaterial>(StringComparer.Ordinal)
                {
                    [privateMaterial.KeyId] = privateMaterial
                };
                foreach (var recipientId in ExtractRecipientIds(parsed.KeyBody))
                    keys.TryAdd(recipientId, privateMaterial);
                registry.Register(parsed.Header.KeyProtection, parsed.Header.KeyWrapAlgorithm,
                    CreateAsymmetricCryptor(parsed.Header.KeyWrapAlgorithm, keys));
            }
            var cryptor = registry.Resolve(parsed.Header);
            logger?.LogDebug("已选择 CVK 解封算法：{Protection}/{WrapAlgorithm}",
                parsed.Header.KeyProtection, parsed.Header.KeyWrapAlgorithm);
            return await new CvkReader(new Sha256IntegrityCalculator(),
                new CvkPayloadUnprotectorAdapter(cryptor)).ReadDocumentAsync(file, token);
        }
        finally { privateMaterial?.Dispose(); }
    }

    /// <summary>创建带私钥候选集的非对称密钥体处理器。</summary>
    private static ICvkPayloadCryptor CreateAsymmetricCryptor(CvkKeyWrapAlgorithm algorithm,
        IReadOnlyDictionary<string, AsymmetricPrivateKeyMaterial> privateKeys)
    {
        return algorithm switch
        {
            CvkKeyWrapAlgorithm.RsaOaepSha256 => new RsaOaepSha256Cryptor(privateKeys),
            CvkKeyWrapAlgorithm.RsaOaepSha384 => new RsaOaepSha384Cryptor(privateKeys),
            CvkKeyWrapAlgorithm.RsaOaepSha512 => new RsaOaepSha512Cryptor(privateKeys),
            CvkKeyWrapAlgorithm.EcdhP256 => new EcdhP256Cryptor(privateKeys),
            CvkKeyWrapAlgorithm.EcdhP384 => new EcdhP384Cryptor(privateKeys),
            CvkKeyWrapAlgorithm.EcdhP521 => new EcdhP521Cryptor(privateKeys),
            _ => throw new NotSupportedException($"不支持的非对称封装算法：{algorithm}。")
        };
    }

    private static IEnumerable<string> ExtractRecipientIds(ReadOnlyMemory<byte> keyBody)
    {
        using var json = JsonDocument.Parse(keyBody.ToArray());
        if (!json.RootElement.TryGetProperty("recipients", out var recipients) || recipients.ValueKind != JsonValueKind.Array)
            yield break;
        foreach (var item in recipients.EnumerateArray())
            if (item.ValueKind == JsonValueKind.Object && item.TryGetProperty("keyId", out var id) &&
                id.ValueKind == JsonValueKind.String)
                yield return id.GetString()!;
    }
}

using System.Security.Cryptography;
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
    /// <summary>创建包含随机 CEK 的新文档。</summary>
    public static CvkDocument CreateNew(CvkKeyProtection protection, CvkKeyWrapAlgorithm algorithm)
    {
        if (!IsValidRoute(protection, algorithm))
            throw new ArgumentException($"不支持的 CVK 保护路由：{protection}/{algorithm}。", nameof(algorithm));
        return new CvkDocument
        {
            Cek = RandomNumberGenerator.GetBytes(32),
            KeyProtection = protection,
            KeyWrapAlgorithm = algorithm,
            CreatedAt = DateTimeOffset.UtcNow,
            Generator = "CrypVol"
        };
    }

    /// <summary>判断保护模式与封装算法是否为已定义且匹配的路由。</summary>
    private static bool IsValidRoute(CvkKeyProtection protection, CvkKeyWrapAlgorithm algorithm) =>
        protection switch
        {
            CvkKeyProtection.Plain => algorithm == CvkKeyWrapAlgorithm.None,
            CvkKeyProtection.Password => algorithm is CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256
                or CvkKeyWrapAlgorithm.PasswordArgon2Id,
            CvkKeyProtection.PublicKey => algorithm is CvkKeyWrapAlgorithm.RsaOaepSha256
                or CvkKeyWrapAlgorithm.RsaOaepSha384
                or CvkKeyWrapAlgorithm.RsaOaepSha512
                or CvkKeyWrapAlgorithm.EcdhP256
                or CvkKeyWrapAlgorithm.EcdhP384
                or CvkKeyWrapAlgorithm.EcdhP521,
            _ => false
        };

    /// <summary>将公钥文件材料加入文档。</summary>
    public static void AddPublicKey(CvkDocument document, FileInfo file, string? keyId = null)
    {
        ArgumentNullException.ThrowIfNull(document);
        using var material = AsymmetricKeyFileLoader.LoadPublicKey(file, keyId);
        if (document.KeyProtection != CvkKeyProtection.PublicKey)
            throw new InvalidOperationException("只有 PublicKey 保护模式才能添加公钥接收者。");
        ValidateRecipientAlgorithm(document.KeyWrapAlgorithm, material);
        if (document.RecipientKeys.Any(x => x is not null && string.Equals(x.KeyId, material.KeyId, StringComparison.Ordinal)))
            throw new InvalidOperationException($"接收者 KeyId 已存在：{material.KeyId}。");
        document.RecipientKeys.Add(new AsymmetricRecipientKey(material.KeyId, material.Algorithm, material.PublicKeyBytes));
    }

    /// <summary>校验公钥材料与文档声明的封装算法匹配。</summary>
    private static void ValidateRecipientAlgorithm(CvkKeyWrapAlgorithm algorithm, AsymmetricPublicKeyMaterial material)
    {
        if (algorithm is CvkKeyWrapAlgorithm.RsaOaepSha256 or CvkKeyWrapAlgorithm.RsaOaepSha384 or CvkKeyWrapAlgorithm.RsaOaepSha512)
        {
            if (!string.Equals(material.Algorithm, "RSA", StringComparison.Ordinal))
                throw new InvalidOperationException("RSA 封装算法必须使用 RSA 公钥。");
            return;
        }

        if (algorithm is CvkKeyWrapAlgorithm.EcdhP256 or CvkKeyWrapAlgorithm.EcdhP384 or CvkKeyWrapAlgorithm.EcdhP521)
        {
            if (!string.Equals(material.Algorithm, "ECDH", StringComparison.Ordinal) || material.Key is not ECDiffieHellman ecdh)
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

        AsymmetricPrivateKeyMaterial? privateMaterial = null;
        try
        {
            if (parsed.Header.KeyProtection == CvkKeyProtection.PublicKey)
            {
                if (privateKeyFile is null)
                    throw new ArgumentNullException(nameof(privateKeyFile), "公钥保护模式必须提供私钥文件。");

                privateMaterial = AsymmetricKeyFileLoader.LoadPrivateKey(privateKeyFile, privateKeyPassword);
                var keys = new Dictionary<string, AsymmetricPrivateKeyMaterial>(StringComparer.Ordinal)
                {
                    [privateMaterial.KeyId] = privateMaterial
                };
                // 私钥文件名不一定等于 CVK 中的接收者 KeyId；为密钥体中声明的
                // 接收者建立别名，处理器随后仍会通过公钥解封失败来筛选候选。
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
        finally
        {
            privateMaterial?.Dispose();
        }
    }

    /// <summary>创建带私钥候选集的非对称密钥体处理器。</summary>
    private static ICvkPayloadCryptor CreateAsymmetricCryptor(CvkKeyWrapAlgorithm algorithm,
        IReadOnlyDictionary<string, AsymmetricPrivateKeyMaterial> privateKeys) => algorithm switch
    {
        CvkKeyWrapAlgorithm.RsaOaepSha256 => new RsaOaepSha256Cryptor(privateKeys),
        CvkKeyWrapAlgorithm.RsaOaepSha384 => new RsaOaepSha384Cryptor(privateKeys),
        CvkKeyWrapAlgorithm.RsaOaepSha512 => new RsaOaepSha512Cryptor(privateKeys),
        CvkKeyWrapAlgorithm.EcdhP256 => new EcdhP256Cryptor(privateKeys),
        CvkKeyWrapAlgorithm.EcdhP384 => new EcdhP384Cryptor(privateKeys),
        CvkKeyWrapAlgorithm.EcdhP521 => new EcdhP521Cryptor(privateKeys),
        _ => throw new NotSupportedException($"不支持的非对称封装算法：{algorithm}。")
    };

    private static IEnumerable<string> ExtractRecipientIds(ReadOnlyMemory<byte> keyBody)
    {
        using var json = System.Text.Json.JsonDocument.Parse(keyBody.ToArray());
        if (!json.RootElement.TryGetProperty("recipients", out var recipients) || recipients.ValueKind != System.Text.Json.JsonValueKind.Array)
            yield break;
        foreach (var item in recipients.EnumerateArray())
            if (item.ValueKind == System.Text.Json.JsonValueKind.Object && item.TryGetProperty("keyId", out var id) && id.ValueKind == System.Text.Json.JsonValueKind.String)
                yield return id.GetString()!;
    }
}

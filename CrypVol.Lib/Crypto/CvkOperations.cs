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
        if (protection == CvkKeyProtection.Plain) algorithm = CvkKeyWrapAlgorithm.None;
        return new CvkDocument
        {
            Cek = RandomNumberGenerator.GetBytes(32),
            KeyProtection = protection,
            KeyWrapAlgorithm = algorithm,
            CreatedAt = DateTimeOffset.UtcNow,
            Generator = "CrypVol"
        };
    }

    /// <summary>将公钥文件材料加入文档。</summary>
    public static void AddPublicKey(CvkDocument document, FileInfo file, string? keyId = null)
    {
        using var material = AsymmetricKeyFileLoader.LoadPublicKey(file, keyId);
        document.RecipientKeys.Add(new AsymmetricRecipientKey(material.KeyId, material.Algorithm, material.PublicKeyBytes));
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
        return LoadAsync(file, password, token);
    }
}
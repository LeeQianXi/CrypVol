using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;

namespace CrypVol.Lib.Crypto;

/// <summary>CVK v3 加载器：先验证容器，再按明文元数据选择密钥体解封路线。</summary>
public static class CvkLoader
{

    /// <summary>读取 CVK 明文元数据中的保护模式。</summary>
    public static EncryptionMode ReadMode(string path) => ReadMetadata(path).ProtectionMode;

    /// <summary>读取 CVK 明文元数据，不解封密钥体。</summary>
    public static CvkMetadataView ReadMetadata(string path)
    {
        var container = ReadContainer(File.ReadAllText(path).Trim());
        return new CvkMetadataView(container.Metadata, container.KeyBody.Length, container.Integrity);
    }

    /// <summary>加载、校验并解封 CVK，返回可编辑文档。</summary>
    public static async Task<CvkDocument> LoadAsync(FileInfo file, string? password = null,
        FileInfo? privateKeyFile = null, string? privateKeyPassword = null,
        CancellationToken cancellationToken = default, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(file);
        if (!file.Exists) throw new FileNotFoundException("密钥文件不存在", file.FullName);
        var container = ReadContainer((await File.ReadAllTextAsync(file.FullName, cancellationToken)).Trim());
        var metadata = container.Metadata;
        logger?.LogDebug("读取 CVK v3: {Path}, 保护模式={ProtectionMode}, 算法={Algorithm}, 密钥体={KeyBodyLength} 字节",
            file.FullName, metadata.ProtectionMode, metadata.Algorithm, container.KeyBody.Length);

        var document = await UnwrapAsync(container.KeyBody, metadata, password, privateKeyFile, privateKeyPassword,
            cancellationToken, logger);
        document.Comment = metadata.Comment;
        document.CreatedAt = metadata.CreatedAt;
        document.Label = metadata.Label;
        document.Description = metadata.Description;
        document.Generator = metadata.Generator;
        return document;
    }

    private static async Task<CvkDocument> UnwrapAsync(byte[] keyBody, CvkMetadataPayload metadata, string? password,
        FileInfo? privateKeyFile, string? privateKeyPassword, CancellationToken cancellationToken, ILogger? logger)
    {
        using var stream = new MemoryStream(keyBody, writable: false);
        using var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);
        var end = stream.Length;
        CvkDocument document;
        switch (metadata.ProtectionMode)
        {
            case EncryptionMode.PlainKey:
                document = new CvkDocument(ReadExact(reader, 32, end, "CEK"), metadata.ProtectionMode, metadata.Algorithm);
                break;
            case EncryptionMode.Password:
                document = new CvkDocument(PasswordKeyProtector.Unprotect(keyBody, password), metadata.ProtectionMode, metadata.Algorithm);
                reader.BaseStream.Position = end;
                break;
            case EncryptionMode.Asymmetric when metadata.Algorithm == EncryptionAlgorithm.Ecc:
                var ecc = await ReadEccPayloadAsync(reader, privateKeyFile, end, cancellationToken, logger);
                document = new CvkDocument(ecc.Cek, metadata.ProtectionMode, metadata.Algorithm);
                document.LoadPublicKeyRecipients(ecc.Recipients, ecc.Dek);
                break;
            case EncryptionMode.Asymmetric:
                var rsa = await ReadRsaPayloadAsync(reader, privateKeyFile, privateKeyPassword, end, cancellationToken, logger);
                document = new CvkDocument(rsa.Cek, metadata.ProtectionMode, metadata.Algorithm);
                document.LoadPublicKeyRecipients(rsa.Recipients, rsa.Dek);
                break;
            default:
                throw new InvalidDataException("CVK 元数据中的保护模式无效。");
        }
        if (reader.BaseStream.Position != end) throw new InvalidDataException("CVK 密钥体存在多余内容。");
        return document;
    }


    private static async Task<PublicKeyPayload> ReadRsaPayloadAsync(BinaryReader reader, FileInfo? privateKeyFile,
        string? privateKeyPassword, long end, CancellationToken cancellationToken, ILogger? logger)
    {
        var recipients = PublicKeyKeyBodyCodec.ReadRecipients(reader, end, "公钥");
        var dek = privateKeyFile is not null
            ? await TryDecryptDekAsync(privateKeyFile, recipients, privateKeyPassword, false, cancellationToken, logger)
            : await FindDekFromUserSshKeysAsync(recipients, privateKeyPassword, cancellationToken, logger);
        if (dek is null) throw new InvalidOperationException("未找到可用 RSA 私钥。");
        return ReadEncryptedCek(reader, end, recipients, dek);
    }

    private static async Task<PublicKeyPayload> ReadEccPayloadAsync(BinaryReader reader, FileInfo? privateKeyFile,
        long end, CancellationToken cancellationToken, ILogger? logger)
    {
        var recipients = PublicKeyKeyBodyCodec.ReadRecipients(reader, end, "ECC");
        if (privateKeyFile is null) throw new InvalidOperationException("ECC CVK 必须通过 --privkey-key 指定 P-256 私钥。");
        using var privateKey = EccKeyLoader.LoadPrivateKey(await File.ReadAllTextAsync(privateKeyFile.FullName, cancellationToken));
        byte[]? dek = null;
        foreach (var recipient in recipients)
            try { dek = EccKeyLoader.UnwrapDek(privateKey, recipient.EncryptedDek); break; }
            catch (CryptographicException) { }
        if (dek is null) throw new CryptographicException("ECC 私钥无法解封任何接收者 DEK。");
        logger?.LogDebug("ECC 私钥匹配成功: {PrivateKey}, 接收者={RecipientCount}", privateKeyFile.FullName, recipients.Count);
        return ReadEncryptedCek(reader, end, recipients, dek);
    }

    private static PublicKeyPayload ReadEncryptedCek(BinaryReader reader, long end,
        IReadOnlyList<CvkPublicKeyRecipient> recipients, byte[] dek)
    {
        var nonce = ReadExact(reader, 12, end, "公钥 nonce");
        var tag = ReadExact(reader, 16, end, "公钥 tag");
        var ciphertext = ReadExact(reader, 32, end, "公钥密文");
        var cek = new byte[32];
        using var aes = new AesGcm(dek, 16);
        aes.Decrypt(nonce, ciphertext, tag, cek);
        return new PublicKeyPayload(cek, dek, recipients);
    }

    private static CvkContainer ReadContainer(string base64)
    {
        var container = CvkContainerCodec.Decode(base64);
        ValidateMetadata(container.Metadata, container.KeyBody.Length);
        return container;
    }

    private static void ValidateMetadata(CvkMetadataPayload metadata, int keyBodyLength)
    {
        if (!Enum.IsDefined(metadata.ProtectionMode) || !Enum.IsDefined(metadata.Algorithm))
            throw new InvalidDataException("CVK 元数据中的模式或算法无效。");
        if (metadata.ProtectionMode != EncryptionMode.Asymmetric && metadata.Algorithm == EncryptionAlgorithm.Ecc)
            throw new InvalidDataException("ECC 算法必须与公钥保护模式组合。");
        if (metadata.ProtectionMode == EncryptionMode.Asymmetric && metadata.Algorithm is not (EncryptionAlgorithm.AesGcm or EncryptionAlgorithm.Ecc))
            throw new InvalidDataException("公钥保护算法无效。");
        if (metadata.KeyBodyLength != keyBodyLength || keyBodyLength <= 0)
            throw new InvalidDataException("CVK 元数据中的密钥体长度无效。");
        if (metadata.KeyIds.Count > ushort.MaxValue || metadata.KeyIds.Any(string.IsNullOrWhiteSpace))
            throw new InvalidDataException("CVK 元数据中的接收者标识无效。");
        if (metadata.Comment?.Length > 65535 || metadata.Label?.Length > 4096 || metadata.Description?.Length > 16384 ||
            metadata.Generator?.Length > 1024)
            throw new InvalidDataException("CVK 元数据字段过长。");
        if (!string.Equals(metadata.Integrity, "SHA-256", StringComparison.Ordinal))
            throw new InvalidDataException("CVK 校验算法不受支持。");
    }

    private static async Task<byte[]?> FindDekFromUserSshKeysAsync(IReadOnlyList<CvkPublicKeyRecipient> recipients,
        string? password, CancellationToken token, ILogger? logger)
    {
        foreach (var key in SshPrivateKeyDiscovery.DiscoverUserPrivateKeys())
        {
            token.ThrowIfCancellationRequested();
            var dek = await TryDecryptDekAsync(key, recipients, password, true, token, logger);
            if (dek is not null)
            {
                logger?.LogInformation("已自动发现并使用 SSH 私钥 {PrivateKeyPath}", key.FullName);
                return dek;
            }
        }
        return null;
    }

    private static async Task<byte[]?> TryDecryptDekAsync(FileInfo file, IReadOnlyList<CvkPublicKeyRecipient> recipients,
        string? password, bool suppress, CancellationToken token, ILogger? logger)
    {
        try
        {
            logger?.LogDebug("尝试使用私钥 {PrivateKeyPath} 匹配 {RecipientCount} 个接收者", file.FullName, recipients.Count);
            using var rsa = RsaKeyLoader.LoadPrivateKey(await File.ReadAllTextAsync(file.FullName, token), password);
            foreach (var recipient in recipients)
                try
                {
                    var dek = rsa.Decrypt(recipient.EncryptedDek, RSAEncryptionPadding.OaepSHA256);
                    logger?.LogDebug("私钥 {PrivateKeyPath} 匹配接收者 {KeyId}", file.FullName, recipient.KeyId);
                    return dek;
                }
                catch (CryptographicException) { }
            return null;
        }
        catch (Exception ex) when (suppress && ex is CryptographicException or IOException or UnauthorizedAccessException or ArgumentException)
        {
            logger?.LogDebug("跳过不可用 SSH 私钥 {Path}: {ExceptionType}", file.FullName, ex.GetType().Name);
            return null;
        }
    }

    private static byte[] ReadExact(BinaryReader reader, int count, long end, string field)
    {
        if (count < 0 || reader.BaseStream.Position + count > end) throw new InvalidDataException($"CVK {field}超出边界。");
        var value = reader.ReadBytes(count);
        if (value.Length != count) throw new InvalidDataException($"CVK {field}长度不足。");
        return value;
    }

    private sealed record PublicKeyPayload(byte[] Cek, byte[] Dek, IReadOnlyList<CvkPublicKeyRecipient> Recipients);
}

/// <summary>只读的 CVK 明文元数据视图。</summary>
public sealed record CvkMetadataView(CvkMetadataPayload Metadata, int KeyBodyLength, ReadOnlyMemory<byte> Integrity)
{
    /// <summary>CEK 保护模式。</summary>
    public EncryptionMode ProtectionMode => Metadata.ProtectionMode;
    /// <summary>使用的密码学算法。</summary>
    public EncryptionAlgorithm Algorithm => Metadata.Algorithm;
    /// <summary>接收者标识。</summary>
    public IReadOnlyList<string> KeyIds => Metadata.KeyIds.ToArray();
}

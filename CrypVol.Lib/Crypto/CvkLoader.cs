using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace CrypVol.Lib.Crypto;

/// <summary>加载既有 KEY0 v1 CVK 文件并返回可重新构建的内容模型。</summary>
public static class CvkLoader
{
    private const uint MinArgonMemoryKiB = 8 * 1024;
    private const uint MaxArgonMemoryKiB = 512 * 1024;
    private const uint MaxArgonIterations = 10;
    private const uint MaxArgonParallelism = 16;
    private const ushort MaxRecipientCiphertextLength = 4096;
    /// <summary>读取 CVK 的封装模式，不解包 CEK。</summary>
    /// <param name="path">CVK 文件路径。</param>
    /// <returns>封装模式。</returns>
    public static EnvelopeMode ReadMode(string path)
    {
        var data = Convert.FromBase64String(File.ReadAllText(path).Trim());
        using var reader = OpenPayload(data, out var mode, out _);
        return mode;
    }

    /// <summary>加载、解包并返回可编辑的 CVK 内容对象。</summary>
    /// <param name="file">CVK 文件。</param>
    /// <param name="password">密码封装时的密码。</param>
    /// <param name="privateKeyFile">公钥封装时的匹配私钥。</param>
    /// <param name="privateKeyPassword">加密私钥的密码。</param>
    /// <param name="cancellationToken">取消令牌。</param>
    /// <param name="logger">自动发现私钥时使用的可选日志记录器。</param>
    /// <returns>包含解包 CEK 与原有模式、注释的可编辑对象。</returns>
    public static async Task<CvkDocument> LoadAsync(FileInfo file, string? password = null,
        FileInfo? privateKeyFile = null, string? privateKeyPassword = null,
        CancellationToken cancellationToken = default, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(file);
        if (!file.Exists) throw new FileNotFoundException("密钥文件不存在", file.FullName);

        var data = Convert.FromBase64String((await File.ReadAllTextAsync(file.FullName, cancellationToken)).Trim());
        using var reader = OpenPayload(data, out var envelopeMode, out var payloadEnd);
        CvkDocument document;
        switch (envelopeMode)
        {
            case EnvelopeMode.Plain:
                document = new CvkDocument(ReadExact(reader, 32, payloadEnd, "CEK"), EncryptionMode.PlainKey);
                break;
            case EnvelopeMode.Password:
                document = new CvkDocument(ReadPasswordPayload(reader, password, payloadEnd), EncryptionMode.Password);
                break;
            case EnvelopeMode.PublicKey:
                var payload = await ReadPublicKeyPayloadAsync(reader, privateKeyFile, privateKeyPassword,
                    payloadEnd, cancellationToken, logger);
                document = new CvkDocument(payload.Cek, EncryptionMode.Asymmetric);
                document.LoadPublicKeyRecipients(payload.Recipients, payload.Dek);
                break;
            default:
                throw new InvalidDataException("未知 CVK 封装模式。");
        }

        if (document.Cek.Length != 32) throw new InvalidDataException("CVK 中的 CEK 长度无效。");
        document.Comment = ReadComment(reader, payloadEnd);
        return document;
    }

    private static byte[] ReadPasswordPayload(BinaryReader reader, string? password, long payloadEnd)
    {
        if (string.IsNullOrWhiteSpace(password))
            throw new InvalidOperationException("密钥受密码保护，请提供密码。");
        var salt = ReadExact(reader, 16, payloadEnd, "Argon2 salt");
        var iterations = BinaryPrimitives.ReverseEndianness(ReadUInt32(reader, payloadEnd, "Argon2 iterations"));
        var memorySize = BinaryPrimitives.ReverseEndianness(ReadUInt32(reader, payloadEnd, "Argon2 memory"));
        var parallelism = BinaryPrimitives.ReverseEndianness(ReadUInt32(reader, payloadEnd, "Argon2 parallelism"));
        ValidateArgonParameters(iterations, memorySize, parallelism);
        var nonce = ReadExact(reader, 12, payloadEnd, "密码 nonce");
        var tag = ReadExact(reader, 16, payloadEnd, "密码 tag");
        var ciphertext = ReadExact(reader, 32, payloadEnd, "密码密文");
        using var argon = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            DegreeOfParallelism = (int)parallelism,
            MemorySize = (int)memorySize,
            Iterations = (int)iterations
        };
        var cek = new byte[32];
        using var aes = new AesGcm(argon.GetBytes(32), 16);
        aes.Decrypt(nonce, ciphertext, tag, cek);
        return cek;
    }

    private static async Task<PublicKeyPayload> ReadPublicKeyPayloadAsync(BinaryReader reader, FileInfo? privateKeyFile,
        string? privateKeyPassword, long payloadEnd, CancellationToken cancellationToken, ILogger? logger)
    {
        var count = BinaryPrimitives.ReverseEndianness(ReadUInt16(reader, payloadEnd, "接收者数量"));
        if (count == 0) throw new InvalidDataException("公钥 CVK 至少需要一个接收者。");
        var recipients = new List<CvkPublicKeyRecipient>(count);
        for (var index = 0; index < count; index++)
        {
            var keyIdLength = ReadByte(reader, payloadEnd, "接收者标识长度");
            if (keyIdLength == 0) throw new InvalidDataException("公钥接收者标识不能为空。");
            var keyId = Encoding.UTF8.GetString(ReadExact(reader, keyIdLength, payloadEnd, "接收者标识"));
            var encryptedDekLength = BinaryPrimitives.ReverseEndianness(ReadUInt16(reader, payloadEnd, "DEK 密文长度"));
            if (encryptedDekLength == 0 || encryptedDekLength > MaxRecipientCiphertextLength)
                throw new InvalidDataException("公钥接收者 DEK 密文长度无效。");
            var encryptedDek = ReadExact(reader, encryptedDekLength, payloadEnd, "DEK 密文");
            recipients.Add(new CvkPublicKeyRecipient(keyId, encryptedDek));
        }

        var dek = privateKeyFile is not null
            ? await TryDecryptDekAsync(privateKeyFile, recipients, privateKeyPassword, false, cancellationToken)
            : await FindDekFromUserSshKeysAsync(recipients, privateKeyPassword, cancellationToken, logger);
        if (dek is null)
            throw new InvalidOperationException("未找到可用私钥。请通过 --privkey-key 明确指定匹配的 RSA 私钥。");
        var nonce = ReadExact(reader, 12, payloadEnd, "公钥 nonce");
        var tag = ReadExact(reader, 16, payloadEnd, "公钥 tag");
        var ciphertext = ReadExact(reader, 32, payloadEnd, "公钥密文");
        var cek = new byte[32];
        using var aes = new AesGcm(dek, 16);
        aes.Decrypt(nonce, ciphertext, tag, cek);
        return new PublicKeyPayload(cek, dek, recipients);
    }

    private static async Task<byte[]?> FindDekFromUserSshKeysAsync(IReadOnlyList<CvkPublicKeyRecipient> recipients,
        string? privateKeyPassword, CancellationToken cancellationToken, ILogger? logger)
    {
        foreach (var privateKeyFile in SshPrivateKeyDiscovery.DiscoverUserPrivateKeys())
        {
            cancellationToken.ThrowIfCancellationRequested();
            var dek = await TryDecryptDekAsync(privateKeyFile, recipients, privateKeyPassword, true, cancellationToken);
            if (dek is not null)
            {
                logger?.LogInformation("已自动发现并使用 SSH 私钥 {PrivateKeyPath}", privateKeyFile.FullName);
                return dek;
            }
        }

        return null;
    }

    private static async Task<byte[]?> TryDecryptDekAsync(FileInfo privateKeyFile,
        IReadOnlyList<CvkPublicKeyRecipient> recipients, string? privateKeyPassword, bool suppressCandidateErrors,
        CancellationToken cancellationToken)
    {
        try
        {
            var pem = await File.ReadAllTextAsync(privateKeyFile.FullName, cancellationToken);
            using var rsa = RsaKeyLoader.LoadPrivateKey(pem, privateKeyPassword);

            foreach (var recipient in recipients)
                try { return rsa.Decrypt(recipient.EncryptedDek, RSAEncryptionPadding.OaepSHA256); }
                catch (CryptographicException) { }

            return null;
        }
        catch (Exception exception) when (suppressCandidateErrors && IsUnreadableOrUnsupportedKey(exception))
        {
            return null;
        }
    }

    private static bool IsUnreadableOrUnsupportedKey(Exception exception)
    {
        return exception is CryptographicException
            or IOException
            or UnauthorizedAccessException
            or ArgumentException;
    }

    private static string? ReadComment(BinaryReader reader, long payloadEnd)
    {
        if (reader.BaseStream.Position == payloadEnd) return null;
        if (reader.BaseStream.Position + sizeof(ushort) > payloadEnd)
            throw new InvalidDataException("CVK 注释长度无效。");
        var length = BinaryPrimitives.ReverseEndianness(reader.ReadUInt16());
        if (reader.BaseStream.Position + length != payloadEnd)
            throw new InvalidDataException("CVK 注释内容无效。");
        return Encoding.UTF8.GetString(ReadExact(reader, length, payloadEnd, "CVK 注释"));
    }

    private static BinaryReader OpenPayload(byte[] data, out EnvelopeMode mode, out long payloadEnd)
    {
        var stream = new MemoryStream(data, false);
        var reader = new BinaryReader(stream);
        if (Encoding.ASCII.GetString(reader.ReadBytes(4)) != "KEY0" || reader.ReadByte() != 1)
            throw new InvalidDataException("无效的密钥文件。");
        mode = (EnvelopeMode)reader.ReadByte();
        var length = BinaryPrimitives.ReverseEndianness(reader.ReadInt32());
        payloadEnd = stream.Position + length;
        if (length < 0 || payloadEnd < stream.Position || payloadEnd > stream.Length)
            throw new InvalidDataException("CVK 载荷长度无效。");
        return reader;
    }

    private static byte[] ReadExact(BinaryReader reader, int count, long payloadEnd, string field)
    {
        if (count < 0 || reader.BaseStream.Position + count > payloadEnd)
            throw new InvalidDataException($"CVK {field}超出载荷边界。");
        var value = reader.ReadBytes(count);
        if (value.Length != count) throw new InvalidDataException($"CVK {field}长度不足。");
        return value;
    }

    private static byte ReadByte(BinaryReader reader, long payloadEnd, string field)
    {
        return ReadExact(reader, 1, payloadEnd, field)[0];
    }

    private static ushort ReadUInt16(BinaryReader reader, long payloadEnd, string field)
    {
        return BinaryPrimitives.ReadUInt16LittleEndian(ReadExact(reader, sizeof(ushort), payloadEnd, field));
    }

    private static uint ReadUInt32(BinaryReader reader, long payloadEnd, string field)
    {
        return BinaryPrimitives.ReadUInt32LittleEndian(ReadExact(reader, sizeof(uint), payloadEnd, field));
    }

    private static void ValidateArgonParameters(uint iterations, uint memorySize, uint parallelism)
    {
        if (iterations is 0 or > MaxArgonIterations || memorySize < MinArgonMemoryKiB ||
            memorySize > MaxArgonMemoryKiB || parallelism is 0 or > MaxArgonParallelism)
            throw new InvalidDataException("CVK Argon2 参数超出允许范围。");
    }

    private sealed record PublicKeyPayload(byte[] Cek,
        byte[] Dek,
        IReadOnlyList<CvkPublicKeyRecipient> Recipients);
}

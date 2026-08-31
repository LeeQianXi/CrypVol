using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace CrypVol.Lib.Crypto;

/// <summary>加载既有 KEY0 v1 CVK 文件并返回可重新构建的内容模型。</summary>
public static class CvkLoader
{
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
    /// <returns>包含解包 CEK 与原有模式、注释的可编辑对象。</returns>
    public static async Task<CvkDocument> LoadAsync(FileInfo file, string? password = null,
        FileInfo? privateKeyFile = null, string? privateKeyPassword = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(file);
        if (!file.Exists) throw new FileNotFoundException("密钥文件不存在", file.FullName);

        var data = Convert.FromBase64String((await File.ReadAllTextAsync(file.FullName, cancellationToken)).Trim());
        using var reader = OpenPayload(data, out var envelopeMode, out var payloadEnd);
        CvkDocument document;
        switch (envelopeMode)
        {
            case EnvelopeMode.Plain:
                document = new CvkDocument(reader.ReadBytes(32), EncryptionMode.PlainKey);
                break;
            case EnvelopeMode.Password:
                document = new CvkDocument(ReadPasswordPayload(reader, password), EncryptionMode.Password);
                break;
            case EnvelopeMode.PublicKey:
                var payload = await ReadPublicKeyPayloadAsync(reader, privateKeyFile, privateKeyPassword,
                    cancellationToken);
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

    private static byte[] ReadPasswordPayload(BinaryReader reader, string? password)
    {
        if (string.IsNullOrWhiteSpace(password))
            throw new InvalidOperationException("密钥受密码保护，请提供密码。");
        var salt = reader.ReadBytes(16);
        var iterations = BinaryPrimitives.ReverseEndianness(reader.ReadUInt32());
        var memorySize = BinaryPrimitives.ReverseEndianness(reader.ReadUInt32());
        var parallelism = BinaryPrimitives.ReverseEndianness(reader.ReadUInt32());
        var nonce = reader.ReadBytes(12);
        var tag = reader.ReadBytes(16);
        var ciphertext = reader.ReadBytes(32);
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
        string? privateKeyPassword, CancellationToken cancellationToken)
    {
        if (privateKeyFile is null)
            throw new InvalidOperationException("密钥受公钥保护，请提供私钥。");
        using var rsa = RSA.Create();
        var pem = await File.ReadAllTextAsync(privateKeyFile.FullName, cancellationToken);
        if (privateKeyPassword is null) rsa.ImportFromPem(pem);
        else rsa.ImportFromEncryptedPem(pem, privateKeyPassword);

        var count = BinaryPrimitives.ReverseEndianness(reader.ReadUInt16());
        byte[]? dek = null;
        var recipients = new List<CvkPublicKeyRecipient>(count);
        for (var index = 0; index < count; index++)
        {
            var keyIdLength = reader.ReadByte();
            var keyId = Encoding.UTF8.GetString(reader.ReadBytes(keyIdLength));
            var encryptedDekLength = BinaryPrimitives.ReverseEndianness(reader.ReadUInt16());
            var encryptedDek = reader.ReadBytes(encryptedDekLength);
            recipients.Add(new CvkPublicKeyRecipient(keyId, encryptedDek));
            if (dek is null)
                try { dek = rsa.Decrypt(encryptedDek, RSAEncryptionPadding.OaepSHA256); }
                catch (CryptographicException) { }
        }

        if (dek is null) throw new InvalidOperationException("没有匹配的私钥。");
        var nonce = reader.ReadBytes(12);
        var tag = reader.ReadBytes(16);
        var ciphertext = reader.ReadBytes(32);
        var cek = new byte[32];
        using var aes = new AesGcm(dek, 16);
        aes.Decrypt(nonce, ciphertext, tag, cek);
        return new PublicKeyPayload(cek, dek, recipients);
    }

    private static string? ReadComment(BinaryReader reader, long payloadEnd)
    {
        if (reader.BaseStream.Position == payloadEnd) return null;
        if (reader.BaseStream.Position + sizeof(ushort) > payloadEnd)
            throw new InvalidDataException("CVK 注释长度无效。");
        var length = BinaryPrimitives.ReverseEndianness(reader.ReadUInt16());
        if (reader.BaseStream.Position + length != payloadEnd)
            throw new InvalidDataException("CVK 注释内容无效。");
        return Encoding.UTF8.GetString(reader.ReadBytes(length));
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
        if (length < 0 || payloadEnd > stream.Length)
            throw new InvalidDataException("CVK 载荷长度无效。");
        return reader;
    }

    private sealed record PublicKeyPayload(byte[] Cek,
        byte[] Dek,
        IReadOnlyList<CvkPublicKeyRecipient> Recipients);
}
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace CrypVol.Lib.Crypto;

/// <summary>引擎外完整的 CVK 领域模型，负责密钥文件的加载、编辑、构建与写入。</summary>
public sealed class CvkDocument
{
    private readonly List<FileInfo> _newPublicKeyFiles = [];
    private byte[]? _publicKeyDek;
    /// <summary>创建带随机 CEK 的 CVK 内容模型。</summary>
    /// <param name="encryptionMode">CEK 封装模式。</param>
    /// <returns>可编辑的 CVK 内容模型。</returns>
    public static CvkDocument CreateNew(EncryptionMode encryptionMode) =>
        new(RandomNumberGenerator.GetBytes(32), encryptionMode);

    /// <summary>创建 CVK 内容模型。</summary>
    /// <param name="cek">要由 CVK 封装的 32 字节内容加密密钥。</param>
    /// <param name="encryptionMode">CEK 封装模式。</param>
    public CvkDocument(byte[] cek, EncryptionMode encryptionMode)
    {
        Cek = cek ?? throw new ArgumentNullException(nameof(cek));
        EncryptionMode = encryptionMode;
    }

    /// <summary>CVK 载荷，即解包后可直接用于内容加密的 CEK。</summary>
    public byte[] Cek { get; set; }

    /// <summary>CEK 的封装模式。</summary>
    public EncryptionMode EncryptionMode { get; set; }

    /// <summary>密码封装时用于派生密钥的密码。</summary>
    public string? Password { get; set; }

    /// <summary>已存在的公钥接收者槽位；可在缺少原始 PEM 文件时保留或删除。</summary>
    public IList<CvkPublicKeyRecipient> PublicKeyRecipients { get; } = new List<CvkPublicKeyRecipient>();

    /// <summary>待新增的 PEM 公钥文件；构建时会生成新的接收者槽位。</summary>
    public IReadOnlyList<FileInfo> NewPublicKeyFiles => _newPublicKeyFiles;

    /// <summary>添加一个公钥接收者。</summary>
    /// <param name="publicKeyFile">PEM 公钥文件。</param>
    public void AddPublicKey(FileInfo publicKeyFile)
    {
        ArgumentNullException.ThrowIfNull(publicKeyFile);
        if (_newPublicKeyFiles.Any(file => string.Equals(file.FullName, publicKeyFile.FullName,
                StringComparison.OrdinalIgnoreCase)))
            return;
        _newPublicKeyFiles.Add(publicKeyFile);
    }

    /// <summary>移除一个公钥接收者。</summary>
    /// <param name="publicKeyFile">要移除的 PEM 公钥文件。</param>
    /// <returns>是否移除了接收者。</returns>
    public bool RemovePublicKey(FileInfo publicKeyFile)
    {
        ArgumentNullException.ThrowIfNull(publicKeyFile);
        var existing = _newPublicKeyFiles.FirstOrDefault(file => string.Equals(file.FullName,
            publicKeyFile.FullName, StringComparison.OrdinalIgnoreCase));
        var removedPending = existing is not null && _newPublicKeyFiles.Remove(existing);
        return RemovePublicKey(Path.GetFileNameWithoutExtension(publicKeyFile.Name)) || removedPending;
    }

    /// <summary>按接收者标识移除既有公钥槽位，无需原始 PEM 文件。</summary>
    /// <param name="keyId">接收者标识。</param>
    /// <returns>是否移除了接收者。</returns>
    public bool RemovePublicKey(string keyId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        var recipient = PublicKeyRecipients.FirstOrDefault(item =>
            string.Equals(item.KeyId, keyId, StringComparison.Ordinal));
        var removedSlot = recipient is not null && PublicKeyRecipients.Remove(recipient);
        var pending = _newPublicKeyFiles.FirstOrDefault(file => string.Equals(
            Path.GetFileNameWithoutExtension(file.Name), keyId, StringComparison.Ordinal));
        return (pending is not null && _newPublicKeyFiles.Remove(pending)) || removedSlot;
    }

    /// <summary>清空全部既有及待新增的公钥接收者。</summary>
    public void ClearPublicKeys()
    {
        PublicKeyRecipients.Clear();
        _newPublicKeyFiles.Clear();
    }

    /// <summary>可选注释。</summary>
    public string? Comment { get; set; }

    /// <summary>提取进入处理引擎所需的轻量凭据。</summary>
    /// <returns>仅包含内容加密模式与 CEK 的运行凭据。</returns>
    public CvkCredentials ToCredentials() => new(EncryptionMode, Cek);

    /// <summary>按现有 KEY0 v1 格式构建二进制 CVK 内容。</summary>
    /// <returns>可直接 Base64 编码或写入的二进制 CVK 内容。</returns>
    public byte[] Build()
    {
        if (EncryptionMode == EncryptionMode.None) return [];
        if (Cek is null || Cek.Length != 32)
            throw new InvalidOperationException("CVK 载荷必须是 32 字节 CEK。");

        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream);
        writer.Write(Encoding.ASCII.GetBytes("KEY0"));
        writer.Write((byte)1);
        writer.Write((byte)(EncryptionMode switch
        {
            EncryptionMode.PlainKey => EnvelopeMode.Plain,
            EncryptionMode.Password => EnvelopeMode.Password,
            EncryptionMode.Asymmetric => EnvelopeMode.PublicKey,
            _ => throw new InvalidOperationException("不支持的 CVK 封装模式。")
        }));
        var payloadLengthPosition = stream.Position;
        writer.Write(0);

        switch (EncryptionMode)
        {
            case EncryptionMode.PlainKey:
                writer.Write(Cek);
                break;
            case EncryptionMode.Password:
                WritePasswordPayload(writer);
                break;
            case EncryptionMode.Asymmetric:
                WritePublicKeyPayload(writer);
                break;
        }

        if (!string.IsNullOrWhiteSpace(Comment))
        {
            var comment = Encoding.UTF8.GetBytes(Comment);
            if (comment.Length > ushort.MaxValue)
                throw new InvalidOperationException("CVK 注释长度不能超过 65535 字节。");
            writer.Write(BinaryPrimitives.ReverseEndianness((ushort)comment.Length));
            writer.Write(comment);
        }

        var end = stream.Position;
        stream.Position = payloadLengthPosition;
        writer.Write(BinaryPrimitives.ReverseEndianness((int)(end - payloadLengthPosition - sizeof(int))));
        return stream.ToArray();
    }

    /// <summary>构建可直接保存为 .cvk 文件的 Base64 文本。</summary>
    /// <returns>Base64 编码后的 CVK 内容；无加密模式返回空字符串。</returns>
    public string BuildBase64() => EncryptionMode == EncryptionMode.None ? string.Empty : Convert.ToBase64String(Build());

    /// <summary>将构建后的内容写入指定 CVK 文件。</summary>
    /// <param name="file">目标 CVK 文件。</param>
    /// <param name="cancellationToken">取消令牌。</param>
    public async Task WriteAsync(FileInfo file, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(file);
        if (EncryptionMode == EncryptionMode.None) return;
        file.Directory?.Create();
        await File.WriteAllTextAsync(file.FullName, BuildBase64(), cancellationToken);
    }

    internal void LoadPublicKeyRecipients(IEnumerable<CvkPublicKeyRecipient> recipients, byte[] dek)
    {
        PublicKeyRecipients.Clear();
        foreach (var recipient in recipients) PublicKeyRecipients.Add(recipient);
        _publicKeyDek = dek;
    }

    private void WritePasswordPayload(BinaryWriter writer)
    {
        if (string.IsNullOrWhiteSpace(Password))
            throw new InvalidOperationException("密码封装模式必须提供密码。");

        var salt = RandomNumberGenerator.GetBytes(16);
        const uint iterations = 3, memorySize = 65536, parallelism = 1;
        using var argon = new Argon2id(Encoding.UTF8.GetBytes(Password))
        {
            Salt = salt,
            DegreeOfParallelism = (int)parallelism,
            MemorySize = (int)memorySize,
            Iterations = (int)iterations
        };
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[32];
        var tag = new byte[16];
        using var aes = new AesGcm(argon.GetBytes(32), 16);
        aes.Encrypt(nonce, Cek, ciphertext, tag);
        writer.Write(salt);
        writer.Write(BinaryPrimitives.ReverseEndianness(iterations));
        writer.Write(BinaryPrimitives.ReverseEndianness(memorySize));
        writer.Write(BinaryPrimitives.ReverseEndianness(parallelism));
        writer.Write(nonce);
        writer.Write(tag);
        writer.Write(ciphertext);
    }

    private void WritePublicKeyPayload(BinaryWriter writer)
    {
        var recipients = PublicKeyRecipients.ToDictionary(item => item.KeyId, item => item,
            StringComparer.Ordinal);
        var dek = _publicKeyDek ??= RandomNumberGenerator.GetBytes(32);
        foreach (var file in _newPublicKeyFiles)
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(File.ReadAllText(file.FullName));
            var keyId = Path.GetFileNameWithoutExtension(file.Name);
            recipients[keyId] = new CvkPublicKeyRecipient(keyId,
                rsa.Encrypt(dek, RSAEncryptionPadding.OaepSHA256));
        }

        if (recipients.Count == 0)
            throw new Exception("至少需要一个接收者公钥。");
        if (recipients.Count > ushort.MaxValue)
            throw new InvalidOperationException("接收者数量不能超过 65535。");

        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[32];
        var tag = new byte[16];
        using var aes = new AesGcm(dek, 16);
        aes.Encrypt(nonce, Cek, ciphertext, tag);
        writer.Write(BinaryPrimitives.ReverseEndianness((ushort)recipients.Count));
        var resolvedRecipients = recipients.Values.ToList();
        foreach (var recipient in resolvedRecipients)
        {
            var keyIdBytes = Encoding.UTF8.GetBytes(recipient.KeyId);
            if (keyIdBytes.Length > byte.MaxValue)
                throw new InvalidOperationException("接收者标识长度不能超过 255 字节。");
            writer.Write((byte)keyIdBytes.Length);
            writer.Write(keyIdBytes);
            writer.Write(BinaryPrimitives.ReverseEndianness((ushort)recipient.EncryptedDek.Length));
            writer.Write(recipient.EncryptedDek);
        }

        writer.Write(nonce);
        writer.Write(tag);
        writer.Write(ciphertext);
        PublicKeyRecipients.Clear();
        foreach (var recipient in resolvedRecipients) PublicKeyRecipients.Add(recipient);
        _newPublicKeyFiles.Clear();
    }
}

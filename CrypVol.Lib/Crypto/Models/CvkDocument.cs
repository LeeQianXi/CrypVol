using System.Security.Cryptography;
using System.Text;
using CrypVol.Lib.Crypto.Container;
using CrypVol.Lib.Crypto.Discovery;
using CrypVol.Lib.Crypto.Protectors;
using CrypVol.Lib.Utility;

namespace CrypVol.Lib.Crypto.Models;

/// <summary>引擎外完整的 CVK 领域模型，负责密钥文件的加载、编辑、构建与写入。</summary>
public sealed class CvkDocument
{
    private readonly List<FileInfo> _newPublicKeyFiles = [];
    private byte[]? _publicKeyDek;

    /// <summary>创建 CVK 内容模型。</summary>
    /// <param name="cek">要由 CVK 封装的 32 字节内容加密密钥。</param>
    /// <param name="encryptionMode">CEK 封装模式。</param>
    public CvkDocument(byte[] cek, EncryptionMode encryptionMode, EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.AesGcm)
    {
        Cek = cek ?? throw new ArgumentNullException(nameof(cek));
        EncryptionMode = encryptionMode;
        EncryptionAlgorithm = encryptionAlgorithm;
    }

    /// <summary>CVK 载荷，即解包后可直接用于内容加密的 CEK。</summary>
    public ReadOnlyMemory<byte> Cek
    {
        get;
        set => field = value.ToArray();
    }

    /// <summary>CEK 的封装模式。</summary>
    public EncryptionMode EncryptionMode { get; set; }

    /// <summary>CVK 使用的密码学算法，与 CEK 保护模式分离。</summary>
    public EncryptionAlgorithm EncryptionAlgorithm { get; set; }

    /// <summary>密码封装时用于派生密钥的密码。</summary>
    public string? Password { get; set; }

    /// <summary>已存在的公钥接收者槽位；可在缺少原始公钥文件时保留或删除。</summary>
    public IList<CvkPublicKeyRecipient> PublicKeyRecipients { get; } = new List<CvkPublicKeyRecipient>();

    /// <summary>待新增的公钥文件；构建时按当前封装模式生成接收者槽位。</summary>
    public IReadOnlyList<FileInfo> NewPublicKeyFiles => _newPublicKeyFiles;

    /// <summary>可选注释。</summary>
    public string? Comment { get; set; }

    /// <summary>CVK 创建时间；旧版 CVK 未携带该字段时为 <see langword="null" />。</summary>
    public DateTimeOffset? CreatedAt { get; set; }

    /// <summary>用户可读的 CVK 标签。</summary>
    public string? Label { get; set; }

    /// <summary>CVK 用途描述。</summary>
    public string? Description { get; set; }

    /// <summary>生成该 CVK 的应用标识。</summary>
    public string? Generator { get; set; }

    /// <summary>当前 CVK 使用的接收者标识快照。</summary>
    public IReadOnlyList<string> KeyIds => PublicKeyRecipients.Select(item => item.KeyId)
        .Concat(_newPublicKeyFiles.Select(CvkKeyIdResolver.Resolve))
        .Distinct(StringComparer.Ordinal)
        .ToArray();

    /// <summary>创建带随机 CEK 的 CVK 内容模型。</summary>
    /// <param name="encryptionMode">CEK 封装模式。</param>
    /// <returns>可编辑的 CVK 内容模型。</returns>
    public static CvkDocument CreateNew(EncryptionMode encryptionMode,
        EncryptionAlgorithm encryptionAlgorithm = EncryptionAlgorithm.AesGcm)
    {
        return new CvkDocument(RandomNumberGenerator.GetBytes(32), encryptionMode, encryptionAlgorithm)
        {
            CreatedAt = DateTimeOffset.UtcNow,
            Generator = "CrypVol"
        };
    }

    /// <summary>添加一个公钥接收者。</summary>
    /// <param name="publicKeyFile">PEM 或 OpenSSH <c>ssh-rsa</c> 公钥文件。</param>
    public void AddPublicKey(FileInfo publicKeyFile)
    {
        ArgumentNullException.ThrowIfNull(publicKeyFile);
        if (_newPublicKeyFiles.Any(file => string.Equals(file.FullName, publicKeyFile.FullName,
                StringComparison.OrdinalIgnoreCase)))
            return;
        _newPublicKeyFiles.Add(publicKeyFile);
    }

    /// <summary>移除一个公钥接收者。</summary>
    /// <param name="publicKeyFile">要移除的公钥文件。</param>
    /// <returns>是否移除了接收者。</returns>
    public bool RemovePublicKey(FileInfo publicKeyFile)
    {
        ArgumentNullException.ThrowIfNull(publicKeyFile);
        var existing = _newPublicKeyFiles.FirstOrDefault(file => string.Equals(file.FullName,
            publicKeyFile.FullName, StringComparison.OrdinalIgnoreCase));
        var removedPending = existing is not null && _newPublicKeyFiles.Remove(existing);
        var keyId = publicKeyFile.Exists
            ? CvkKeyIdResolver.Resolve(publicKeyFile)
            : Path.GetFileNameWithoutExtension(publicKeyFile.Name);
        return RemovePublicKey(keyId) || removedPending;
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
        return pending is not null && _newPublicKeyFiles.Remove(pending) || removedSlot;
    }

    /// <summary>清空全部既有及待新增的公钥接收者。</summary>
    public void ClearPublicKeys()
    {
        PublicKeyRecipients.Clear();
        _newPublicKeyFiles.Clear();
    }

    /// <summary>提取进入处理引擎所需的轻量凭据。</summary>
    /// <returns>仅包含内容加密模式与 CEK 的运行凭据。</returns>
    public CvkCredentials ToCredentials()
    {
        return new CvkCredentials(EncryptionMode, Cek, EncryptionAlgorithm);
    }

    /// <summary>按 CVK v3 三段式格式构建二进制内容。</summary>
    /// <returns>可直接 Base64 编码或写入的二进制 CVK 内容。</returns>
    public byte[] Build()
    {
        if (EncryptionMode == EncryptionMode.None) return [];
        if (Cek.Length != 32)
            throw new InvalidOperationException("CVK 载荷必须是 32 字节 CEK。");
        if (!Enum.IsDefined(EncryptionMode) || !Enum.IsDefined(EncryptionAlgorithm))
            throw new CvkValidationException("CVK 模式或算法无效。");
        if (EncryptionAlgorithm == EncryptionAlgorithm.Ecc && EncryptionMode != EncryptionMode.Asymmetric)
            throw new CvkValidationException("ECC 算法只能与 Asymmetric 公钥保护模式组合。");

        using var keyBodyStream = new MemoryStream();
        using (var keyBodyWriter = new BinaryWriter(keyBodyStream, Encoding.UTF8, true))
        {
            switch (EncryptionMode)
            {
                case EncryptionMode.PlainKey:
                    keyBodyWriter.Write(Cek.Span);
                    break;
                case EncryptionMode.Password:
                    WritePasswordPayload(keyBodyWriter);
                    break;
                case EncryptionMode.Asymmetric:
                    var result = PublicKeyKeyProtector.Protect(EncryptionAlgorithm, Cek.Span,
                        PublicKeyRecipients.ToArray(), _newPublicKeyFiles, _publicKeyDek);
                    keyBodyWriter.Write(result.KeyBody);
                    PublicKeyRecipients.Clear();
                    foreach (var recipient in result.Recipients) PublicKeyRecipients.Add(recipient);
                    _publicKeyDek = result.Dek;
                    _newPublicKeyFiles.Clear();
                    break;
                default:
                    throw new InvalidOperationException("不支持的 CVK 封装模式。");
            }
        }
        var keyBody = keyBodyStream.ToArray();
        var metadata = new CvkMetadataPayload(
            EncryptionMode, EncryptionAlgorithm, CreatedAt, Label, Description, Generator,
            Comment, KeyIds, keyBody.Length);
        return Convert.FromBase64String(CvkContainerCodec.Encode(metadata, keyBody));
    }

    /// <summary>构建可直接保存为 .cvk 文件的 Base64 文本。</summary>
    /// <returns>Base64 编码后的 CVK 内容；无加密模式返回空字符串。</returns>
    public string BuildBase64()
    {
        return EncryptionMode == EncryptionMode.None ? string.Empty : Convert.ToBase64String(Build());
    }

    /// <summary>将构建后的内容写入指定 CVK 文件。</summary>
    /// <param name="file">目标 CVK 文件。</param>
    /// <param name="cancellationToken">取消令牌。</param>
    public async Task WriteAsync(FileInfo file, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(file);
        if (EncryptionMode == EncryptionMode.None) return;
        await AtomicFile.WriteTextAsync(file.FullName, BuildBase64(), cancellationToken);
    }

    internal void LoadPublicKeyRecipients(IEnumerable<CvkPublicKeyRecipient> recipients, byte[] dek)
    {
        PublicKeyRecipients.Clear();
        foreach (var recipient in recipients) PublicKeyRecipients.Add(recipient);
        _publicKeyDek = dek;
    }

    private void WritePasswordPayload(BinaryWriter writer)
    {
        var payload = PasswordKeyProtector.Protect(Cek.Span, Password);
        writer.Write(payload);
    }

}

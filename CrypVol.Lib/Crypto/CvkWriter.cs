using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace CrypVol.Lib.Crypto;

/// <summary>CVK 生成黑盒。封装 CEK 生成、密钥包裹、二进制写入。</summary>
public sealed class CvkWriter
{
    private readonly byte[] _cek;

    public CvkWriter(byte[] cek, EncryptionMode mode,
        string? password = null, IEnumerable<FileInfo>? publicKeyFiles = null, string? comment = null)
    {
        _cek = cek;
        EncryptionMode = mode;
        Password = password;
        PublicKeys = publicKeyFiles ?? [];
        Comment = comment;
    }

    public CvkWriter(EncryptionMode mode, string? password = null,
        IEnumerable<FileInfo>? publicKeyFiles = null, string? comment = null)
    {
        _cek = RandomNumberGenerator.GetBytes(32);
        EncryptionMode = mode;
        Password = password;
        PublicKeys = publicKeyFiles ?? [];
        Comment = comment;
    }

    public EncryptionMode EncryptionMode { get; init; }
    public string? Password { get; init; }
    public IEnumerable<FileInfo> PublicKeys { get; init; }
    public string? Comment { get; init; }

    /// <summary>结构化日志（可选）</summary>
    public ILogger? Logger { get; set; }

    public async Task<CvkCredentials> WriteCvkAsync(DirectoryInfo folder, string prefix, CancellationToken ct = default)
    {
        Logger?.LogDebug("生成密钥: 模式={Mode}, 前缀={Prefix}", EncryptionMode, prefix);
        if (EncryptionMode != EncryptionMode.None)
        {
            var secret = new byte[32];
            Buffer.BlockCopy(_cek, 0, secret, 0, 32);
            using var ms = new MemoryStream();
            using var w = new BinaryWriter(ms);
            w.Write(Encoding.ASCII.GetBytes("KEY0"));
            w.Write((byte)1);
            w.Write((byte)(EncryptionMode switch
            {
                EncryptionMode.PlainKey => 0, EncryptionMode.Password => 1, EncryptionMode.Asymmetric => 2, _ => 0
            }));
            var plPos = ms.Position;
            w.Write(0);
            if (EncryptionMode == EncryptionMode.PlainKey)
            {
                Logger?.LogTrace("写入 PlainKey CEK");
                w.Write(secret);
            }
            else if (EncryptionMode == EncryptionMode.Password)
            {
                Logger?.LogDebug("Argon2id 密钥派生中...");
                WritePassword(w, secret);
            }
            else
            {
                Logger?.LogDebug("公钥加密 CEK: {Count} 个接收者", PublicKeys.Count());
                WritePublicKey(w, secret);
            }

            if (!string.IsNullOrWhiteSpace(Comment))
            {
                var cb = Encoding.UTF8.GetBytes(Comment);
                w.Write(BinaryPrimitives.ReverseEndianness((ushort)cb.Length));
                w.Write(cb);
            }

            var end = ms.Position;
            ms.Position = plPos;
            w.Write(BinaryPrimitives.ReverseEndianness((int)(end - plPos - 4)));
            var path = Path.Combine(folder.FullName, $"{prefix}.cvk");
            Logger?.LogDebug("写入密钥文件: {Path}", path);
            await File.WriteAllTextAsync(path, Convert.ToBase64String(ms.ToArray()), ct);
        }

        return new CvkCredentials(EncryptionMode, _cek);
    }

    private void WritePassword(BinaryWriter w, byte[] secret)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        const uint t = 3, m = 65536, p = 1;
        using var a2 = new Argon2id(Encoding.UTF8.GetBytes(Password!))
        {
            Salt = salt,
            DegreeOfParallelism = (int)p,
            MemorySize = (int)m,
            Iterations = (int)t
        };
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ct = new byte[32];
        var tag = new byte[16];
        using var aes = new AesGcm(a2.GetBytes(32), 16);
        aes.Encrypt(nonce, secret, ct, tag);
        w.Write(salt);
        w.Write(BinaryPrimitives.ReverseEndianness(t));
        w.Write(BinaryPrimitives.ReverseEndianness(m));
        w.Write(BinaryPrimitives.ReverseEndianness(p));
        w.Write(nonce);
        w.Write(tag);
        w.Write(ct);
    }

    private void WritePublicKey(BinaryWriter w, byte[] secret)
    {
        var recipients = new Dictionary<string, RSA>();
        foreach (var f in PublicKeys)
        {
            var r = RSA.Create();
            try
            {
                r.ImportFromPem(File.ReadAllText(f.FullName));
                recipients[Path.GetFileNameWithoutExtension(f.Name)] = r;
                Logger?.LogTrace("加载公钥: {Name}", f.Name);
            }
            catch
            {
                Logger?.LogWarning("无法加载公钥: {Name}", f.Name);
                r.Dispose();
            }
        }

        if (recipients.Count == 0) throw new Exception("至少需要一个接收者公钥");
        var dek = RandomNumberGenerator.GetBytes(32);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ct = new byte[32];
        var tag = new byte[16];
        using var aes = new AesGcm(dek, 16);
        aes.Encrypt(nonce, secret, ct, tag);
        w.Write(BinaryPrimitives.ReverseEndianness((ushort)recipients.Count));
        foreach (var (kid, rsa) in recipients)
        {
            var kb = Encoding.UTF8.GetBytes(kid);
            var ed = rsa.Encrypt(dek, RSAEncryptionPadding.OaepSHA256);
            w.Write((byte)kb.Length);
            w.Write(kb);
            w.Write(BinaryPrimitives.ReverseEndianness((ushort)ed.Length));
            w.Write(ed);
        }

        w.Write(nonce);
        w.Write(tag);
        w.Write(ct);
        foreach (var r in recipients.Values) r.Dispose();
    }
}

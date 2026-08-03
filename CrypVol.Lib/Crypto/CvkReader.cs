using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace CrypVol.Lib.Crypto;

/// <summary>CVK 读取黑盒。封装修凭据校验、格式解析、CEK 解密。</summary>
public sealed class CvkReader
{
    public CvkReader(FileInfo cvkFile, string? password = null, FileInfo? privateKeyFile = null,
        string? privateKeyPass = null)
    {
        CvkFile = cvkFile;
        Password = password;
        PrivateKeyFile = privateKeyFile;
        PrivateKeyPass = privateKeyPass;
    }

    public FileInfo CvkFile { get; init; }
    public string? Password { get; init; }
    public FileInfo? PrivateKeyFile { get; init; }
    public string? PrivateKeyPass { get; init; }

    public static EnvelopeMode ReadMode(string path)
    {
        var d = Convert.FromBase64String(File.ReadAllText(path).Trim());
        if (d.Length < 6 || d[0] != 'K' || d[1] != 'E' || d[2] != 'Y' || d[3] != '0' || d[4] != 1)
            throw new InvalidDataException("无效的密钥文件");
        return (EnvelopeMode)d[5];
    }

    public async Task<CvkCredentials> LoadKeyAsync(CancellationToken ct = default)
    {
        if (!CvkFile.Exists) throw new FileNotFoundException("密钥文件不存在", CvkFile.FullName);
        var mode = ReadMode(CvkFile.FullName);

        return mode switch
        {
            EnvelopeMode.Plain => LoadPlain(),
            EnvelopeMode.Password => LoadPassword(),
            EnvelopeMode.PublicKey => await LoadPublicKeyAsync(ct),
            _ => throw new InvalidDataException("未知模式")
        };
    }

    // ── Plain ──

    private CvkCredentials LoadPlain()
    {
        var data = OpenCvk();
        using var r = ReadPayload(data);
        return new CvkCredentials(EncryptionMode.PlainKey, r.ReadBytes(32));
    }

    // ── Password ──

    private CvkCredentials LoadPassword()
    {
        if (string.IsNullOrWhiteSpace(Password)) throw new InvalidOperationException("密钥受密码保护，请提供密码");
        var data = OpenCvk();
        using var r = ReadPayload(data);
        byte[] cek;
        var salt = r.ReadBytes(16);
        var t = BinaryPrimitives.ReverseEndianness(r.ReadUInt32());
        var m = BinaryPrimitives.ReverseEndianness(r.ReadUInt32());
        var p = BinaryPrimitives.ReverseEndianness(r.ReadUInt32());
        var nonce = r.ReadBytes(12);
        var tag = r.ReadBytes(16);
        var ct = r.ReadBytes(32);
        using (var a2 = new Argon2id(Encoding.UTF8.GetBytes(Password!)))
        {
            a2.Salt = salt;
            a2.DegreeOfParallelism = (int)p;
            a2.MemorySize = (int)m;
            a2.Iterations = (int)t;
            using var aes = new AesGcm(a2.GetBytes(32), 16);
            var pt = new byte[32];
            aes.Decrypt(nonce, ct, tag, pt);
            cek = pt;
        }

        return new CvkCredentials(EncryptionMode.Password, cek);
    }

    // ── PublicKey ──

    private async Task<CvkCredentials> LoadPublicKeyAsync(CancellationToken ct)
    {
        if (PrivateKeyFile is null) throw new InvalidOperationException("密钥受公钥保护，请提供私钥");
        using var rsa = RSA.Create();
        var pem = await File.ReadAllTextAsync(PrivateKeyFile.FullName, ct);
        if (PrivateKeyPass is not null) rsa.ImportFromEncryptedPem(pem, PrivateKeyPass);
        else rsa.ImportFromPem(pem);

        var data = OpenCvk();
        using var r = ReadPayload(data);
        byte[] cek;
        var count = BinaryPrimitives.ReverseEndianness(r.ReadUInt16());
        byte[]? dek = null;
        for (var i = 0; i < count; i++)
        {
            int il = r.ReadByte();
            r.ReadBytes(il);
            var edl = BinaryPrimitives.ReverseEndianness(r.ReadUInt16());
            var ed = r.ReadBytes(edl);
            if (dek == null)
                try { dek = rsa.Decrypt(ed, RSAEncryptionPadding.OaepSHA256); }
                catch (CryptographicException)
                {
                    /* 不匹配，尝试下一个接收者 */
                }
        }

        if (dek == null) throw new Exception("没有匹配的私钥");
        var nonce = r.ReadBytes(12);
        var tag = r.ReadBytes(16);
        var ct1 = r.ReadBytes(32);
        using (var aes = new AesGcm(dek, 16))
        {
            var pt = new byte[32];
            aes.Decrypt(nonce, ct1, tag, pt);
            cek = pt;
        }

        return new CvkCredentials(EncryptionMode.Asymmetric, cek);
    }

    // ── 格式工具 ──

    private byte[] OpenCvk()
    {
        return Convert.FromBase64String(File.ReadAllText(CvkFile.FullName).Trim());
    }

    private static BinaryReader ReadPayload(byte[] data)
    {
        var ms = new MemoryStream(data);
        var r = new BinaryReader(ms);
        if (Encoding.ASCII.GetString(r.ReadBytes(4)) != "KEY0") throw new Exception("无效的密钥文件");
        if (r.ReadByte() != 1) throw new Exception("不支持的版本");
        r.ReadByte();
        _ = BinaryPrimitives.ReverseEndianness(r.ReadInt32());
        return r; // caller must dispose ms via using
    }
}
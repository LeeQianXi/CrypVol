using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace CrypVol.Lib;

/// <summary>生成 .cvk 密钥信封文件</summary>
public static class CvkGenerator
{
    public static async Task CreateAsync(
        string keyOutputDir, string outputPrefix, EncryptionMode mode,
        byte[] cek, byte[] salt, string? password = null,
        IEnumerable<FileInfo>? publicKeys = null, CancellationToken token = default)
    {
        if (mode is EncryptionMode.None) return;

        byte[] secret = [.. cek, .. salt];
        using var ms = new MemoryStream();
        await using var writer = new BinaryWriter(ms);

        writer.Write(Encoding.ASCII.GetBytes("KEY0"));
        writer.Write((byte)1);

        writer.Write(mode switch
        {
            EncryptionMode.None => (byte)0,
            EncryptionMode.PlainKey => (byte)0,
            EncryptionMode.Password => (byte)1,
            EncryptionMode.Asymmetric => (byte)2,
            _ => throw new Exception("未知加密模式")
        });

        var payloadLenPos = ms.Position;
        writer.Write(0);

        switch (mode)
        {
            case EncryptionMode.PlainKey:
                writer.Write(secret);
                break;
            case EncryptionMode.Password:
                WritePasswordPayload(writer, secret, password!);
                break;
            case EncryptionMode.Asymmetric:
                WritePublicKeyPayload(writer, secret, publicKeys!);
                break;
        }

        var endPos = ms.Position;
        ms.Seek(payloadLenPos, SeekOrigin.Begin);
        writer.Write(BinaryPrimitives.ReverseEndianness((int)(endPos - payloadLenPos - 4)));

        var base64 = Convert.ToBase64String(ms.ToArray());
        var filePath = Path.Combine(keyOutputDir, $"{outputPrefix}.cvk");
        await File.WriteAllTextAsync(filePath, base64, token);
    }

    private static void WritePasswordPayload(BinaryWriter writer, byte[] secret, string password)
    {
        var argonSalt = RandomNumberGenerator.GetBytes(16);
        const uint time = 3, memory = 65536, parallelism = 1;

        using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password));
        argon2.Salt = argonSalt;
        argon2.DegreeOfParallelism = (int)parallelism;
        argon2.MemorySize = (int)memory;
        argon2.Iterations = (int)time;
        var kek = argon2.GetBytes(32);

        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[secret.Length];
        var tag = new byte[16];
        using var aes = new AesGcm(kek, 16);
        aes.Encrypt(nonce, secret, ciphertext, tag);

        writer.Write(argonSalt);
        writer.Write(BinaryPrimitives.ReverseEndianness(time));
        writer.Write(BinaryPrimitives.ReverseEndianness(memory));
        writer.Write(BinaryPrimitives.ReverseEndianness(parallelism));
        writer.Write(nonce);
        writer.Write(tag);
        writer.Write(ciphertext);
    }

    private static void WritePublicKeyPayload(BinaryWriter writer, byte[] secret, IEnumerable<FileInfo> pemFiles)
    {
        var recipients = new List<(string KeyId, RSA Rsa)>();
        foreach (var f in pemFiles)
        {
            var rsa = RSA.Create();
            try { rsa.ImportFromPem(File.ReadAllText(f.FullName)); }
            catch { continue; }

            recipients.Add((Path.GetFileNameWithoutExtension(f.Name), rsa));
        }

        if (recipients.Count == 0) throw new Exception("至少需要一个接收者公钥");

        var dek = RandomNumberGenerator.GetBytes(32);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ct = new byte[64];
        var tag = new byte[16];
        using var aes = new AesGcm(dek, 16);
        aes.Encrypt(nonce, secret, ct, tag);

        writer.Write(BinaryPrimitives.ReverseEndianness((ushort)recipients.Count));
        foreach (var (kid, rsa) in recipients)
        {
            var kb = Encoding.UTF8.GetBytes(kid);
            var edek = rsa.Encrypt(dek, RSAEncryptionPadding.OaepSHA256);
            writer.Write((byte)kb.Length);
            writer.Write(kb);
            writer.Write(BinaryPrimitives.ReverseEndianness((ushort)edek.Length));
            writer.Write(edek);
        }

        writer.Write(nonce);
        writer.Write(tag);
        writer.Write(ct);
        recipients.ForEach(p => p.Rsa.Dispose());
    }
}
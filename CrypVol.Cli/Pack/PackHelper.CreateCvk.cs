using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using CrypVol.Lib;
using Konscious.Security.Cryptography;

namespace CrypVol.Cli.Pack;

public static partial class PackHelper
{
    /// <summary>
    ///     根据 PackConfig 生成 .cvk 密钥文件。
    /// </summary>
    private static async Task CreateCvkAsync(PackConfig config, CancellationToken token)
    {
        if (config.Mode is EncryptionMode.None) return;

        byte[] secret = [.. config.Cek, .. config.Salt];
        using var ms = new MemoryStream();
        await using var writer = new BinaryWriter(ms);

        // 写入头
        writer.Write(Encoding.ASCII.GetBytes("KEY0"));
        writer.Write((byte)1); // Version
        // 映射 EncryptionMode → EnvelopeMode 字节值
        writer.Write(config.Mode switch
        {
            EncryptionMode.None => (byte)0,
            EncryptionMode.PlainKey => (byte)0,  // EnvelopeMode.Plain
            EncryptionMode.Password => (byte)1,   // EnvelopeMode.Password
            EncryptionMode.Asymmetric => (byte)2, // EnvelopeMode.PublicKey
            _ => throw new Exception("未知加密模式")
        });

        var payloadLenPos = ms.Position;
        writer.Write(0); // 占位

        switch (config.Mode)
        {
            case EncryptionMode.PlainKey:
                writer.Write(secret);
                break;
            case EncryptionMode.Password:
                WritePasswordPayload(writer, secret, config.Password);
                break;
            case EncryptionMode.Asymmetric:
                WritePublicKeyPayload(writer, secret, config.PublicKey!);
                break;
        }

        // 回填负载长度
        var endPos = ms.Position;
        ms.Seek(payloadLenPos, SeekOrigin.Begin);
        writer.Write(BinaryPrimitives.ReverseEndianness((int)(endPos - payloadLenPos - 4)));
        ms.Seek(endPos, SeekOrigin.Begin);

        // Base64 编码并保存
        var base64 = System.Convert.ToBase64String(ms.ToArray());
        var filePath = Path.Combine(config.KeyOutputDir, $"{config.OutputPrefix}.cvk");
        await File.WriteAllTextAsync(filePath, base64, token);
    }

    private static void WritePasswordPayload(BinaryWriter writer, byte[] secret, string password)
    {
        var argonSalt = RandomNumberGenerator.GetBytes(16);
        const uint time = 3;
        const uint memory = 65536;
        const uint parallelism = 1;

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

    private static void WritePublicKeyPayload(BinaryWriter writer, byte[] secret, IEnumerable<FileInfo> recipientPemFiles)
    {
        var recipients = new List<(string KeyId, RSA Rsa)>();
        foreach (var pemFile in recipientPemFiles)
        {
            var pemContent = File.ReadAllText(pemFile.FullName);
            var rsa = RSA.Create();
            try { rsa.ImportFromPem(pemContent); }
            catch (Exception ex)
            {
                Console.WriteLine($"无法导入公钥文件 '{pemFile.Name}': {ex.Message}");
                continue;
            }

            var keyId = Path.GetFileNameWithoutExtension(pemFile.Name);
            recipients.Add((keyId, rsa));
        }

        if (recipients.Count == 0)
            throw new Exception("至少需要一个接收者公钥");

        var dek = RandomNumberGenerator.GetBytes(32);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[64];
        var tag = new byte[16];

        using var aes = new AesGcm(dek, 16);
        aes.Encrypt(nonce, secret, ciphertext, tag);

        writer.Write(BinaryPrimitives.ReverseEndianness((ushort)recipients.Count));
        foreach (var (keyId, rsa) in recipients)
        {
            var keyIdBytes = Encoding.UTF8.GetBytes(keyId);
            var encryptedDek = rsa.Encrypt(dek, RSAEncryptionPadding.OaepSHA256);

            writer.Write((byte)keyIdBytes.Length);
            writer.Write(keyIdBytes);
            writer.Write(BinaryPrimitives.ReverseEndianness((ushort)encryptedDek.Length));
            writer.Write(encryptedDek);
        }

        writer.Write(nonce);
        writer.Write(tag);
        writer.Write(ciphertext);
        recipients.ForEach(p => p.Rsa.Dispose());
    }
}

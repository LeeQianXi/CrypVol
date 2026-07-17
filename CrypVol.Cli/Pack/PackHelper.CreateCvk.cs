using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using CrypVol.Lib;
using Konscious.Security.Cryptography;

namespace CrypVol.Cli.Pack;

public static partial class PackHelper
{
    private static partial async Task CreateCvkAsync(CancellationToken token)
    {
        if (GlobalConfig.Mode is EncryptionMode.None) return;
        byte[] secret = [.. GlobalConfig.Cek, .. GlobalConfig.Salt];
        using var ms = new MemoryStream();
        await using var writer = new BinaryWriter(ms);
        // 写入头
        writer.Write(Encoding.ASCII.GetBytes("KEY0"));
        writer.Write((byte)1); // Version
        writer.Write((byte)GlobalConfig.Mode);
        var payloadLenPos = ms.Position;
        writer.Write(0); // 占位
        // 2. 根据模式写入负载
        switch (GlobalConfig.Mode)
        {
            case EncryptionMode.PlainKey:
                writer.Write(secret);
                break;
            case EncryptionMode.Password:
                WritePasswordPayload(writer, secret, GlobalConfig.Password);
                break;
            case EncryptionMode.Asymmetric:
                WritePublicKeyPayload(writer, secret, GlobalConfig.PublicKey!);
                break;
        }

        // 3. 回填负载长度
        var endPos = ms.Position;
        ms.Seek(payloadLenPos, SeekOrigin.Begin);
        writer.Write(BinaryPrimitives.ReverseEndianness((int)(endPos - payloadLenPos - 4)));
        ms.Seek(endPos, SeekOrigin.Begin);
        // 4. 编码为 Base64 并保存
        var base64 = Convert.ToBase64String(ms.ToArray());
        var filePath = Path.Combine(GlobalConfig.KeyOutputDir, $"{GlobalConfig.OutputPrefix}.cvk");
        await File.WriteAllTextAsync(filePath, base64, token);
    }

    private static void WritePasswordPayload(BinaryWriter writer, byte[] secret, string password)
    {
        // Argon2id 参数 (生产环境建议 Memory=65536, Time=3, Parallelism=1)
        var argonSalt = RandomNumberGenerator.GetBytes(16);
        uint time = 3;
        uint memory = 65536; // 64 MB
        uint parallelism = 1;
        // 派生 KEK (32字节)
        using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password));
        argon2.Salt = argonSalt;
        argon2.DegreeOfParallelism = (int)parallelism;
        argon2.MemorySize = (int)memory;
        argon2.Iterations = (int)time;
        var kek = argon2.GetBytes(32);
        // AES-GCM 加密 Secret
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[secret.Length];
        ;
        var tag = new byte[16];
        using var aes = new AesGcm(kek, 16);
        aes.Encrypt(nonce, secret, ciphertext, tag);
        // 写入负载
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
            try
            {
                rsa.ImportFromPem(pemContent);
            }
            catch (Exception ex)
            {
                GeneralLog("无法导入公钥文件 '{0}': {1}", pemFile.Name, ex.Message);
                continue;
            }

            // KeyId 使用文件名（不含扩展名），也可改用公钥指纹
            var keyId = Path.GetFileNameWithoutExtension(pemFile.Name);
            recipients.Add((keyId, rsa));
        }

        if (recipients.Count == 0)
            throw new Exception("至少需要一个接收者公钥");
        // 1. 生成随机 DEK (数据加密密钥)
        var dek = RandomNumberGenerator.GetBytes(32);
        // 2. 用 DEK 加密 Secret
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[64];
        var tag = new byte[16];
        using var aes = new AesGcm(dek, 16);
        aes.Encrypt(nonce, secret, ciphertext, tag);
        // 3. 为每个接收者加密 DEK
        writer.Write(BinaryPrimitives.ReverseEndianness((ushort)recipients.Count));
        foreach (var kv in recipients)
        {
            var keyIdBytes = Encoding.UTF8.GetBytes(kv.KeyId);
            var encryptedDek = kv.Rsa.Encrypt(dek, RSAEncryptionPadding.OaepSHA256);

            writer.Write((byte)keyIdBytes.Length);
            writer.Write(keyIdBytes);
            writer.Write(BinaryPrimitives.ReverseEndianness((ushort)encryptedDek.Length));
            writer.Write(encryptedDek);
        }

        // 4. 写入 GCM 参数和密文
        writer.Write(nonce);
        writer.Write(tag);
        writer.Write(ciphertext);
        recipients.ForEach(p => p.Rsa.Dispose());
    }
}
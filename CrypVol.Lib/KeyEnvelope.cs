using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace CrypVol.Lib;

public class KeyEnvelope
{
    /// <summary>
    ///     生成密钥信封并保存为 Base64URL 文本文件
    /// </summary>
    public static void SaveEnvelope(string filePath, EnvelopeMode mode,
        string? password = null,
        Dictionary<string, RSA>? recipients = null)
    {
        // 1. 生成秘密 (CEK + Salt)
        var cek = RandomNumberGenerator.GetBytes(32);
        var salt = RandomNumberGenerator.GetBytes(32);
        var secret = new byte[32 + 32];
        Buffer.BlockCopy(cek, 0, secret, 0, 32);
        Buffer.BlockCopy(salt, 0, secret, 32, 32);

        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);

        // 写入头
        writer.Write(Encoding.ASCII.GetBytes("KEY0"));
        writer.Write((byte)1); // Version
        writer.Write((byte)mode);

        var payloadLenPos = ms.Position;
        writer.Write(0); // 占位

        // 2. 根据模式写入负载
        if (mode == EnvelopeMode.Plain)
            writer.Write(secret);
        else if (mode == EnvelopeMode.Password)
            WritePasswordPayload(writer, secret, password!);
        else if (mode == EnvelopeMode.PublicKey)
            WritePublicKeyPayload(writer, secret, recipients!);

        // 3. 回填负载长度
        var endPos = ms.Position;
        ms.Seek(payloadLenPos, SeekOrigin.Begin);
        writer.Write(BinaryPrimitives.ReverseEndianness((int)(endPos - payloadLenPos - 4)));
        ms.Seek(endPos, SeekOrigin.Begin);

        // 4. 编码为 Base64URL 并保存
        var base64Url = Base64UrlEncode(ms.ToArray());
        File.WriteAllText(filePath, base64Url);
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
        using var aes = new AesGcm(kek);
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

    private static void WritePublicKeyPayload(BinaryWriter writer, byte[] secret, Dictionary<string, RSA> recipients)
    {
        // 1. 生成随机 DEK (数据加密密钥)
        var dek = RandomNumberGenerator.GetBytes(32);

        // 2. 用 DEK 加密 Secret
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[32 + 32];
        var tag = new byte[16];
        using var aes = new AesGcm(dek);
        aes.Encrypt(nonce, secret, ciphertext, tag);

        // 3. 为每个接收者加密 DEK
        writer.Write(BinaryPrimitives.ReverseEndianness((ushort)recipients.Count));
        foreach (var kv in recipients)
        {
            var keyIdBytes = Encoding.UTF8.GetBytes(kv.Key);
            var encryptedDek = kv.Value.Encrypt(dek, RSAEncryptionPadding.OaepSHA256);

            writer.Write((byte)keyIdBytes.Length);
            writer.Write(keyIdBytes);
            writer.Write(BinaryPrimitives.ReverseEndianness((ushort)encryptedDek.Length));
            writer.Write(encryptedDek);
        }

        // 4. 写入 GCM 参数和密文
        writer.Write(nonce);
        writer.Write(tag);
        writer.Write(ciphertext);
    }

    /// <summary>
    ///     解析信封并还原 CEK + Salt
    /// </summary>
    public static (byte[] CEK, byte[] Salt, string RequiredHint) LoadEnvelope(string filePath,
        string? password = null,
        RSA? privateKey = null)
    {
        var data = Base64UrlDecode(File.ReadAllText(filePath));
        using var ms = new MemoryStream(data);
        using var reader = new BinaryReader(ms);

        // 验证头
        if (Encoding.ASCII.GetString(reader.ReadBytes(4)) != "KEY0") throw new Exception("无效的密钥文件");
        if (reader.ReadByte() != 1) throw new Exception("不支持的版本");
        var mode = (EnvelopeMode)reader.ReadByte();
        var payloadLen = BinaryPrimitives.ReverseEndianness(reader.ReadInt32());

        byte[] secret;
        var hint = string.Empty;

        if (mode == EnvelopeMode.Plain)
        {
            secret = reader.ReadBytes(32 + 32);
            hint = "此密钥为明文存储，无需额外输入。";
        }
        else if (mode == EnvelopeMode.Password)
        {
            if (string.IsNullOrEmpty(password))
                throw new Exception("需要提供密码 (Password)");
            secret = DecryptPasswordPayload(reader, password);
            hint = "使用密码解密成功。";
        }
        else if (mode == EnvelopeMode.PublicKey)
        {
            if (privateKey == null)
                throw new Exception("需要提供与 KeyID 匹配的私钥 (RSA PrivateKey)");
            secret = DecryptPublicKeyPayload(reader, privateKey, out var keyIds);
            hint = $"成功使用私钥解密，接收者 KeyID: {string.Join(", ", keyIds)}";
        }
        else
        {
            throw new Exception("未知模式");
        }

        // 拆分结果
        var cek = new byte[32];
        var salt = new byte[32];
        Buffer.BlockCopy(secret, 0, cek, 0, 32);
        Buffer.BlockCopy(secret, 32, salt, 0, 32);
        return (cek, salt, hint);
    }

    private static byte[] DecryptPasswordPayload(BinaryReader reader, string password)
    {
        var argonSalt = reader.ReadBytes(16);
        var time = BinaryPrimitives.ReverseEndianness(reader.ReadUInt32());
        var memory = BinaryPrimitives.ReverseEndianness(reader.ReadUInt32());
        var parallelism = BinaryPrimitives.ReverseEndianness(reader.ReadUInt32());
        var nonce = reader.ReadBytes(12);
        var tag = reader.ReadBytes(16);
        var ciphertext = reader.ReadBytes(32 + 32);

        using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password));
        argon2.Salt = argonSalt;
        argon2.DegreeOfParallelism = (int)parallelism;
        argon2.MemorySize = (int)memory;
        argon2.Iterations = (int)time;
        var kek = argon2.GetBytes(32);

        var plaintext = new byte[32 + 32];
        using var aes = new AesGcm(kek);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        return plaintext;
    }

    private static byte[] DecryptPublicKeyPayload(BinaryReader reader, RSA privateKey, out List<string> keyIds)
    {
        keyIds = new List<string>();
        var count = BinaryPrimitives.ReverseEndianness(reader.ReadUInt16());

        byte[]? dek = null;
        for (var i = 0; i < count; i++)
        {
            int idLen = reader.ReadByte();
            var keyId = Encoding.UTF8.GetString(reader.ReadBytes(idLen));
            keyIds.Add(keyId);

            var encDekLen = BinaryPrimitives.ReverseEndianness(reader.ReadUInt16());
            var encDek = reader.ReadBytes(encDekLen);

            // 尝试用当前私钥解密（如果已提供）
            if (dek == null && privateKey != null)
                try { dek = privateKey.Decrypt(encDek, RSAEncryptionPadding.OaepSHA256); }
                catch
                {
                    /* 不匹配，继续尝试下一个 */
                }
        }

        if (dek == null) throw new Exception("没有匹配的私钥或解密失败");

        var nonce = reader.ReadBytes(12);
        var tag = reader.ReadBytes(16);
        var ciphertext = reader.ReadBytes(32 + 32);

        var plaintext = new byte[32 + 32];
        using var aes = new AesGcm(dek);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        return plaintext;
    }

    // Base64URL 转换 (无填充, 替换 +/ 为 -_)
    private static string Base64UrlEncode(byte[] bytes)
    {
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static byte[] Base64UrlDecode(string base64)
    {
        return Convert.FromBase64String(base64.Replace('-', '+').Replace('_', '/')
            .PadRight(base64.Length + (4 - base64.Length % 4) % 4, '='));
    }
}

public enum EnvelopeMode : byte
{
    Plain = 0x00,
    Password = 0x01,
    PublicKey = 0x02
}
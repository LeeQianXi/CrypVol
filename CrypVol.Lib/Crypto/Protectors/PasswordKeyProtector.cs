using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace CrypVol.Lib.Crypto.Protectors;

/// <summary>负责 Password 保护模式的 Argon2id 派生与 AES-GCM 密钥体编解码。</summary>
internal static class PasswordKeyProtector
{
    private const uint MinMemoryKiB = 8 * 1024;
    private const uint MaxMemoryKiB = 512 * 1024;
    private const uint MaxIterations = 10;
    private const uint MaxParallelism = 16;
    private const uint Iterations = 3;
    private const uint MemoryKiB = 65536;
    private const uint Parallelism = 1;

    /// <summary>生成密码密钥体。</summary>
    public static byte[] Protect(ReadOnlySpan<byte> cek, string? password)
    {
        if (string.IsNullOrWhiteSpace(password)) throw new InvalidOperationException("密码封装模式必须提供密码。");
        var salt = RandomNumberGenerator.GetBytes(16);
        using var argon = CreateKdf(password, salt, Iterations, MemoryKiB, Parallelism);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[cek.Length];
        var tag = new byte[16];
        using var aes = new AesGcm(argon.GetBytes(32), 16);
        aes.Encrypt(nonce, cek, ciphertext, tag);
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream);
        writer.Write(salt);
        WriteUInt32(writer, Iterations);
        WriteUInt32(writer, MemoryKiB);
        WriteUInt32(writer, Parallelism);
        writer.Write(nonce); writer.Write(tag); writer.Write(ciphertext);
        return stream.ToArray();
    }

    /// <summary>解封密码密钥体。</summary>
    public static byte[] Unprotect(ReadOnlySpan<byte> body, string? password)
    {
        if (string.IsNullOrWhiteSpace(password)) throw new InvalidOperationException("密钥受密码保护，请提供密码。");
        if (body.Length < 16 + 12 + 16 + 32 + 12) throw new InvalidDataException("密码密钥体长度不足。");
        var offset = 0;
        var salt = Read(body, ref offset, 16);
        var iterations = ReadUInt32(body, ref offset);
        var memory = ReadUInt32(body, ref offset);
        var parallelism = ReadUInt32(body, ref offset);
        Validate(iterations, memory, parallelism);
        var nonce = Read(body, ref offset, 12);
        var tag = Read(body, ref offset, 16);
        var ciphertext = body[offset..].ToArray();
        if (ciphertext.Length != 32) throw new InvalidDataException("密码密文长度无效。");
        using var argon = CreateKdf(password, salt.ToArray(), iterations, memory, parallelism);
        var cek = new byte[32];
        using var aes = new AesGcm(argon.GetBytes(32), 16);
        aes.Decrypt(nonce.ToArray(), ciphertext, tag.ToArray(), cek);
        return cek;
    }

    private static Argon2id CreateKdf(string password, byte[] salt, uint iterations, uint memory, uint parallelism) =>
        new(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt, Iterations = checked((int)iterations), MemorySize = checked((int)memory),
            DegreeOfParallelism = checked((int)parallelism)
        };

    private static void Validate(uint iterations, uint memory, uint parallelism)
    {
        if (iterations is 0 or > MaxIterations || memory is < MinMemoryKiB or > MaxMemoryKiB ||
            parallelism is 0 or > MaxParallelism)
            throw new InvalidDataException("CVK Argon2 参数超出允许范围。");
    }

    private static void WriteUInt32(BinaryWriter writer, uint value) =>
        writer.Write(BinaryPrimitives.ReverseEndianness(value));

    private static uint ReadUInt32(ReadOnlySpan<byte> data, ref int offset)
    {
        var bytes = Read(data, ref offset, 4);
        return BinaryPrimitives.ReverseEndianness(BinaryPrimitives.ReadUInt32LittleEndian(bytes));
    }

    private static ReadOnlySpan<byte> Read(ReadOnlySpan<byte> data, ref int offset, int count)
    {
        if (count < 0 || offset > data.Length - count) throw new InvalidDataException("密码密钥体字段越界。");
        var value = data.Slice(offset, count); offset += count; return value;
    }
}

using System.Security.Cryptography;
using System.Text;
using CrypVol.Lib.Crypto.Models;
using Konscious.Security.Cryptography;

namespace CrypVol.Lib.Crypto.Cryptography;

/// <summary>Password + PBKDF2-SHA256 处理器。</summary>
public sealed class PasswordPbkdf2Sha256Cryptor : CvkAlgorithmCryptorBase
{
    private const int Iterations = 600_000;
    private const int SaltSize = 16;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private readonly string _password;

    /// <summary>创建密码处理器。</summary>
    public PasswordPbkdf2Sha256Cryptor(string password)
        : base(CvkKeyProtection.Password, CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256)
    {
        if (string.IsNullOrEmpty(password)) throw new ArgumentException("密码不能为空。", nameof(password));
        _password = password;
    }

    protected override ValueTask<ReadOnlyMemory<byte>> ProtectCoreAsync(CvkHeader header, CvkPayload payload,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var key = Rfc2898DeriveBytes.Pbkdf2(_password, salt, Iterations, HashAlgorithmName.SHA256, 32);
        var plain = CvkPayloadCodec.Encode(payload);
        var cipher = new byte[plain.Length];
        var tag = new byte[TagSize];
        using (var aes = new AesGcm(key, TagSize))
        {
            aes.Encrypt(nonce, plain, cipher, tag, CvkPayloadCodec.EncodeHeader(header));
        }

        var result = new byte[1 + SaltSize + NonceSize + TagSize + cipher.Length];
        result[0] = 1;
        salt.CopyTo(result, 1);
        nonce.CopyTo(result, 1 + SaltSize);
        tag.CopyTo(result, 1 + SaltSize + NonceSize);
        cipher.CopyTo(result, 1 + SaltSize + NonceSize + TagSize);
        CryptographicOperations.ZeroMemory(key);
        return ValueTask.FromResult<ReadOnlyMemory<byte>>(result);
    }

    protected override ValueTask<CvkPayload> UnprotectCoreAsync(CvkHeader header, ReadOnlyMemory<byte> keyBody,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var bytes = keyBody.ToArray();
        if (bytes.Length < 1 + SaltSize + NonceSize + TagSize || bytes[0] != 1)
            throw new InvalidDataException("PBKDF2 密钥体格式无效。");
        var salt = bytes.AsSpan(1, SaltSize).ToArray();
        var nonce = bytes.AsSpan(1 + SaltSize, NonceSize).ToArray();
        var tag = bytes.AsSpan(1 + SaltSize + NonceSize, TagSize).ToArray();
        var cipher = bytes[(1 + SaltSize + NonceSize + TagSize)..];
        var key = Rfc2898DeriveBytes.Pbkdf2(_password, salt, Iterations, HashAlgorithmName.SHA256, 32);
        var plain = new byte[cipher.Length];
        try
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(nonce, cipher, tag, plain, CvkPayloadCodec.EncodeHeader(header));
            return ValueTask.FromResult(CvkPayloadCodec.Decode(plain));
        }
        catch (CryptographicException ex) { throw new CryptographicException("密码错误或 CVK 密钥体已损坏。", ex); }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
}

/// <summary>Password + Argon2id 处理器。</summary>
public sealed class PasswordArgon2IdCryptor : CvkAlgorithmCryptorBase
{
    private const int SaltSize = 16;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int MemorySize = 64 * 1024;
    private const int Iterations = 3;
    private readonly byte[] _password;

    /// <summary>创建 Argon2id 密码处理器。</summary>
    public PasswordArgon2IdCryptor(string password)
        : base(CvkKeyProtection.Password, CvkKeyWrapAlgorithm.PasswordArgon2Id)
    {
        if (string.IsNullOrEmpty(password)) throw new ArgumentException("密码不能为空。", nameof(password));
        _password = Encoding.UTF8.GetBytes(password);
    }

    protected override async ValueTask<ReadOnlyMemory<byte>> ProtectCoreAsync(CvkHeader header, CvkPayload payload,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var key = await DeriveAsync(salt, cancellationToken);
        var plain = CvkPayloadCodec.Encode(payload);
        var cipher = new byte[plain.Length];
        var tag = new byte[TagSize];
        using (var aes = new AesGcm(key, TagSize))
        {
            aes.Encrypt(nonce, plain, cipher, tag, CvkPayloadCodec.EncodeHeader(header));
        }

        var result = new byte[1 + SaltSize + NonceSize + TagSize + cipher.Length];
        result[0] = 2;
        salt.CopyTo(result, 1);
        nonce.CopyTo(result, 1 + SaltSize);
        tag.CopyTo(result, 1 + SaltSize + NonceSize);
        cipher.CopyTo(result, 1 + SaltSize + NonceSize + TagSize);
        CryptographicOperations.ZeroMemory(key);
        return result;
    }

    protected override async ValueTask<CvkPayload> UnprotectCoreAsync(CvkHeader header, ReadOnlyMemory<byte> keyBody,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var bytes = keyBody.ToArray();
        if (bytes.Length < 1 + SaltSize + NonceSize + TagSize || bytes[0] != 2)
            throw new InvalidDataException("Argon2id 密钥体格式无效。");
        var salt = bytes.AsSpan(1, SaltSize).ToArray();
        var nonce = bytes.AsSpan(1 + SaltSize, NonceSize).ToArray();
        var tag = bytes.AsSpan(1 + SaltSize + NonceSize, TagSize).ToArray();
        var cipher = bytes[(1 + SaltSize + NonceSize + TagSize)..];
        var key = await DeriveAsync(salt, cancellationToken);
        var plain = new byte[cipher.Length];
        try
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(nonce, cipher, tag, plain, CvkPayloadCodec.EncodeHeader(header));
            return CvkPayloadCodec.Decode(plain);
        }
        catch (CryptographicException ex) { throw new CryptographicException("密码错误或 CVK 密钥体已损坏。", ex); }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    private async Task<byte[]> DeriveAsync(byte[] salt, CancellationToken cancellationToken)
    {
        using var argon = new Argon2id(_password)
        {
            Salt = salt,
            DegreeOfParallelism = Math.Max(1, Math.Min(Environment.ProcessorCount, 4)),
            Iterations = Iterations,
            MemorySize = MemorySize
        };
        var result = await argon.GetBytesAsync(32);
        cancellationToken.ThrowIfCancellationRequested();
        return result;
    }
}
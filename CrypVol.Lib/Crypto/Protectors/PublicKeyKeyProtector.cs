using System.Security.Cryptography;
using CrypVol.Lib.Crypto.Discovery;
using CrypVol.Lib.Crypto.Models;

namespace CrypVol.Lib.Crypto.Protectors;

/// <summary>统一将公钥文件转换为 CVK 公钥密钥体，算法差异仅存在于 DEK 包裹步骤。</summary>
internal static class PublicKeyKeyProtector
{
    /// <summary>从既有和新增公钥文件构建密钥体。</summary>
    public static PublicKeyProtectionResult Protect(EncryptionAlgorithm algorithm, ReadOnlySpan<byte> cek,
        IReadOnlyCollection<CvkPublicKeyRecipient> existingRecipients, IReadOnlyList<FileInfo> newKeyFiles,
        byte[]? existingDek)
    {
        if (algorithm is not (EncryptionAlgorithm.AesGcm or EncryptionAlgorithm.Ecc))
            throw new CvkValidationException("不支持的公钥封装算法。");
        var recipients = existingRecipients.ToDictionary(item => item.KeyId, item => item, StringComparer.Ordinal);
        var dek = existingDek ?? RandomNumberGenerator.GetBytes(32);
        foreach (var file in newKeyFiles)
        {
            var keyId = CvkKeyIdResolver.Resolve(file);
            byte[] encryptedDek;
            if (algorithm == EncryptionAlgorithm.Ecc)
            {
                using var key = EccKeyLoader.LoadPublicKey(File.ReadAllText(file.FullName));
                encryptedDek = EccKeyLoader.WrapDek(key, dek);
            }
            else
            {
                using var key = RsaKeyLoader.LoadPublicKey(File.ReadAllText(file.FullName));
                encryptedDek = key.Encrypt(dek, RSAEncryptionPadding.OaepSHA256);
            }
            recipients[keyId] = new CvkPublicKeyRecipient(keyId, encryptedDek);
        }
        if (recipients.Count == 0)
            throw new CvkValidationException("公钥模式必须提供至少一个公钥接收者。");

        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream);
        PublicKeyKeyBodyCodec.WriteRecipients(writer, recipients.Values.ToList());
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[cek.Length];
        var tag = new byte[16];
        using var aes = new AesGcm(dek, 16);
        aes.Encrypt(nonce, cek, ciphertext, tag);
        writer.Write(nonce); writer.Write(tag); writer.Write(ciphertext);
        return new PublicKeyProtectionResult(stream.ToArray(), recipients.Values.ToList(), dek);
    }
}

/// <summary>公钥保护生成结果。</summary>
internal sealed record PublicKeyProtectionResult(byte[] KeyBody,
    IReadOnlyList<CvkPublicKeyRecipient> Recipients, byte[] Dek);

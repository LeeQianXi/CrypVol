using System.Buffers;
using System.Security.Cryptography;
using CrypVol.Lib.Pipeline;

namespace CrypVol.Lib.Transforms;

/// <summary>块级密钥轮换：旧 CEK 解密 → 新 CEK 加密，不解压</summary>
public sealed class ConvertTransform : IBlockTransform
{
    private readonly byte[] _newCek;
    private readonly byte[] _oldCek;

    public ConvertTransform(byte[] oldCek, byte[] newCek)
    {
        _oldCek = oldCek;
        _newCek = newCek;
    }

    public byte[] Transform(byte[] input, int inputLength, out int outputLength)
    {
        // Step 1: 旧 CEK 解密
        var nonce = input.AsSpan(0, 12);
        var tag = input.AsSpan(inputLength - 16, 16);
        var cipherLen = inputLength - 12 - 16;
        var plaintext = ArrayPool<byte>.Shared.Rent(cipherLen);

        using (var aes = new AesGcm(_oldCek, 16))
        {
            aes.Decrypt(nonce, input.AsSpan(12, cipherLen), tag, plaintext.AsSpan(0, cipherLen));
        }

        // Step 2: 新 CEK 加密
        var newNonce = RandomNumberGenerator.GetBytes(12);
        var newCipher = new byte[cipherLen];
        var newTag = new byte[16];

        using (var aes = new AesGcm(_newCek, 16))
        {
            aes.Encrypt(newNonce, plaintext.AsSpan(0, cipherLen), newCipher, newTag);
        }

        ArrayPool<byte>.Shared.Return(plaintext);

        // 组装: nonce(12) + cipher + tag(16)
        outputLength = 12 + cipherLen + 16;
        var output = ArrayPool<byte>.Shared.Rent(outputLength);
        Buffer.BlockCopy(newNonce, 0, output, 0, 12);
        Buffer.BlockCopy(newCipher, 0, output, 12, cipherLen);
        Buffer.BlockCopy(newTag, 0, output, 12 + cipherLen, 16);
        return output;
    }
}
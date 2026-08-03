using System.Buffers;
using System.Security.Cryptography;
using CrypVol.Lib.Pipeline;

namespace CrypVol.Lib.Transforms;

/// <summary>块级密钥轮换：旧 CEK 解密 → 新 CEK 加密，不解压，保留 CRC32</summary>
public sealed class ConvertTransform : IBlockTransform
{
    private readonly bool _enableCrc32;
    private readonly byte[] _newCek;
    private readonly byte[] _oldCek;

    public ConvertTransform(byte[] oldCek, byte[] newCek, IntegrityLevel integrityLevel = IntegrityLevel.None)
    {
        _oldCek = oldCek;
        _newCek = newCek;
        _enableCrc32 = integrityLevel >= IntegrityLevel.Block;
    }

    public byte[] Transform(byte[] input, int inputLength, out int outputLength)
    {
        // Verify and strip CRC32 if present (last 4 bytes)
        var dataLen = inputLength;
        if (_enableCrc32)
        {
            var expectedCrc = BitConverter.ToUInt32(input, inputLength - 4);
            var actualCrc = Crc32.Compute(input.AsSpan(0, inputLength - 4));
            if (expectedCrc != actualCrc)
                throw new InvalidDataException(
                    $"CRC32 校验失败 (convert): 期望 {expectedCrc:X8}, 实际 {actualCrc:X8}");
            dataLen -= 4;
        }

        // Step 1: 旧 CEK 解密
        var nonce = input.AsSpan(0, 12);
        var tag = input.AsSpan(dataLen - 16, 16);
        var cipherLen = dataLen - 12 - 16;
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

        // 组装: nonce(12) + cipher + tag(16) [+ crc32(4)]
        var crcLen = _enableCrc32 ? 4 : 0;
        outputLength = 12 + cipherLen + 16 + crcLen;
        var output = ArrayPool<byte>.Shared.Rent(outputLength);
        Buffer.BlockCopy(newNonce, 0, output, 0, 12);
        Buffer.BlockCopy(newCipher, 0, output, 12, cipherLen);
        Buffer.BlockCopy(newTag, 0, output, 12 + cipherLen, 16);

        if (_enableCrc32)
        {
            var crc = Crc32.Compute(output.AsSpan(0, outputLength - 4));
            var crcBytes = BitConverter.GetBytes(crc);
            Buffer.BlockCopy(crcBytes, 0, output, outputLength - 4, 4);
        }

        return output;
    }
}
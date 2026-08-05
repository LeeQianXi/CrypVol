using System.Buffers;
using System.IO.Compression;
using System.Security.Cryptography;
using CrypVol.Lib.Pipeline;

namespace CrypVol.Lib.Transforms;

/// <summary>AES-GCM 解密 + GZip 解压 + 块级 CRC32 校验</summary>
public sealed class ExtractTransform : IBlockTransform
{
    private readonly byte[] _cek;
    private readonly bool _compressed;
    private readonly bool _enableCrc32;
    private readonly bool _rescue;

    public ExtractTransform(byte[] cek, bool compressed = false,
        IntegrityLevel integrityLevel = IntegrityLevel.None, bool rescue = false)
    {
        _cek = cek;
        _compressed = compressed;
        _enableCrc32 = integrityLevel >= IntegrityLevel.Block;
        _rescue = rescue;
    }

    public byte[] Transform(byte[] input, int inputLength, out int outputLength)
    {
        // Verify CRC32 if present (last 4 bytes of input)
        if (_enableCrc32)
        {
            var expectedCrc = BitConverter.ToUInt32(input, inputLength - 4);
            var actualCrc = Crc32.Compute(input.AsSpan(0, inputLength - 4));
            if (expectedCrc != actualCrc)
            {
                if (_rescue)
                {
                    // Return zero-filled output matching expected plaintext size
                    outputLength = inputLength - 12 - 16 - 4;
                    var zero = ArrayPool<byte>.Shared.Rent(outputLength);
                    Array.Clear(zero, 0, outputLength);
                    return zero;
                }

                throw new InvalidDataException(
                    $"CRC32 校验失败: 期望 {expectedCrc:X8}, 实际 {actualCrc:X8}");
            }

            inputLength -= 4; // strip CRC32 for decryption
        }

        var nonce = input.AsSpan(0, 12);
        var tag = input.AsSpan(inputLength - 16, 16);
        var cipherLen = inputLength - 12 - 16;
        byte[]? plaintext = null;

        try
        {
            plaintext = ArrayPool<byte>.Shared.Rent(cipherLen);
            using var aes = new AesGcm(_cek, 16);
            aes.Decrypt(nonce, input.AsSpan(12, cipherLen), tag, plaintext.AsSpan(0, cipherLen));

            if (_compressed)
            {
                using var compressed = new MemoryStream(plaintext, 0, cipherLen);
                using var gz = new GZipStream(compressed, CompressionMode.Decompress);
                using var decompressed = new MemoryStream();
                gz.CopyTo(decompressed);
                ArrayPool<byte>.Shared.Return(plaintext);
                var decompLen = (int)decompressed.Length;
                var result = ArrayPool<byte>.Shared.Rent(decompLen);
                Buffer.BlockCopy(decompressed.GetBuffer(), 0, result, 0, decompLen);
                outputLength = decompLen;
                return result;
            }

            outputLength = cipherLen;
            return plaintext;
        }
        catch (CryptographicException) when (_rescue)
        {
            if (plaintext is not null) ArrayPool<byte>.Shared.Return(plaintext);
            outputLength = cipherLen;
            var zero = ArrayPool<byte>.Shared.Rent(outputLength);
            Array.Clear(zero, 0, outputLength);
            return zero;
        }
    }
}
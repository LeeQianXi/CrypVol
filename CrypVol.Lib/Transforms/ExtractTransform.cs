using System.Buffers;
using System.IO.Compression;
using System.Security.Cryptography;
using CrypVol.Lib.Pipeline;

namespace CrypVol.Lib.Transforms;

/// <summary>AES-GCM 解密 + GZip 解压</summary>
public sealed class ExtractTransform : IBlockTransform
{
    private readonly byte[] _cek;
    private readonly bool _compressed;

    public ExtractTransform(byte[] cek, bool compressed)
    {
        _cek = cek;
        _compressed = compressed;
    }

    public byte[] Transform(byte[] input, int inputLength, out int outputLength)
    {
        var nonce = input.AsSpan(0, 12);
        var tag = input.AsSpan(inputLength - 16, 16);
        var cipherLen = inputLength - 12 - 16;
        var plaintext = ArrayPool<byte>.Shared.Rent(cipherLen);

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
}
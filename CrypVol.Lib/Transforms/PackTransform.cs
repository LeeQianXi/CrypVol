using System.Buffers;
using System.IO.Compression;
using System.Security.Cryptography;
using CrypVol.Lib.Pipeline;

namespace CrypVol.Lib.Transforms;

/// <summary>GZip 压缩 + AES-GCM 加密</summary>
public sealed class PackTransform : IBlockTransform
{
    private readonly byte[] _cek;
    private readonly CompressionLevel _compressionLevel;
    private readonly bool _enableCompression;

    public PackTransform(byte[] cek, bool enableCompression, int compressionLevel)
    {
        _cek = cek;
        _enableCompression = enableCompression;
        _compressionLevel = compressionLevel switch
        {
            0 => CompressionLevel.NoCompression,
            <= 3 => CompressionLevel.Fastest,
            <= 6 => CompressionLevel.Optimal,
            _ => CompressionLevel.SmallestSize
        };
    }

    public byte[] Transform(byte[] input, int originalLength, out int outputLength)
    {
        ReadOnlySpan<byte> toEncrypt;
        int preLen;

        if (_enableCompression)
        {
            using var compressed = new MemoryStream();
            using (var gz = new GZipStream(compressed, _compressionLevel, true))
            {
                gz.Write(input, 0, originalLength);
            }

            compressed.Position = 0;
            var cd = compressed.ToArray();
            toEncrypt = cd;
            preLen = cd.Length;
        }
        else
        {
            toEncrypt = input.AsSpan(0, originalLength);
            preLen = originalLength;
        }

        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[preLen];
        var tag = new byte[16];

        using var aes = new AesGcm(_cek, 16);
        aes.Encrypt(nonce, toEncrypt, ciphertext, tag);

        outputLength = 12 + ciphertext.Length + 16;
        var output = ArrayPool<byte>.Shared.Rent(outputLength);
        Buffer.BlockCopy(nonce, 0, output, 0, 12);
        Buffer.BlockCopy(ciphertext, 0, output, 12, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, output, 12 + ciphertext.Length, 16);
        return output;
    }
}
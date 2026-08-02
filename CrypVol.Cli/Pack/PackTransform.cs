using System.Buffers;
using System.IO.Compression;
using System.Security.Cryptography;
using CrypVol.Cli.Pipeline;

namespace CrypVol.Cli.Pack;

/// <summary>
///     pack 专用变换：GZip 压缩 + AES-GCM 加密。
/// </summary>
public sealed class PackTransform : IBlockTransform
{
    private readonly byte[] _cek; // 32 字节 CEK
    private readonly bool _enableCompression;
    private readonly CompressionLevel _compressionLevel;

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
        // Step 1: 压缩（可选）
        ReadOnlySpan<byte> toEncrypt;
        int preLen;

        if (_enableCompression)
        {
            using var compressed = new MemoryStream();
            using (var gz = new GZipStream(compressed, _compressionLevel, leaveOpen: true))
                gz.Write(input, 0, originalLength);

            // GZipStream 需要显式关闭才能刷新尾部
            compressed.Position = 0;
            var compressedData = compressed.ToArray();
            toEncrypt = compressedData;
            preLen = compressedData.Length;
        }
        else
        {
            toEncrypt = input.AsSpan(0, originalLength);
            preLen = originalLength;
        }

        // Step 2: AES-GCM 加密 (12B nonce + ciphertext + 16B tag)
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[preLen];
        var tag = new byte[16];

        using var aes = new AesGcm(_cek, 16);
        aes.Encrypt(nonce, toEncrypt, ciphertext, tag);

        // 组装输出: nonce(12) + ciphertext + tag(16)
        outputLength = 12 + ciphertext.Length + 16;
        var output = ArrayPool<byte>.Shared.Rent(outputLength);
        Buffer.BlockCopy(nonce, 0, output, 0, 12);
        Buffer.BlockCopy(ciphertext, 0, output, 12, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, output, 12 + ciphertext.Length, 16);

        return output;
    }
}

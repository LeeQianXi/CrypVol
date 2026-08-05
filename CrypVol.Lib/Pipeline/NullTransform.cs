using System.Buffers;
using System.IO.Compression;

namespace CrypVol.Lib.Pipeline;

/// <summary>
///     明文变换：Pack 时可选 GZip 压缩，Extract 时按需 GZip 解压。
///     注意：Transform 不负责归还 input 数组——由管线 RawBlock.Dispose() 统一处理。
/// </summary>
public sealed class NullTransform : IBlockTransform
{
    private readonly CompressionLevel _compressionLevel;
    private readonly bool _extractDecompress;
    private readonly bool _packCompress;

    /// <summary>Pack 模式：可选压缩</summary>
    public NullTransform(bool enableCompression = false, int compressionLevel = 6)
    {
        _packCompress = enableCompression;
        _compressionLevel = compressionLevel switch
        {
            0 => CompressionLevel.NoCompression,
            <= 3 => CompressionLevel.Fastest,
            <= 6 => CompressionLevel.Optimal,
            _ => CompressionLevel.SmallestSize
        };
    }

    private NullTransform(bool extractDecompress)
    {
        _extractDecompress = extractDecompress;
    }

    public byte[] Transform(byte[] input, int originalLength, out int outputLength)
    {
        if (_extractDecompress)
            return Decompress(input, originalLength, out outputLength);
        if (_packCompress)
            return Compress(input, originalLength, out outputLength);

        var passthrough = ArrayPool<byte>.Shared.Rent(originalLength);
        Buffer.BlockCopy(input, 0, passthrough, 0, originalLength);
        outputLength = originalLength;
        return passthrough;
    }

    /// <summary>Extract 模式，按需解压</summary>
    public static NullTransform ForExtract(bool compressed)
    {
        return new NullTransform(compressed);
    }

    private byte[] Compress(byte[] input, int originalLength, out int outputLength)
    {
        using var compressed = new MemoryStream();
        using (var gz = new GZipStream(compressed, _compressionLevel, true))
        {
            gz.Write(input, 0, originalLength);
        }

        compressed.Position = 0;
        var cd = compressed.ToArray();
        outputLength = cd.Length;
        var output = ArrayPool<byte>.Shared.Rent(outputLength);
        Buffer.BlockCopy(cd, 0, output, 0, outputLength);
        return output;
    }

    private static byte[] Decompress(byte[] input, int length, out int outputLength)
    {
        using var compressed = new MemoryStream(input, 0, length);
        using var gz = new GZipStream(compressed, CompressionMode.Decompress);
        using var decompressed = new MemoryStream();
        gz.CopyTo(decompressed);
        outputLength = (int)decompressed.Length;
        var result = ArrayPool<byte>.Shared.Rent(outputLength);
        Buffer.BlockCopy(decompressed.GetBuffer(), 0, result, 0, outputLength);
        return result;
    }
}
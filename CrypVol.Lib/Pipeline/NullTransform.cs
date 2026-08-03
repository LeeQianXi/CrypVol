using System.Buffers;

namespace CrypVol.Lib.Pipeline;

/// <summary>
///     空变换：数据原样透传（用于 None 模式，不加密不压缩）。
/// </summary>
public sealed class NullTransform : IBlockTransform
{
    public byte[] Transform(byte[] input, int originalLength, out int outputLength)
    {
        // 直接归还输入，返回新租借的相同数据
        var output = ArrayPool<byte>.Shared.Rent(originalLength);
        Buffer.BlockCopy(input, 0, output, 0, originalLength);
        outputLength = originalLength;
        ArrayPool<byte>.Shared.Return(input);
        return output;
    }
}
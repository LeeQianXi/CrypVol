using System.Buffers;

namespace CrypVol.Cli.Pipeline;

/// <summary>
///     可插拔的块变换。不同子命令提供不同实现：
///     pack:   压缩 + 加密
///     extract:解密 + 解压
///     convert:解密 + 加密
/// </summary>
public interface IBlockTransform
{
    /// <summary>
    ///     变换数据块。输入和输出均来自 ArrayPool，调用者负责归还输入块。
    /// </summary>
    /// <param name="input">输入数据（ArrayPool 租借，由调用者归还）</param>
    /// <param name="originalLength">变换前原始数据长度</param>
    /// <param name="outputLength">变换后数据长度</param>
    /// <returns>变换后的数据（ArrayPool 租借，调用者负责归还）</returns>
    byte[] Transform(byte[] input, int originalLength, out int outputLength);
}

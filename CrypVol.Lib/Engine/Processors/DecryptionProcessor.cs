using System.Buffers;
using System.Security.Cryptography;
using CrypVol.Lib.Engine.Models;

namespace CrypVol.Lib.Engine.Processors;

/// <summary>仅负责校验可选 CRC32 并使用 AES-GCM 解密数据块。</summary>
public sealed class DecryptionProcessor : DataProcessorBase
{
    private readonly ReadOnlyMemory<byte> _cek;
    private readonly bool _rescue;

    /// <summary>创建解密处理器。</summary>
    /// <param name="cek">内容加密密钥。</param>
    /// <param name="rescue">校验或解密失败时是否输出零填充数据。</param>
    public DecryptionProcessor(ReadOnlyMemory<byte> cek, bool rescue = false)
    {
        if (cek.Length != 32) throw new ArgumentException("CEK 必须是 32 字节。", nameof(cek));
        _cek = cek.ToArray();
        _rescue = rescue;
    }

    /// <inheritdoc />
    protected override ValueTask<DataBlock?> ProcessBlockAsync(DataBlock block,
        CancellationToken cancellationToken = default)
    {
        var length = block.Length;
        var cipherLength = length - 12 - 16;
        var buffer = ArrayPool<byte>.Shared.Rent(cipherLength);
        try
        {
            using var aes = new AesGcm(_cek.Span, 16);
            aes.Decrypt(block.Buffer.AsSpan(0, 12), block.Buffer.AsSpan(12, cipherLength),
                block.Buffer.AsSpan(length - 16, 16), buffer.AsSpan(0, cipherLength));
            return ValueTask.FromResult<DataBlock?>(new DataBlock(buffer, cipherLength, block.Metadata));
        }
        catch (CryptographicException) when (_rescue)
        {
            ArrayPool<byte>.Shared.Return(buffer);
            return ValueTask.FromResult<DataBlock?>(CreateZeroBlock(block, cipherLength));
        }
    }

    private static DataBlock CreateZeroBlock(DataBlock input, int length)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(length);
        Array.Clear(buffer, 0, length);
        return new DataBlock(buffer, length, input.Metadata);
    }
}

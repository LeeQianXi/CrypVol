using System.Buffers;
using System.Security.Cryptography;
using CrypVol.Lib.Engine.Models;
using CrypVol.Lib.Utility;

namespace CrypVol.Lib.Engine.Processors;

/// <summary>仅负责校验可选 CRC32 并使用 AES-GCM 解密数据块。</summary>
public sealed class DecryptionProcessor : DataProcessorBase
{
    private readonly byte[] _cek;
    private readonly bool _enableCrc32;
    private readonly bool _rescue;

    /// <summary>创建解密处理器。</summary>
    /// <param name="cek">内容加密密钥。</param>
    /// <param name="integrityLevel">完整性级别。</param>
    /// <param name="rescue">校验或解密失败时是否输出零填充数据。</param>
    public DecryptionProcessor(byte[] cek, IntegrityLevel integrityLevel = IntegrityLevel.None, bool rescue = false)
    {
        _cek = cek ?? throw new ArgumentNullException(nameof(cek));
        _enableCrc32 = integrityLevel >= IntegrityLevel.Block;
        _rescue = rescue;
    }

    /// <inheritdoc />
    protected override ValueTask<DataBlock?> ProcessBlockAsync(DataBlock block,
        CancellationToken cancellationToken = default)
    {
        var length = block.Length;
        if (_enableCrc32)
        {
            var expected = BitConverter.ToUInt32(block.Buffer, length - 4);
            var actual = Crc32.Compute(block.Buffer.AsSpan(0, length - 4));
            if (expected != actual)
            {
                if (!_rescue) throw new InvalidDataException($"CRC32 校验失败: 期望 {expected:X8}, 实际 {actual:X8}");
                return ValueTask.FromResult<DataBlock?>(CreateZeroBlock(block, length - 32));
            }

            length -= 4;
        }

        var cipherLength = length - 12 - 16;
        var buffer = ArrayPool<byte>.Shared.Rent(cipherLength);
        try
        {
            using var aes = new AesGcm(_cek, 16);
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
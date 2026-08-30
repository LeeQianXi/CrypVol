using System.Buffers;
using System.Security.Cryptography;
using CrypVol.Lib.Engine.Models;

namespace CrypVol.Lib.Engine.Processors;

/// <summary>仅负责使用 AES-GCM 加密数据块并附加可选 CRC32。</summary>
public sealed class EncryptionProcessor : DataProcessorBase
{
    private readonly byte[] _cek;
    private readonly bool _enableCrc32;

    /// <summary>创建加密处理器。</summary>
    /// <param name="cek">内容加密密钥。</param>
    /// <param name="integrityLevel">完整性级别。</param>
    public EncryptionProcessor(byte[] cek, IntegrityLevel integrityLevel = IntegrityLevel.None)
    {
        _cek = cek ?? throw new ArgumentNullException(nameof(cek));
        _enableCrc32 = integrityLevel >= IntegrityLevel.Block;
    }

    /// <inheritdoc />
    protected override ValueTask<DataBlock?> ProcessBlockAsync(DataBlock block,
        CancellationToken cancellationToken = default)
    {
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[block.Length];
        var tag = new byte[16];
        using var aes = new AesGcm(_cek, 16);
        aes.Encrypt(nonce, block.Data.Span, ciphertext, tag);

        var crcLength = _enableCrc32 ? 4 : 0;
        var length = nonce.Length + ciphertext.Length + tag.Length + crcLength;
        var buffer = ArrayPool<byte>.Shared.Rent(length);
        Buffer.BlockCopy(nonce, 0, buffer, 0, nonce.Length);
        Buffer.BlockCopy(ciphertext, 0, buffer, nonce.Length, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, buffer, nonce.Length + ciphertext.Length, tag.Length);
        if (_enableCrc32)
            BitConverter.GetBytes(Crc32.Compute(buffer.AsSpan(0, length - 4))).CopyTo(buffer, length - 4);
        return ValueTask.FromResult<DataBlock?>(new DataBlock(buffer, length, block.Metadata));
    }
}
using System.Buffers;
using System.Security.Cryptography;
using CrypVol.Lib.Engine.Models;

namespace CrypVol.Lib.Engine.Processors;

/// <summary>仅负责使用 AES-GCM 加密数据块并附加可选 CRC32。</summary>
public sealed class EncryptionProcessor : DataProcessorBase
{
    private readonly byte[] _cek;

    /// <summary>创建加密处理器。</summary>
    /// <param name="cek">内容加密密钥。</param>
    public EncryptionProcessor(byte[] cek)
    {
        _cek = cek ?? throw new ArgumentNullException(nameof(cek));
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

        var length = nonce.Length + ciphertext.Length + tag.Length;
        var buffer = ArrayPool<byte>.Shared.Rent(length);
        Buffer.BlockCopy(nonce, 0, buffer, 0, nonce.Length);
        Buffer.BlockCopy(ciphertext, 0, buffer, nonce.Length, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, buffer, nonce.Length + ciphertext.Length, tag.Length);
        return ValueTask.FromResult<DataBlock?>(new DataBlock(buffer, length, block.Metadata));
    }
}
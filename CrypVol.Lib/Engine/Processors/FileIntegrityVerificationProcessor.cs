using System.Buffers;
using System.Security.Cryptography;
using CrypVol.Lib.Engine.Models;
using CrypVol.Lib.Volume;

namespace CrypVol.Lib.Engine.Processors;

/// <summary>在解密与解压后的原始文件数据上验证 File 级 SHA-256 摘要。</summary>
public sealed class FileIntegrityVerificationProcessor : DataProcessorBase
{
    /// <summary>Engine 记录中保存 File 摘要失败路径的名称。</summary>
    public const string FailuresRecordName = "file-integrity-failures";

    private readonly bool _continueOnFailure;
    private readonly Dictionary<string, IncrementalHash> _hashes = new(StringComparer.Ordinal);

    /// <summary>创建 File 级摘要验证处理器。</summary>
    /// <param name="continueOnFailure">为 <see langword="true" /> 时记录失败并继续处理后续文件。</param>
    public FileIntegrityVerificationProcessor(bool continueOnFailure = false)
    {
        _continueOnFailure = continueOnFailure;
    }

    /// <inheritdoc />
    protected override Task OnInitializeAsync(CancellationToken cancellationToken = default)
    {
        if (_continueOnFailure)
            Engine.SetRecord(FailuresRecordName, new List<string>());
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    protected override ValueTask<DataBlock?> ProcessBlockAsync(DataBlock block,
        CancellationToken cancellationToken = default)
    {
        var path = block.Metadata.RelativePath;
        if (!_hashes.TryGetValue(path, out var hash))
            _hashes[path] = hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(block.Data.Span);

        if (IsLastFileBlock(block.Metadata))
        {
            var expected = block.Metadata.FileHash ?? throw new InvalidDataException("文件末块缺少 SHA-256 摘要。");
            var actual = hash.GetHashAndReset();
            _hashes.Remove(path);
            hash.Dispose();
            if (!CryptographicOperations.FixedTimeEquals(expected, actual))
            {
                var error = new InvalidDataException($"文件 SHA-256 校验失败: {path}");
                if (!_continueOnFailure) throw error;
                if (!Engine.TryGetRecord<List<string>>(FailuresRecordName, out var failures) || failures is null)
                    throw new InvalidOperationException("File 完整性失败记录未初始化。", error);
                failures.Add(path);
                Engine.LogWarning("文件 SHA-256 校验失败: {Path}", path);
            }
        }

        var buffer = ArrayPool<byte>.Shared.Rent(block.Length);
        block.Data.CopyTo(buffer);
        return ValueTask.FromResult<DataBlock?>(new DataBlock(buffer, block.Length, block.Metadata));
    }

    /// <inheritdoc />
    public override Task DisposeAsync(CancellationToken cancellationToken = default)
    {
        foreach (var hash in _hashes.Values) hash.Dispose();
        _hashes.Clear();
        return Task.CompletedTask;
    }

    /// <summary>判断数据块是否为一个文件的最后一个块。</summary>
    private static bool IsLastFileBlock(BlockMetadata metadata)
    {
        return (metadata.Flags & 3) is (byte)FileEntryHeaderFlagsEnum.Full or (byte)FileEntryHeaderFlagsEnum.CrossTail;
    }
}
using System.Buffers;
using CrypVol.Lib.Pipeline;
using Microsoft.Extensions.Logging;

namespace CrypVol.Lib.IO.Sources;

/// <summary>
///     带状态的源文件读取器，跨连续块缓存 FileStream。
///     同一文件的连续块复用打开的句柄，避免重复打开/关闭的开销。
/// </summary>
public sealed class FileSourceReader : IDisposable
{
    private FileStream? _openFs;
    private string? _openPath;

    public void Dispose()
    {
        _openFs?.Dispose();
        _openFs = null;
        _openPath = null;
    }

    public async Task<RawBlock?> ReadAsync(WorkItem item, CancellationToken token, ILogger? logger = null)
    {
        if (item.Length == 0)
        {
            var empty = ArrayPool<byte>.Shared.Rent(0);
            return new RawBlock
            {
                Work = item,
                Data = empty,
                DataLength = 0
            };
        }

        // 仅在路径变化时重新打开
        if (item.SourceFullPath != _openPath)
        {
            _openFs?.Dispose();
            _openFs = File.OpenRead(item.SourceFullPath);
            _openPath = item.SourceFullPath;
        }

        var array = ArrayPool<byte>.Shared.Rent(item.Length);
        try
        {
            _openFs!.Position = item.SourceOffset;
            var read = await _openFs.ReadAsync(array.AsMemory(0, item.Length), token);
            logger?.LogTrace("文件读: {Path}@{Offset:X} {Bytes}字节",
                item.RelativePath, item.SourceOffset, read);
            return new RawBlock
            {
                Work = item,
                Data = array,
                DataLength = read
            };
        }
        catch
        {
            ArrayPool<byte>.Shared.Return(array);
            throw;
        }
    }
}
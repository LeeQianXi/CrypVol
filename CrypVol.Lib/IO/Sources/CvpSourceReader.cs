using System.Buffers;
using CrypVol.Lib.Pipeline;
using Microsoft.Extensions.Logging;

namespace CrypVol.Lib.IO.Sources;

/// <summary>
///     带状态的 .cvp 源读取器，跨连续块缓存 FileStream。
///     同一文件的连续块复用打开的句柄，避免重复打开/关闭的开销。
/// </summary>
public sealed class CvpSourceReader : IDisposable
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
        // 仅在路径变化时重新打开
        if (item.SourceFullPath != _openPath)
        {
            _openFs?.Dispose();
            _openFs = File.OpenRead(item.SourceFullPath);
            _openPath = item.SourceFullPath;
        }

        var buf = ArrayPool<byte>.Shared.Rent(item.Length);
        try
        {
            _openFs!.Position = item.SourceOffset;
            var read = await _openFs.ReadAsync(buf.AsMemory(0, item.Length), token);
            logger?.LogTrace("CVP读: {Path}#{Seq} offset={Offset:X} {Bytes}字节",
                item.RelativePath, item.Sequence, item.SourceOffset, read);
            return new RawBlock
            {
                Work = item,
                Data = buf,
                DataLength = read
            };
        }
        catch
        {
            ArrayPool<byte>.Shared.Return(buf);
            throw;
        }
    }
}
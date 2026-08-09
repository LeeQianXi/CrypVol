using System.Buffers;
using CrypVol.Lib.Pipeline;
using Microsoft.Extensions.Logging;

namespace CrypVol.Lib.IO.Sources;

/// <summary>从文件系统读取原始数据块</summary>
public static class FileSource
{
    public static async Task<RawBlock?> ReadAsync(WorkItem item, CancellationToken token, ILogger? logger = null)
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

        var array = ArrayPool<byte>.Shared.Rent(item.Length);
        try
        {
            await using var fs = File.OpenRead(item.SourceFullPath);
            fs.Position = item.SourceOffset;
            var read = await fs.ReadAsync(array.AsMemory(0, item.Length), token);
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

using System.Buffers;
using CrypVol.Lib.Pipeline;
using Microsoft.Extensions.Logging;

namespace CrypVol.Lib.IO.Sources;

/// <summary>从 .cvp 文件读取加密数据块</summary>
public static class CvpSource
{
    public static ILogger? Logger { get; set; }

    public static async Task<RawBlock?> ReadAsync(WorkItem item, CancellationToken token)
    {
        var buf = ArrayPool<byte>.Shared.Rent(item.Length);
        try
        {
            await using var fs = File.OpenRead(item.SourceFullPath);
            fs.Position = item.SourceOffset;
            var read = await fs.ReadAsync(buf.AsMemory(0, item.Length), token);
            Logger?.LogTrace("CVP读: {Path}#{Seq} offset={Offset:X} {Bytes}字节",
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

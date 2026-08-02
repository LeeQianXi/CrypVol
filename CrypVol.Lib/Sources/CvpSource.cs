using System.Buffers;
using CrypVol.Lib.Pipeline;

namespace CrypVol.Lib.Sources;

/// <summary>从 .cvp 文件读取加密数据块</summary>
public static class CvpSource
{
    public static async Task<RawBlock?> ReadAsync(WorkItem item, CancellationToken token)
    {
        var buf = ArrayPool<byte>.Shared.Rent(item.Length);
        try
        {
            await using var fs = File.OpenRead(item.SourceFullPath);
            fs.Position = item.SourceOffset;
            var read = await fs.ReadAsync(buf.AsMemory(0, item.Length), token);
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
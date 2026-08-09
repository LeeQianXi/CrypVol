using CrypVol.Lib.Pipeline;
using Microsoft.Extensions.Logging;

namespace CrypVol.Lib.IO.Sinks;

/// <summary>有序写入还原文件</summary>
public static class FileSink
{
    public static ILogger? Logger { get; set; }

    public static async Task WriteAsync(string outputDir, bool overwrite, VolumeContext ctx, CancellationToken token)
    {
        var fullPath = ctx.OutputPath;
        if (!overwrite && File.Exists(fullPath))
        {
            Logger?.LogInformation("文件已存在，跳过: {Path}", fullPath);
            await foreach (var block in ctx.OutputChannel.Reader.ReadAllAsync(token))
                block.Dispose();
            return;
        }

        var dir = Path.GetDirectoryName(fullPath);
        if (dir is not null) Directory.CreateDirectory(dir);

        FileStream? fs = null;
        try
        {
            long pos = 0;
            var totalBytes = 0L;
            await foreach (var block in ctx.OutputChannel.Reader.ReadAllAsync(token))
            {
                if (fs is null)
                {
                    fs = new FileStream(fullPath, FileMode.Create, FileAccess.Write,
                        FileShare.None, 4096 * 16, FileOptions.SequentialScan);
                    Logger?.LogTrace("创建文件: {Path}", fullPath);
                }

                fs.Position = pos;
                await fs.WriteAsync(block.Data.AsMemory(0, block.OutputLength), token);
                totalBytes += block.OutputLength;
                pos += block.OutputLength;
                block.Dispose();
            }

            Logger?.LogTrace("文件写入完成: {Path} {Bytes}字节", fullPath, totalBytes);
        }
        finally
        {
            if (fs is not null) await fs.DisposeAsync();
        }
    }
}

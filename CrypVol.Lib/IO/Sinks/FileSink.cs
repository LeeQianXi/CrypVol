using CrypVol.Lib.Pipeline;

namespace CrypVol.Lib.IO.Sinks;

/// <summary>有序写入还原文件</summary>
public static class FileSink
{
    public static async Task WriteAsync(string outputDir, bool overwrite, VolumeContext ctx, CancellationToken token)
    {
        var fullPath = ctx.OutputPath;
        if (!overwrite && File.Exists(fullPath))
        {
            await foreach (var _ in ctx.OutputChannel.Reader.ReadAllAsync(token)) { }

            return;
        }

        var dir = Path.GetDirectoryName(fullPath);
        if (dir is not null) Directory.CreateDirectory(dir);

        await using var fs = new FileStream(fullPath, FileMode.Create, FileAccess.Write,
            FileShare.None, 4096 * 16, FileOptions.SequentialScan);

        long pos = 0;
        await foreach (var block in ctx.OutputChannel.Reader.ReadAllAsync(token))
        {
            fs.Position = pos;
            await fs.WriteAsync(block.Data.AsMemory(0, block.OutputLength), token);
            pos += block.OutputLength;
            block.Dispose();
        }
    }
}
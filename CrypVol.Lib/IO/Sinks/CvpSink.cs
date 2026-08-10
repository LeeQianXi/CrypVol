using System.Text;
using CrypVol.Lib.Pipeline;
using CrypVol.Lib.Volume;
using Microsoft.Extensions.Logging;

namespace CrypVol.Lib.IO.Sinks;

/// <summary>有序写入 .cvp 卷文件。cek 非 null 时加密文件头。</summary>
public static class CvpSink
{
    public static async Task WriteAsync(VolumeContext ctx, byte[]? cek, CancellationToken token,
        ILogger? logger = null)
    {
        FileStream? fs = null;
        try
        {
            long pos = 0;
            var totalBlocks = 0;

            await foreach (var block in ctx.OutputChannel.Reader.ReadAllAsync(token))
            {
                if (fs is null)
                {
                    fs = new FileStream(ctx.OutputPath, FileMode.Create, FileAccess.Write,
                        FileShare.None, 4096 * 16, FileOptions.SequentialScan);
                    logger?.LogTrace("创建卷: {Path}", ctx.OutputPath);
                }

                if (block.Work.IsFirstFragment)
                {
                    var header = new FileEntryHeader
                    {
                        FileId = Fnv1AHash64(block.Work.RelativePath),
                        Flags = block.Work.Flags,
                        FragmentIndex = (uint)block.Work.Sequence,
                        SizeOrTotal = block.Work.TotalFileSize
                    };
                    header.SetFilePath(block.Work.RelativePath);

                    var headerBytes = cek is not null
                        ? FileEntryHeader.Encrypt(header, cek)
                        : header.ToBytes();

                    fs.Position = pos;
                    await fs.WriteAsync(headerBytes, token);
                    pos += headerBytes.Length;
                    logger?.LogTrace("卷头: {Path} ({HeaderType})", block.Work.RelativePath,
                        cek is not null ? "CVPE加密" : "CVPH明文");
                }

                var len = BitConverter.GetBytes(block.OutputLength);
                fs.Position = pos;
                await fs.WriteAsync(len, token);
                await fs.WriteAsync(block.Data.AsMemory(0, block.OutputLength), token);
                totalBlocks++;
                pos += 4 + block.OutputLength;
                block.Dispose();
            }

            logger?.LogTrace("卷写入完成: {Path} {Blocks}块 {Bytes}字节",
                ctx.OutputPath, totalBlocks, pos);
        }
        finally
        {
            if (fs is not null) await fs.DisposeAsync();
        }
    }

    private static ulong Fnv1AHash64(string input)
    {
        const ulong basis = 14695981039346656037ul;
        const ulong prime = 1099511628211ul;
        var hash = basis;
        foreach (var b in Encoding.UTF8.GetBytes(input))
        {
            hash ^= b;
            hash *= prime;
        }

        return hash;
    }
}
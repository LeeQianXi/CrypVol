using System.Text;
using CrypVol.Lib.Pipeline;
using CrypVol.Lib.Volume;

namespace CrypVol.Lib.IO.Sinks;

/// <summary>有序写入 .cvp 卷文件。cek 非 null 时加密文件头。</summary>
public static class CvpSink
{
    public static async Task WriteAsync(VolumeContext ctx, byte[]? cek, CancellationToken token)
    {
        await using var fs = new FileStream(ctx.OutputPath, FileMode.Create, FileAccess.Write,
            FileShare.None, 4096 * 16, FileOptions.SequentialScan);

        long pos = 0;

        await foreach (var block in ctx.OutputChannel.Reader.ReadAllAsync(token))
        {
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
            }

            var len = BitConverter.GetBytes(block.OutputLength);
            fs.Position = pos;
            await fs.WriteAsync(len, token);
            await fs.WriteAsync(block.Data.AsMemory(0, block.OutputLength), token);
            pos += 4 + block.OutputLength;
            block.Dispose();
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
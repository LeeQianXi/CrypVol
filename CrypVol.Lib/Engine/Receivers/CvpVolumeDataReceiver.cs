using System.Text;
using CrypVol.Lib.Volume;

namespace CrypVol.Lib.Engine.Receivers;

/// <summary>将处理后的数据块写入 CVP 卷的接收阶段。</summary>
public sealed class CvpFileReciver : VolumeDataReceiverBase
{
    private readonly byte[]? _cek;

    /// <summary>创建 CVP 卷接收阶段。</summary>
    /// <param name="cek">加密卷头所用 CEK；明文卷传 <see langword="null" />。</param>
    public CvpFileReciver(byte[]? cek)
    {
        _cek = cek;
    }

    /// <inheritdoc />
    protected override async Task ReceiveVolumeAsync(VolumeContext context, CancellationToken cancellationToken)
    {
        FileStream? stream = null;
        try
        {
            long position = 0;
            var totalBlocks = 0;
            await foreach (var block in context.OutputChannel.Reader.ReadAllAsync(cancellationToken))
                try
                {
                    if (stream is null)
                    {
                        stream = new FileStream(context.OutputPath, FileMode.Create, FileAccess.Write,
                            FileShare.None, 4096 * 16, FileOptions.SequentialScan);
                        Engine.LogTrace("创建卷: {Path}", context.OutputPath);
                    }

                    if (block.Metadata.IsFirstFragment)
                    {
                        var header = new FileEntryHeader
                        {
                            FileId = Fnv1AHash64(block.Metadata.RelativePath),
                            Flags = block.Metadata.Flags,
                            FragmentIndex = (uint)block.Metadata.Sequence,
                            SizeOrTotal = block.Metadata.TotalFileSize
                        };
                        header.SetFilePath(block.Metadata.RelativePath);

                        var headerBytes = _cek is not null
                            ? FileEntryHeader.Encrypt(header, _cek)
                            : header.ToBytes();
                        stream.Position = position;
                        await stream.WriteAsync(headerBytes, cancellationToken);
                        position += headerBytes.Length;
                        Engine.LogTrace("卷头: {Path} ({HeaderType})", block.Metadata.RelativePath,
                            _cek is not null ? "CVPE加密" : "CVPH明文");
                    }

                    var length = BitConverter.GetBytes(block.Length);
                    stream.Position = position;
                    await stream.WriteAsync(length, cancellationToken);
                    await stream.WriteAsync(block.Data, cancellationToken);
                    position += sizeof(int) + block.Length;
                    totalBlocks++;
                }
                finally
                {
                    block.Dispose();
                }

            Engine.LogTrace("卷写入完成: {Path} {Blocks}块 {Bytes}字节",
                context.OutputPath, totalBlocks, position);
        }
        finally
        {
            if (stream is not null) await stream.DisposeAsync();
        }
    }

    /// <summary>计算文件路径的 FNV-1a 64 位标识。</summary>
    /// <param name="input">文件相对路径。</param>
    /// <returns>稳定的路径标识。</returns>
    private static ulong Fnv1AHash64(string input)
    {
        const ulong basis = 14695981039346656037ul;
        const ulong prime = 1099511628211ul;
        var hash = basis;
        foreach (var value in Encoding.UTF8.GetBytes(input))
        {
            hash ^= value;
            hash *= prime;
        }

        return hash;
    }
}
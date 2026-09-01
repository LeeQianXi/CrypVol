using System.Security.Cryptography;
using System.Text;
using CrypVol.Lib.Volume;

namespace CrypVol.Lib.Engine.Receivers;

/// <summary>将处理后的数据块写入 CVP 卷的接收阶段。</summary>
public sealed class CvpFileReciver : VolumeDataReceiverBase
{
    private readonly byte[]? _cek;
    private readonly Func<int, string>? _outputPathFactory;

    /// <summary>创建 CVP 卷接收阶段。</summary>
    /// <param name="cek">加密卷头所用 CEK；明文卷传 <see langword="null" />。</param>
    public CvpFileReciver(ReadOnlyMemory<byte>? cek)
    {
        _cek = cek?.ToArray();
    }

    /// <summary>创建可按目标卷编号动态生成输出路径的 CVP 卷接收阶段。</summary>
    /// <param name="cek">加密卷头所用 CEK；明文卷传 <see langword="null" />。</param>
    /// <param name="outputDirectory">输出目录。</param>
    /// <param name="outputPrefix">输出卷文件名前缀。</param>
    public CvpFileReciver(ReadOnlyMemory<byte>? cek, string outputDirectory, string outputPrefix)
        : this(cek, index => Path.Combine(
            outputDirectory ?? throw new ArgumentNullException(nameof(outputDirectory)),
            $"{outputPrefix ?? throw new ArgumentNullException(nameof(outputPrefix))}.{index}.cvp"))
    {
    }

    /// <summary>创建可按目标卷编号动态生成输出路径的 CVP 卷接收阶段。</summary>
    /// <param name="cek">加密卷头所用 CEK；明文卷传 <see langword="null" />。</param>
    /// <param name="outputPathFactory">根据目标卷编号生成输出路径的工厂。</param>
    public CvpFileReciver(ReadOnlyMemory<byte>? cek, Func<int, string> outputPathFactory)
    {
        _cek = cek?.ToArray();
        _outputPathFactory = outputPathFactory ?? throw new ArgumentNullException(nameof(outputPathFactory));
    }

    /// <summary>本次运行实际创建的卷文件路径。</summary>
    public IReadOnlyList<string> VolumePaths => Targets
        .OrderBy(context => context.VolumeIndex)
        .Select(context => context.OutputPath)
        .ToArray();

    /// <inheritdoc />
    protected override VolumeContext? CreateTarget(int index)
    {
        if (_outputPathFactory is null || index < 0)
            return null;

        return new VolumeContext
        {
            VolumeIndex = index,
            OutputPath = _outputPathFactory(index)
        };
    }

    /// <inheritdoc />
    protected override async Task ReceiveVolumeAsync(VolumeContext context, CancellationToken cancellationToken)
    {
        FileStream? stream = null;
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var integrityLevel = IntegrityLevel.None;
        try
        {
            long position = 0;
            var totalBlocks = 0;
            await foreach (var block in context.OutputChannel.Reader.ReadAllAsync(cancellationToken))
                try
                {
                    if (stream is null)
                    {
                        var directory = Path.GetDirectoryName(context.OutputPath);
                        if (!string.IsNullOrEmpty(directory))
                            Directory.CreateDirectory(directory);
                        stream = new FileStream(context.OutputPath, FileMode.Create, FileAccess.Write,
                            FileShare.None, 4096 * 16, FileOptions.SequentialScan);
                        Engine.LogDebug("创建卷: {Path}", context.OutputPath);
                    }

                    integrityLevel = (IntegrityLevel)(block.Metadata.Flags >> 3 & 3);

                    // 一个新卷中的首块必须有文件头，即使它是跨卷文件的续片。
                    if (totalBlocks == 0 || block.Metadata.IsFirstFragment)
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
                        hash.AppendData(headerBytes);
                        position += headerBytes.Length;
                        Engine.LogTrace("卷头: {Path} ({HeaderType})", block.Metadata.RelativePath,
                            _cek is not null ? "CVPE加密" : "CVPH明文");
                    }

                    var length = BitConverter.GetBytes(block.Length);
                    stream.Position = position;
                    await stream.WriteAsync(length, cancellationToken);
                    await stream.WriteAsync(block.Data, cancellationToken);
                    hash.AppendData(length);
                    hash.AppendData(block.Data.Span);
                    position += sizeof(int) + block.Length;
                    totalBlocks++;
                }
                finally
                {
                    block.Dispose();
                }

            if (stream is not null && integrityLevel >= IntegrityLevel.Volume)
            {
                var footer = VolumeIntegrityFooter.Create(hash.GetHashAndReset());
                await stream.WriteAsync(footer, cancellationToken);
            }

            Engine.LogDebug("卷写入完成: {Path} {Blocks}块 {Bytes}字节",
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

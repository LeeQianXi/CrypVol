namespace CrypVol.Lib.Engine.Receivers;

/// <summary>将处理后的数据块写入普通文件的接收阶段。</summary>
public sealed class DataFileReciver : VolumeDataReceiverBase
{
    private readonly string _outputDirectory;
    private readonly bool _overwrite;

    /// <summary>创建文件接收阶段。</summary>
    /// <param name="outputDirectory">输出根目录。</param>
    /// <param name="overwrite">是否覆盖已有文件。</param>
    public DataFileReciver(string outputDirectory, bool overwrite)
    {
        _outputDirectory = outputDirectory ?? throw new ArgumentNullException(nameof(outputDirectory));
        _overwrite = overwrite;
    }

    /// <inheritdoc />
    protected override async Task ReceiveVolumeAsync(VolumeContext context, CancellationToken cancellationToken)
    {
        var fullPath = context.OutputPath;
        if (!Path.IsPathFullyQualified(fullPath))
            fullPath = Path.Combine(_outputDirectory, fullPath);

        if (!_overwrite && File.Exists(fullPath))
        {
            Engine.LogInformation("文件已存在，跳过: {Path}", fullPath);
            await foreach (var block in context.OutputChannel.Reader.ReadAllAsync(cancellationToken))
                block.Dispose();
            return;
        }

        var directory = Path.GetDirectoryName(fullPath);
        if (directory is not null) Directory.CreateDirectory(directory);

        FileStream? stream = null;
        try
        {
            long position = 0;
            long totalBytes = 0;
            await foreach (var block in context.OutputChannel.Reader.ReadAllAsync(cancellationToken))
                try
                {
                    if (stream is null)
                    {
                        stream = new FileStream(fullPath, FileMode.Create, FileAccess.Write,
                            FileShare.None, 4096 * 16, FileOptions.SequentialScan);
                        Engine.LogTrace("创建文件: {Path}", fullPath);
                    }

                    stream.Position = position;
                    await stream.WriteAsync(block.Data, cancellationToken);
                    position += block.Length;
                    totalBytes += block.Length;
                }
                finally
                {
                    block.Dispose();
                }

            Engine.LogTrace("文件写入完成: {Path} {Bytes}字节", fullPath, totalBytes);
        }
        finally
        {
            if (stream is not null) await stream.DisposeAsync();
        }
    }
}
using System.Text;

namespace CrypVol.Lib.Utility;

/// <summary>提供同目录临时文件写入后原子替换的文件操作。</summary>
public static class AtomicFile
{
    /// <summary>以二进制方式原子写入目标文件。</summary>
    /// <param name="path">目标文件路径。</param>
    /// <param name="contents">待写入字节。</param>
    /// <param name="cancellationToken">取消令牌。</param>
    public static async Task WriteBytesAsync(string path, ReadOnlyMemory<byte> contents,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath)
                        ?? throw new ArgumentException("目标文件路径无效。", nameof(path));
        Directory.CreateDirectory(directory);
        var temporaryPath = Path.Combine(directory, $".{Path.GetFileName(fullPath)}.{Guid.NewGuid():N}.tmp");
        try
        {
            await File.WriteAllBytesAsync(temporaryPath, contents.ToArray(), cancellationToken);
            File.Move(temporaryPath, fullPath, true);
        }
        finally
        {
            if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
        }
    }

    /// <summary>以 UTF-8 文本方式原子写入目标文件。</summary>
    /// <param name="path">目标文件路径。</param>
    /// <param name="contents">待写入文本。</param>
    /// <param name="cancellationToken">取消令牌。</param>
    public static async Task WriteTextAsync(string path, string contents,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(contents);

        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath)
                        ?? throw new ArgumentException("目标文件路径无效。", nameof(path));
        Directory.CreateDirectory(directory);
        var temporaryPath = Path.Combine(directory, $".{Path.GetFileName(fullPath)}.{Guid.NewGuid():N}.tmp");
        try
        {
            await File.WriteAllTextAsync(temporaryPath, contents, Encoding.UTF8, cancellationToken);
            File.Move(temporaryPath, fullPath, true);
        }
        finally
        {
            if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
        }
    }
}
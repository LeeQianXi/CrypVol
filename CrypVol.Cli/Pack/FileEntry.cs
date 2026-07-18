using System.Text;
using CrypVol.Lib;

namespace CrypVol.Cli.Pack;

/// <summary> 预处理输出的文件条目 </summary>
public sealed class FileEntry
{
    public required string RelativePath { get; init; }
    public ulong FileId => Fnv1AHash64(RelativePath);
    public required long TotalFileSize { get; init; }

    /// 该文件的跨卷序号
    public int FragmentIndex { get; init; }

    /// 在源文件中的读取偏移
    public long SourceOffset { get; init; }

    /// 有效数据字节数（写入时不包含填充）
    public long LogicalDataLength { get; init; }

    /// 实际占用的数据体空间（对齐后的值）
    public long PhysicalDataLength { get; init; }

    public FileEntryHeaderFlagsEnum Flags { get; init; }
    public bool HasExtendedPath { get; init; }

    public static ulong Fnv1AHash64(string input)
    {
        const ulong fnvOffsetBasis = 14695981039346656037ul;
        const ulong fnvPrime = 1099511628211ul;

        var hash = fnvOffsetBasis;
        var data = Encoding.UTF8.GetBytes(input);

        foreach (var b in data)
        {
            hash ^= b;
            hash *= fnvPrime;
        }

        return hash;
    }
}
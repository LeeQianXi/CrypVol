using CrypVol.Lib.Pipeline;
using Microsoft.Extensions.Logging;

namespace CrypVol.Lib.Volume;

/// <summary>文件→卷的预分配算法。单文件内块大小 = min(totalSize, 4MiB)，1KiB 对齐。</summary>
public static class VolumeAllocator
{
    private const long MaxBlockSize = 4L * 1024 * 1024; // 4 MiB — 减少 WorkItem 数量
    private const long Alignment = 1024;               // 1 KiB — 避免文件头浪费

    /// <summary>结构化日志（可选）</summary>
    public static ILogger? Logger { get; set; }

    public static (List<WorkItem> items, List<(int Index, long Size)> volumes)
        Allocate(IEnumerable<FileInfo> files, DirectoryInfo sourceDir, long volumeCapacity, int headerSize = 284,
            IntegrityLevel integrityLevel = IntegrityLevel.None, bool enableCompression = false)
    {
        const int maxPathLen = 231 + 256;

        var items = new List<WorkItem>();
        var volSizes = new Dictionary<int, long>();
        var perVolSeq = new Dictionary<int, long>();

        var currentVol = 0;
        long used = 0;

        long NextSeq(int vol)
        {
            perVolSeq.TryGetValue(vol, out var s);
            perVolSeq[vol] = s + 1;
            return s;
        }

        foreach (var file in files)
        {
            var relPath = Path.GetRelativePath(sourceDir.FullName, file.FullName);
            if (relPath.Length > maxPathLen) continue;

            var totalSize = file.Length;
            if (totalSize == 0)
            {
                if (used + headerSize > volumeCapacity)
                {
                    currentVol++;
                    used = 0;
                }

                items.Add(new WorkItem
                {
                    RelativePath = relPath,
                    SourceFullPath = file.FullName,
                    VolumeIndex = currentVol,
                    Sequence = NextSeq(currentVol),
                    Length = 0,
                    TotalFileSize = 0,
                    Flags = (byte)(((int)integrityLevel & 3) << 3 | (enableCompression ? 0x20 : 0)),
                    IsFirstFragment = true
                });
                used += headerSize;
                volSizes[currentVol] = used;
                continue;
            }

            // 单文件内块大小：取 min(文件总大小, 4MiB)，便于单线程流水线减少块数
            var blockSize = Math.Min((long)totalSize, MaxBlockSize);
            var remaining = totalSize;
            long srcOffset = 0;
            var fragmentIdx = 0;

            while (remaining > 0)
            {
                if (volumeCapacity - used < headerSize)
                {
                    currentVol++;
                    used = 0;
                }

                var dataSpace = volumeCapacity - used - headerSize;
                var maxBlocks = dataSpace / Alignment;
                if (maxBlocks == 0)
                {
                    currentVol++;
                    used = 0;
                    continue;
                }

                // 取三者最小值: 剩余数据、块大小上限、本卷剩余空间（按对齐边界）
                var spaceLimit = maxBlocks * Alignment;
                var rawToWrite = Math.Min(blockSize, Math.Min(remaining, spaceLimit));
                var physicalLen = (rawToWrite + Alignment - 1) / Alignment * Alignment;

                byte flags = fragmentIdx switch
                {
                    0 when rawToWrite == remaining => 0,
                    0 => 1,
                    _ when rawToWrite == remaining => 3,
                    _ => 2
                };
                if (relPath.Length > 231) flags |= 4;
                flags |= (byte)(((int)integrityLevel & 3) << 3);
                if (enableCompression) flags |= 0x20;

                items.Add(new WorkItem
                {
                    RelativePath = relPath,
                    SourceFullPath = file.FullName,
                    VolumeIndex = currentVol,
                    Sequence = NextSeq(currentVol),
                    SourceOffset = srcOffset,
                    Length = (int)rawToWrite,
                    TotalFileSize = totalSize,
                    Flags = flags,
                    IsFirstFragment = true
                });

                remaining -= physicalLen;
                srcOffset += physicalLen;
                fragmentIdx++;
                used += headerSize + physicalLen;
                volSizes[currentVol] = used;
                if (used >= volumeCapacity)
                {
                    currentVol++;
                    used = 0;
                }
            }
        }

        var volumes = volSizes.OrderBy(kv => kv.Key).Select(kv => (kv.Key, kv.Value)).ToList();
        Logger?.LogInformation("分配完成: {FileCount} 文件 → {ItemCount} 块, {VolCount} 卷",
            items.GroupBy(i => i.RelativePath).Count(), items.Count, volumes.Count);
        if (Logger?.IsEnabled(LogLevel.Debug) == true)
            foreach (var (volIdx, size) in volumes)
                Logger.LogDebug("  卷 {VolIdx}: {Size} 字节", volIdx, size);
        return (items, volumes);
    }
}

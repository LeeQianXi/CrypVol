using CrypVol.Lib.Pipeline;

namespace CrypVol.Lib.Volume;

/// <summary>文件→卷的预分配算法</summary>
public static class VolumeAllocator
{
    public static (List<WorkItem> items, List<(int Index, long Size)> volumes)
        Allocate(IEnumerable<FileInfo> files, DirectoryInfo sourceDir, long volumeCapacity, int headerSize = 284,
            IntegrityLevel integrityLevel = IntegrityLevel.None, bool enableCompression = false)
    {
        const int maxPathLen = 231 + 256;
        const long alignment = 4096;

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
                var maxBlocks = dataSpace / alignment;
                if (maxBlocks == 0)
                {
                    currentVol++;
                    used = 0;
                    continue;
                }

                var rawToWrite = Math.Min(remaining, maxBlocks * alignment);
                var physicalLen = (rawToWrite + alignment - 1) / alignment * alignment;

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
        return (items, volumes);
    }
}
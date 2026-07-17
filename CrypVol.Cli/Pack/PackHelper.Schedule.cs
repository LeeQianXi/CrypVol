using CrypVol.Lib;

namespace CrypVol.Cli.Pack;

public static partial class PackHelper
{
    private static partial async Task PreTreatmentAsync(CancellationToken token)
    {
        const int headerBaseSize = 256;
        const int headerExtendedSize = 256;
        const int maxPathLength = 231 + headerExtendedSize;
        const long alignment = 512;
        var pathOrigin = GlobalConfig.SourceDir;
        var volumeDataCapacity = GlobalConfig.VolumeDataCapacity;
        var currentVolume = 0;
        // 当前卷已用物理空间
        long usedInVolume = 0;

        VolumeContext GetOrCreateVolume(int index)
        {
            // 辅助方法：获取或创建卷上下文
            if (VolumeContexts.TryGetValue(index, out var ctx)) return ctx;
            ctx = new VolumeContext
            {
                VolumeIndex = index
            };
            VolumeContexts[index] = ctx;
            return ctx;
        }

        foreach (var fileInfo in GlobalConfig.Files)
        {
            var relativePath = Path.GetRelativePath(pathOrigin, fileInfo.FullName);
            if (relativePath.Length > maxPathLength)
            {
                GeneralLog("路径过长（{0} > {1}）：{2}", relativePath.Length, maxPathLength, relativePath);
                continue;
            }

            var hasExtendedPath = relativePath.Length > 231;
            var headerSize = hasExtendedPath ? headerBaseSize + headerExtendedSize : headerBaseSize;

            var totalSize = fileInfo.Length;
            var remaining = totalSize;
            long srcOffset = 0;
            var fragmentIdx = 0;

            // 处理空文件（仍需要一个段，数据体长度为 0）
            if (totalSize == 0)
            {
                long needed = headerSize;
                while (usedInVolume + needed > volumeDataCapacity)
                {
                    currentVolume++;
                    usedInVolume = 0;
                }

                var ctx = GetOrCreateVolume(currentVolume);
                ctx.Entries.Add(new FileEntry
                {
                    RelativePath = relativePath,
                    TotalFileSize = 0,
                    HasExtendedPath = hasExtendedPath
                });
                usedInVolume += needed;
                continue;
            }

            while (remaining > 0)
            {
                var avail = volumeDataCapacity - usedInVolume;
                if (avail < headerSize)
                {
                    currentVolume++;
                    usedInVolume = 0;
                    continue;
                }

                var dataSpace = avail - headerSize;
                var maxBlocks = dataSpace / alignment;
                if (maxBlocks == 0)
                {
                    currentVolume++;
                    usedInVolume = 0;
                    continue;
                }

                var maxWritableRaw = maxBlocks * alignment;
                var rawToWrite = Math.Min(remaining, maxWritableRaw);
                var physicalDataLen = (rawToWrite + alignment - 1) / alignment * alignment;
                if (headerSize + physicalDataLen > avail)
                    throw new Exception("物理长度超出卷剩余空间，算法逻辑错误");

                var isFirstFragment = fragmentIdx == 0;
                var isLastFragment = rawToWrite == remaining;
                var flags = isFirstFragment switch
                {
                    true when isLastFragment => FileEntryHeaderFlagsEnum.Full,
                    true => FileEntryHeaderFlagsEnum.CrossHead,
                    _ => isLastFragment ? FileEntryHeaderFlagsEnum.CrossTail : FileEntryHeaderFlagsEnum.CrossMid
                };

                var ctx = GetOrCreateVolume(currentVolume);
                ctx.Entries.Add(new FileEntry
                {
                    RelativePath = relativePath,
                    TotalFileSize = totalSize,
                    FragmentIndex = fragmentIdx,
                    SourceOffset = srcOffset,
                    LogicalDataLength = rawToWrite,
                    PhysicalDataLength = physicalDataLen,
                    Flags = flags,
                    HasExtendedPath = hasExtendedPath
                });
                // 更新状态
                remaining -= physicalDataLen;
                srcOffset += physicalDataLen;
                fragmentIdx++;
                usedInVolume += headerSize + physicalDataLen;
                // 若当前卷恰好用完或已满，切到下一卷
                if (usedInVolume < volumeDataCapacity) continue;
                currentVolume++;
                usedInVolume = 0;
            }
        }

        var emptyVolumes = VolumeContexts.Where(kv => kv.Value.Entries.Count == 0).Select(kv => kv.Key).ToList();
        foreach (var key in emptyVolumes)
            VolumeContexts.TryRemove(key, out _);
    }
}
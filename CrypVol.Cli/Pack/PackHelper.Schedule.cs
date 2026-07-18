using System.Buffers;
using CrypVol.Lib;

namespace CrypVol.Cli.Pack;

public static partial class PackHelper
{
    private static partial async Task PreTreatmentAsync(CancellationToken token)
    {
        VerboseLog("启动 预处理 流程");
        const int headerBaseSize = 256;
        const int headerExtendedSize = 256;
        const int maxPathLength = 231 + headerExtendedSize;
        const long alignment = 512;
        var pathOrigin = GlobalConfig.SourceDir;
        var volumeDataCapacity = GlobalConfig.VolumeDataCapacity;
        var currentVolume = 0;
        // 当前卷已用物理空间
        long usedInVolume = 0;

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
        foreach (var (key,ctx) in VolumeContexts)
        {
            if (ctx.Entries.Count is 0)
            {
                VolumeContexts.Remove(key, out _);
                continue;
            }

            ctx.TotalBlocks = ctx.Entries.Select(item => item.PhysicalDataLength / alignment).Sum();
        }
        var emptyVolumes = VolumeContexts.Where(kv => kv.Value.Entries.Count == 0).Select(kv => kv.Key).ToList();
        foreach (var key in emptyVolumes)
            VolumeContexts.TryRemove(key, out _);
        VerboseLog("预处理 成功完成");
        GeneralLog("预计生成 {0}个 数据卷", VolumeContexts.Count);
        return;

        VolumeContext GetOrCreateVolume(int index)
        {
            // 辅助方法：获取或创建卷上下文
            if (VolumeContexts.TryGetValue(index, out var ctx)) return ctx;
            ctx = new VolumeContext
            {
                VolumeIndex = index
            };
            VolumeContexts[index] = ctx;
            VerboseLog("成功创建 卷{0} 上下文", index);
            return ctx;
        }
    }

    private static partial async Task ReadLoopAsync(CancellationToken token)
    {
        VerboseLog("启动 读循环 流程");
        var provider = TaskChannel.Reader;
        var consumer = RawBlockChannel.Writer;
        var root = GlobalConfig.SourceDir;
        await foreach (var entry in provider.ReadAllAsync(token))
        {
            await using var fs = File.OpenRead(Path.Combine(root, entry.RelativePath));
            var index = 0;
            var offset = 0;
            fs.Position = entry.SourceOffset;
            while (fs.Position < fs.Length)
            {
                var array = ArrayPool<byte>.Shared.Rent(1024 * 4);
                var length = await fs.ReadAsync(array, token);
                var meta = new TaskItem
                {
                    RelativePath = entry.RelativePath,
                    FragmentIndex = entry.FragmentIndex,
                    Length = length,
                    TotalFileSize = entry.TotalFileSize,
                    SourceOffset = offset,
                    Sequence = index,
                    Flags = entry.Flags
                };
                index++;
                offset += length;
                await consumer.WriteAsync(new RawBlock()
                {
                    Metadata = meta,
                    Data = array,
                }, token);
            }
        }

        VerboseLog("推出 读循环 流程");
    }

    private static partial async Task ComputeLoopAsync(CancellationToken token)
    {
        VerboseLog("启动 压缩/加密循环 流程");
        var provider = RawBlockChannel.Reader;
        var consumer = EncryptedBlockChannel.Writer;
        var stream = ComplineStream();
        await foreach (var block in provider.ReadAllAsync(token))
        {
            await stream.WriteAsync(block.Data, token);
            var array = ArrayPool<byte>.Shared.Rent(1024 * 4);
            var length = await stream.ReadAsync(array, token);
            await consumer.WriteAsync(new EncryptedBlock()
            {
                Metadata = block.Metadata,
                Data = array,
                OriginalLength = block.Data.Length
            }, token);
            block.Dispose();
        }

        VerboseLog("推出 压缩/加密循环 流程");

        Stream ComplineStream()
        {
            return new MemoryStream();
        }
    }

    private static partial async Task RerouteLoopAsync(CancellationToken token)
    {
        VerboseLog("启动 重路由 流程");
        var reader = EncryptedBlockChannel.Reader;
        await foreach (var item in reader.ReadAllAsync(token))
        {
            var volId = item.Metadata.FragmentIndex;
            var order = item.Metadata.Sequence;
            var context = VolumeContexts[volId];
            if (order < context.NextExpectedSeq) continue;
            if (order > context.NextExpectedSeq)
            {
                context.Buffer.Add(order, item);
                continue;
            }

            var writer = context.OutputChannel.Writer;
            context.NextExpectedSeq++;
            await writer.WriteAsync(item, token);
            while (context.Buffer.TryGetValue(context.NextExpectedSeq, out var next))
            {
                context.NextExpectedSeq++;
                context.Buffer.Remove(context.NextExpectedSeq);
                await writer.WriteAsync(next, token);
            }

            if (order + 1 >= context.TotalBlocks)
            {
                context.OutputChannel.Writer.TryComplete();
            }
        }

        foreach (var context in VolumeContexts.Values)
        {
            context.OutputChannel.Writer.TryComplete();
        }

        VerboseLog("推出 重路由 流程");
    }

    private static partial async Task WriteLoopAsync(VolumeContext ctx, CancellationToken token)
    {
        VerboseLog("启动 写循环 流程");
        GeneralLog("开始写入 卷{0}", ctx.VolumeIndex);
        var reader = ctx.OutputChannel.Reader;
        var prefix = GlobalConfig.OutputPrefix;
        var path = GlobalConfig.OutputDir;
        var vol = Path.Combine(path, $"{prefix}.{ctx.VolumeIndex}.cvp");
        await using var writer = File.OpenWrite(vol);
        writer.SetLength(ctx.Entries.Select(i => i.PhysicalDataLength).Sum());
        await foreach (var item in reader.ReadAllAsync(token))
        {
            VerboseLog("WriteLoopAsync:<{0},{1}>:{2}", item.Metadata.FragmentIndex, item.Metadata.Sequence,
                item.Metadata.Length);
            await writer.WriteAsync(item.Data, token);
        }

        await writer.FlushAsync(token);
        GeneralLog("卷{0} 写入完成", ctx.VolumeIndex);
        VerboseLog("退出 写循环 流程");
    }
}
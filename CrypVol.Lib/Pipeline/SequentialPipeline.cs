using System.Threading.Channels;

namespace CrypVol.Lib.Pipeline;

/// <summary>
///     单线程顺序流水线编排器。
///     完全序列化处理：读一块 → 变换一块 → 路由一块，不使用 Channel 并发、
///     ConcurrentDictionary、Interlocked 或任何锁。
///     与 VolumePipeline 共享相同的 VolumeContext / OutputChannel / Sink 接口，
///     方便与多线程方案进行性能对比。
/// </summary>
public sealed class SequentialPipeline
{
    private readonly IBlockTransform _transform;

    // ── 卷（普通 Dictionary，非并发）──
    private readonly Dictionary<int, VolumeContext> _volumes = new();

    public SequentialPipeline(IBlockTransform transform)
    {
        _transform = transform;
    }

    // ── 可插拔委托 ──
    public Func<WorkItem, CancellationToken, Task<RawBlock?>> ReadBlockAsync { private get; init; } = null!;
    public Func<VolumeContext, CancellationToken, Task> WriteVolumeAsync { private get; init; } = null!;

    // ═══════════════════════════════════════════════════════
    //  公开入口
    // ═══════════════════════════════════════════════════════

    public VolumeContext AddVolume(int index, string outputPath, long preallocatedSize)
    {
        var ctx = new VolumeContext
        {
            VolumeIndex = index,
            OutputPath = outputPath,
            PreallocatedSize = preallocatedSize
        };
        _volumes[index] = ctx;
        return ctx;
    }

    public async Task RunAsync(IReadOnlyList<WorkItem> items, CancellationToken token)
    {
        // 分配工作项到各卷
        foreach (var item in items)
        {
            if (!_volumes.TryGetValue(item.VolumeIndex, out var ctx))
                throw new InvalidOperationException($"卷 {item.VolumeIndex} 未注册");
            ctx.Items.Add(item);
        }

        // ── 单线程顺序处理：读 → 变换 → 路由 ──
        foreach (var item in items)
        {
            token.ThrowIfCancellationRequested();

            // Stage 1: Read
            var block = await ReadBlockAsync(item, token);
            if (block is null) continue;

            // Stage 2: Transform
            var output = _transform.Transform(block.Data, block.DataLength, out var outputLen);

            var processed = new ProcessedBlock
            {
                Work = block.Work,
                Data = output,
                OutputLength = outputLen,
                OriginalLength = block.DataLength
            };

            block.Dispose();

            // Stage 3: Route — 顺序处理，天然有序，无需缓冲
            if (!_volumes.TryGetValue(item.VolumeIndex, out var volCtx))
            {
                processed.Dispose();
                continue;
            }

            await volCtx.OutputChannel.Writer.WriteAsync(processed, token);
            volCtx.NextExpectedSeq = item.Sequence + 1;
        }

        // 所有块处理完毕，关闭各卷的输出通道
        foreach (var ctx in _volumes.Values)
            ctx.OutputChannel.Writer.Complete();

        // Stage 4: Write — 逐卷写入磁盘
        foreach (var ctx in _volumes.Values)
            await WriteVolumeAsync(ctx, token);
    }
}

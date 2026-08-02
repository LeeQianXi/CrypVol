using System.Collections.Concurrent;
using System.Threading.Channels;

namespace CrypVol.Cli.Pipeline;

/// <summary>
///     共享的并行流水线编排器。
///     四阶段串行流程（每个阶段内部并行），阶段间通过 Channel 解耦：
///
///     Push → EntryChannel → [Read×N] → RawChannel → [Transform×M] → ProcessedChannel → Route → [Write×V]
///
///     阶段边界由 Channel 的 Complete 保证：上游全部退出后才关闭通道，下游自然结束。
/// </summary>
public sealed class Pipeline
{
    private readonly PipelineConfig _config;
    private readonly IBlockTransform _transform;

    // ── 通道 ──
    private readonly Channel<WorkItem> _entryChannel = Channel.CreateUnbounded<WorkItem>();
    private readonly Channel<RawBlock> _rawChannel;
    private readonly Channel<ProcessedBlock> _processedChannel;

    // ── 卷 ──
    private readonly ConcurrentDictionary<int, VolumeContext> _volumes = new();

    // ── 活跃计数 ──
    private int _activeReaders;
    private int _activeTransforms;

    // ── 可插拔委托 ──
    public Func<WorkItem, CancellationToken, Task<RawBlock?>> ReadBlockAsync { private get; init; } = null!;
    public Func<VolumeContext, CancellationToken, Task> WriteVolumeAsync { private get; init; } = null!;

    public Pipeline(PipelineConfig config, IBlockTransform transform)
    {
        _config = config;
        _transform = transform;

        _rawChannel = Channel.CreateBounded<RawBlock>(new BoundedChannelOptions(config.RawChannelCapacity)
        {
            FullMode = BoundedChannelFullMode.Wait
        });

        _processedChannel = Channel.CreateBounded<ProcessedBlock>(
            new BoundedChannelOptions(config.ProcessedChannelCapacity)
            {
                FullMode = BoundedChannelFullMode.Wait
            });
    }

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

        _activeReaders = _config.ReaderConcurrency;
        _activeTransforms = _config.TransformConcurrency;

        // 启动阶段：push + route 单实例，read/transform/write 并行
        var push = PushItemsAsync(items, token);
        var route = RouteLoopAsync(token);

        var readers = new List<Task>();
        for (var i = 0; i < _config.ReaderConcurrency; i++)
            readers.Add(ReadLoopAsync(token));

        var transforms = new List<Task>();
        for (var i = 0; i < _config.TransformConcurrency; i++)
            transforms.Add(TransformLoopAsync(token));

        var writers = new List<Task>();
        foreach (var v in _volumes.Values)
            writers.Add(WriteVolumeAsync!(v, token));

        // 等待全部完成
        await Task.WhenAll([push, ..readers, ..transforms, route, ..writers]);
    }

    // ═══════════════════════════════════════════════════════
    //  Push
    // ═══════════════════════════════════════════════════════

    private async Task PushItemsAsync(IReadOnlyList<WorkItem> items, CancellationToken token)
    {
        foreach (var item in items)
            await _entryChannel.Writer.WriteAsync(item, token);
        _entryChannel.Writer.Complete();
    }

    // ═══════════════════════════════════════════════════════
    //  Stage 1: Read（N 个并发读实例）
    // ═══════════════════════════════════════════════════════

    private async Task ReadLoopAsync(CancellationToken token)
    {
        try
        {
            var reader = _entryChannel.Reader;
            var writer = _rawChannel.Writer;

            await foreach (var item in reader.ReadAllAsync(token))
            {
                var block = await ReadBlockAsync(item, token);
                if (block is null) continue;
                await writer.WriteAsync(block, token);
            }
        }
        finally
        {
            // 所有读实例退出后关闭 raw 通道，解除 transform 阻塞
            if (Interlocked.Decrement(ref _activeReaders) == 0)
                _rawChannel.Writer.Complete();
        }
    }

    // ═══════════════════════════════════════════════════════
    //  Stage 2: Transform（M 个并发变换实例）
    // ═══════════════════════════════════════════════════════

    private async Task TransformLoopAsync(CancellationToken token)
    {
        try
        {
            var reader = _rawChannel.Reader;
            var writer = _processedChannel.Writer;

            await foreach (var raw in reader.ReadAllAsync(token))
            {
                var output = _transform.Transform(raw.Data, raw.DataLength, out var outputLen);

                var processed = new ProcessedBlock
                {
                    Work = raw.Work,
                    Data = output,
                    OutputLength = outputLen,
                    OriginalLength = raw.DataLength
                };

                await writer.WriteAsync(processed, token);
                raw.Dispose();
            }
        }
        finally
        {
            // 所有变换实例退出后关闭 processed 通道，route 自然结束
            if (Interlocked.Decrement(ref _activeTransforms) == 0)
                _processedChannel.Writer.Complete();
        }
    }

    // ═══════════════════════════════════════════════════════
    //  Stage 3: Route（单实例，保证卷内有序）
    // ═══════════════════════════════════════════════════════

    private async Task RouteLoopAsync(CancellationToken token)
    {
        var reader = _processedChannel.Reader;

        await foreach (var block in reader.ReadAllAsync(token))
        {
            var volId = block.Work.VolumeIndex;
            var seq = block.Work.Sequence;

            if (!_volumes.TryGetValue(volId, out var ctx))
            {
                block.Dispose();
                continue;
            }

            // 卷内有序路由：比期望序号小 = 重复（丢弃），大 = 乱序（暂存缓冲）
            if (seq < ctx.NextExpectedSeq)
            {
                block.Dispose();
                continue;
            }

            if (seq > ctx.NextExpectedSeq)
            {
                ctx.Buffer[seq] = block;
                continue;
            }

            // 正好是期望序号，直接输出
            await DeliverAsync(ctx, block, token);

            // 排空缓冲中已连续的后继
            while (ctx.Buffer.Remove(ctx.NextExpectedSeq, out var next))
                await DeliverAsync(ctx, next, token);
        }

        // processed 通道结束后，关闭所有卷的输出通道
        foreach (var ctx in _volumes.Values)
            ctx.OutputChannel.Writer.Complete();
    }

    private static async Task DeliverAsync(VolumeContext ctx, ProcessedBlock block, CancellationToken token)
    {
        await ctx.OutputChannel.Writer.WriteAsync(block, token);
        ctx.NextExpectedSeq = block.Work.Sequence + 1;
    }
}

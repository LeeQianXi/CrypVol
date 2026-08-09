using System.Threading.Channels;
using Microsoft.Extensions.Logging;

namespace CrypVol.Lib.Pipeline;

/// <summary>
///     顺序流水线编排器。
///     每个阶段一个独立线程，阶段间通过 Channel 解耦。
///     Stage 0: Read  (1 线程) → Stage 1: Transform (1 线程) → Stage 2: Route (1 线程) → Stage 3: Write (1 线程 per volume)
///     所有阶段严格串行——每个阶段内部同时只处理一个项目，保证全链路有序。
/// </summary>
public sealed class SequentialPipeline
{
    private readonly IBlockTransform _transform;

    // ── 阶段间 Channel ──
    private readonly Channel<RawBlock> _rawChannel =
        Channel.CreateBounded<RawBlock>(new BoundedChannelOptions(1) { SingleReader = true, SingleWriter = true });

    private readonly Channel<ProcessedBlock> _processedChannel =
        Channel.CreateBounded<ProcessedBlock>(new BoundedChannelOptions(1) { SingleReader = true, SingleWriter = true });

    // ── 卷 ──
    private readonly Dictionary<int, VolumeContext> _volumes = new();

    // ── 日志 ──
    public ILogger? Logger { get; set; }

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
        Logger?.LogInformation("流水线启动: {ItemCount} 项, {VolCount} 卷", items.Count, _volumes.Count);

        // 分配工作项到各卷
        foreach (var item in items)
        {
            if (!_volumes.TryGetValue(item.VolumeIndex, out var ctx))
                throw new InvalidOperationException($"卷 {item.VolumeIndex} 未注册");
            ctx.Items.Add(item);
        }

        // ── 阶段 0: Read 线程 ──
        var readTask = Task.Run(async () =>
        {
            try
            {
                var idx = 0;
                foreach (var item in items)
                {
                    token.ThrowIfCancellationRequested();
                    var block = await ReadBlockAsync(item, token);
                    if (block is null) continue;
                    await _rawChannel.Writer.WriteAsync(block, token);
                    idx++;
                }

                Logger?.LogTrace("读阶段完成: {Count} 块", idx);
            }
            finally
            {
                _rawChannel.Writer.Complete();
            }
        }, token);

        // ── 阶段 1: Transform 线程 ──
        var transformTask = Task.Run(async () =>
        {
            try
            {
                var count = 0;
                await foreach (var raw in _rawChannel.Reader.ReadAllAsync(token))
                {
                    var output = _transform.Transform(raw.Data, raw.DataLength, out var outputLen);

                    var processed = new ProcessedBlock
                    {
                        Work = raw.Work,
                        Data = output,
                        OutputLength = outputLen,
                        OriginalLength = raw.DataLength
                    };

                    raw.Dispose();
                    await _processedChannel.Writer.WriteAsync(processed, token);
                    count++;
                }

                Logger?.LogTrace("变换阶段完成: {Count} 块", count);
            }
            finally
            {
                _processedChannel.Writer.Complete();
            }
        }, token);

        // ── 阶段 2: Route 线程 ──
        var routeTask = Task.Run(async () =>
        {
            var count = 0;
            await foreach (var block in _processedChannel.Reader.ReadAllAsync(token))
            {
                if (!_volumes.TryGetValue(block.Work.VolumeIndex, out var volCtx))
                {
                    Logger?.LogWarning("未知卷 {VolIdx}: {Path}", block.Work.VolumeIndex, block.Work.RelativePath);
                    block.Dispose();
                    continue;
                }

                // 顺序处理，天然有序
                await volCtx.OutputChannel.Writer.WriteAsync(block, token);
                count++;
            }

            Logger?.LogTrace("路由阶段完成: {Count} 块", count);

            // processed 通道结束后，关闭所有卷的输出通道
            foreach (var ctx in _volumes.Values)
                ctx.OutputChannel.Writer.Complete();
        }, token);

        // 等待前三阶段结束
        await Task.WhenAll(readTask, transformTask, routeTask);
        Logger?.LogTrace("流水线处理阶段结束");

        // ── 阶段 3: Write 线程 ──
        // 逐卷写入磁盘（每个卷一个独立 Task，但只同时处理一个）
        foreach (var ctx in _volumes.Values)
            await WriteVolumeAsync(ctx, token);

        Logger?.LogInformation("流水线完成: {VolCount} 卷", _volumes.Count);
    }
}

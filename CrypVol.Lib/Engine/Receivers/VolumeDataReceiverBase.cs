using System.Diagnostics;

namespace CrypVol.Lib.Engine.Receivers;

/// <summary>按目标编号路由到多个输出卷的接收阶段基类。</summary>
public abstract class VolumeDataReceiverBase : DataReceiverBase
{
    private readonly Dictionary<int, Task> _receiveTasks = new();
    private readonly Dictionary<int, VolumeContext> _volumes = new();

    /// <summary>已注册或运行时动态创建的输出卷。</summary>
    protected IEnumerable<VolumeContext> Targets => _volumes.Values;

    /// <summary>注册一个输出目标卷。</summary>
    /// <param name="index">目标编号。</param>
    /// <param name="outputPath">输出路径。</param>
    public VolumeDataReceiverBase AddTarget(int index, string outputPath)
    {
        _volumes.Add(index, new VolumeContext
        {
            VolumeIndex = index,
            OutputPath = outputPath
        });
        return this;
    }

    /// <summary>
    ///     为首次路由到的目标卷创建上下文。
    ///     默认不创建目标，以兼容需要显式注册目标的接收器。
    /// </summary>
    /// <param name="index">目标卷编号。</param>
    /// <returns>新建的卷上下文；不支持该目标时返回 <see langword="null" />。</returns>
    protected virtual VolumeContext? CreateTarget(int index)
    {
        return null;
    }

    /// <inheritdoc />
    public override async Task ReceiveAsync(CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();
        using var receiveCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        foreach (var context in _volumes.Values)
            StartReceiver(context, receiveCancellation);

        Exception? routingError = null;
        try
        {
            await foreach (var block in ReadAsync(receiveCancellation.Token))
            {
                if (!_volumes.TryGetValue(block.Metadata.TargetIndex, out var context))
                {
                    context = CreateTarget(block.Metadata.TargetIndex);
                    if (context is not null)
                    {
                        _volumes.Add(context.VolumeIndex, context);
                        Engine.LogDebug("Receiver {Receiver} 创建目标 {TargetIndex}: {OutputPath}", GetType().Name,
                            context.VolumeIndex, context.OutputPath);
                        StartReceiver(context, receiveCancellation);
                    }
                }

                if (context is not null)
                {
                    try
                    {
                        Engine.LogTrace("Receiver {Receiver} 路由块: {Path}, Seq={Sequence}, Target={TargetIndex}",
                            GetType().Name, block.Metadata.RelativePath, block.Metadata.Sequence,
                            context.VolumeIndex);
                        await context.OutputChannel.Writer.WriteAsync(block, receiveCancellation.Token);
                    }
                    catch
                    {
                        block.Dispose();
                        throw;
                    }

                    continue;
                }

                Engine.LogWarning("未知目标 {TargetIndex}: {Path}",
                    block.Metadata.TargetIndex, block.Metadata.RelativePath);
                block.Dispose();
            }
        }
        catch (Exception ex)
        {
            routingError = ex;
            throw;
        }
        finally
        {
            foreach (var context in _volumes.Values)
                context.OutputChannel.Writer.TryComplete(routingError);
            try
            {
                await Task.WhenAll(_receiveTasks.Values);
            }
            finally
            {
                foreach (var context in _volumes.Values)
                    while (context.OutputChannel.Reader.TryRead(out var block))
                        block.Dispose();

                var status = routingError is null
                    ? cancellationToken.IsCancellationRequested ? "Canceled" : "Completed"
                    : routingError is OperationCanceledException
                        ? "Canceled"
                        : "Faulted";
                var throughput = stopwatch.Elapsed.TotalSeconds > 0
                    ? ReceivedByteCount / 1024d / 1024d / stopwatch.Elapsed.TotalSeconds
                    : 0d;
                Engine.LogDebug(
                    "Receiver {Receiver} 路由完成: Status={Status}, Blocks={Blocks}, Bytes={Bytes}, Targets={Targets}, ElapsedMs={ElapsedMilliseconds}, ThroughputMiBPerSecond={ThroughputMiBPerSecond:F2}, ExceptionType={ExceptionType}",
                    GetType().Name, status, ReceivedBlockCount, ReceivedByteCount, _volumes.Count,
                    stopwatch.ElapsedMilliseconds, throughput, routingError?.GetType().Name ?? "None");
            }
        }
    }

    /// <summary>启动单个卷的写入任务，并在失败时中断整个接收阶段。</summary>
    private void StartReceiver(VolumeContext context, CancellationTokenSource receiveCancellation)
    {
        Engine.LogDebug("Receiver {Receiver} 启动目标 {TargetIndex}: {OutputPath}", GetType().Name,
            context.VolumeIndex, context.OutputPath);
        var task = ReceiveVolumeAsync(context, receiveCancellation.Token);
        _receiveTasks.Add(context.VolumeIndex, task);
        _ = task.ContinueWith(
            _ => receiveCancellation.Cancel(),
            CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted,
            TaskScheduler.Default);
    }

    /// <summary>消费一个卷内有序数据流。</summary>
    /// <param name="context">卷上下文。</param>
    /// <param name="cancellationToken">取消令牌。</param>
    protected abstract Task ReceiveVolumeAsync(VolumeContext context, CancellationToken cancellationToken);
}
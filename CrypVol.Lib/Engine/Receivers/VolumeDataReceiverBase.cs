namespace CrypVol.Lib.Engine.Receivers;

/// <summary>按目标编号路由到多个输出卷的接收阶段基类。</summary>
public abstract class VolumeDataReceiverBase : DataReceiverBase
{
    private readonly Dictionary<int, VolumeContext> _volumes = new();

    /// <summary>注册一个输出目标卷。</summary>
    /// <param name="index">目标编号。</param>
    /// <param name="outputPath">输出路径。</param>
    /// <param name="preallocatedSize">预分配大小。</param>
    public VolumeDataReceiverBase AddTarget(int index, string outputPath, long preallocatedSize = 0)
    {
        _volumes.Add(index, new VolumeContext
        {
            VolumeIndex = index,
            OutputPath = outputPath,
            PreallocatedSize = preallocatedSize
        });
        return this;
    }

    /// <inheritdoc />
    public override async Task ReceiveAsync(CancellationToken cancellationToken = default)
    {
        using var receiveCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var receiveTasks = _volumes.Values
            .Select(context => ReceiveVolumeAsync(context, receiveCancellation.Token))
            .ToArray();

        foreach (var receiveTask in receiveTasks)
            _ = receiveTask.ContinueWith(
                _ => receiveCancellation.Cancel(),
                CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted,
                TaskScheduler.Default);

        Exception? routingError = null;
        try
        {
            await foreach (var block in ReadAsync(receiveCancellation.Token))
            {
                if (_volumes.TryGetValue(block.Metadata.TargetIndex, out var context))
                {
                    try
                    {
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
                await Task.WhenAll(receiveTasks);
            }
            finally
            {
                foreach (var context in _volumes.Values)
                    while (context.OutputChannel.Reader.TryRead(out var block))
                        block.Dispose();
            }
        }
    }

    /// <summary>消费一个卷内有序数据流。</summary>
    /// <param name="context">卷上下文。</param>
    /// <param name="cancellationToken">取消令牌。</param>
    protected abstract Task ReceiveVolumeAsync(VolumeContext context, CancellationToken cancellationToken);
}
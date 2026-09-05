using System.Diagnostics;
using System.Threading.Channels;
using CrypVol.Lib.Engine.Models;

namespace CrypVol.Lib.Engine.Providers;

/// <summary>数据提供阶段基类，封装 Engine 与输出通道的绑定。</summary>
public abstract class DataProviderBase : IDataProvider
{
    private long _producedBlocks;
    private long _producedBytes;
    private ChannelWriter<DataBlock>? _writer;

    /// <summary>生命周期期间注入的处理引擎。</summary>
    protected ProcessingEngine Engine { get; private set; } = null!;

    /// <inheritdoc />
    public void BindChannel(ChannelWriter<DataBlock> writer)
    {
        _writer = writer ?? throw new ArgumentNullException(nameof(writer));
    }

    /// <inheritdoc />
    public async Task InitializeAsync(ProcessingEngine engine, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(engine);
        var stopwatch = Stopwatch.StartNew();
        Engine = engine;
        try
        {
            await OnInitializeAsync(cancellationToken);
        }
        finally
        {
            Engine.LogDebug("Provider {Provider} 初始化耗时 {ElapsedMilliseconds} ms", GetType().Name,
                stopwatch.ElapsedMilliseconds);
        }
    }

    /// <inheritdoc />
    public async Task ValidateAsync(CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();
        try
        {
            await OnValidateAsync(cancellationToken);
        }
        finally
        {
            Engine.LogDebug("Provider {Provider} 静态校验耗时 {ElapsedMilliseconds} ms", GetType().Name,
                stopwatch.ElapsedMilliseconds);
        }
    }

    /// <inheritdoc />
    public async Task PrepareAsync(CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();
        try
        {
            await OnPrepareAsync(cancellationToken);
        }
        finally
        {
            Engine.LogDebug("Provider {Provider} 资源预处理耗时 {ElapsedMilliseconds} ms", GetType().Name,
                stopwatch.ElapsedMilliseconds);
        }
    }

    /// <inheritdoc />
    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();
        try
        {
            await OnStartAsync(cancellationToken);
        }
        finally
        {
            Engine.LogDebug("Provider {Provider} 启动钩子耗时 {ElapsedMilliseconds} ms", GetType().Name,
                stopwatch.ElapsedMilliseconds);
        }
    }

    /// <inheritdoc />
    public async Task DisposeAsync(CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();
        try
        {
            await OnDisposeAsync(cancellationToken);
        }
        finally
        {
            Engine.LogDebug("Provider {Provider} 释放钩子耗时 {ElapsedMilliseconds} ms", GetType().Name,
                stopwatch.ElapsedMilliseconds);
        }
    }

    /// <inheritdoc />
    public async Task ProduceAsync(CancellationToken cancellationToken = default)
    {
        var writer = _writer ?? throw new InvalidOperationException("Provider 尚未绑定输出通道。");
        var stopwatch = Stopwatch.StartNew();
        Exception? error = null;
        try
        {
            await ProduceCoreAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            error = ex;
            throw;
        }
        finally
        {
            writer.TryComplete(error);
            var status = error is null ? "Completed" : error is OperationCanceledException ? "Canceled" : "Faulted";
            var throughput = stopwatch.Elapsed.TotalSeconds > 0
                ? _producedBytes / 1024d / 1024d / stopwatch.Elapsed.TotalSeconds
                : 0d;
            Engine.LogDebug(
                "Provider {Provider} 输出完成: Status={Status}, Blocks={Blocks}, Bytes={Bytes}, ElapsedMs={ElapsedMilliseconds}, ThroughputMiBPerSecond={ThroughputMiBPerSecond:F2}, ExceptionType={ExceptionType}",
                GetType().Name, status, _producedBlocks, _producedBytes, stopwatch.ElapsedMilliseconds, throughput,
                error?.GetType().Name ?? "None");
        }
    }

    /// <summary>确认 Engine 已为 Provider 绑定输出通道。</summary>
    protected void EnsureChannelBound()
    {
        if (_writer is null) throw new InvalidOperationException("Provider 尚未绑定输出通道。");
    }

    /// <summary>写出一个数据块；反压由 Engine 创建的有界通道提供。</summary>
    /// <param name="block">待写出的数据块。</param>
    /// <param name="cancellationToken">取消令牌。</param>
    protected async Task WriteAsync(DataBlock block, CancellationToken cancellationToken = default)
    {
        Engine.LogTrace(
            "Provider {Provider} 输出块: {Path}, Seq={Sequence}, Target={TargetIndex}, Offset={Offset}, Length={Length}, Flags=0x{Flags:X2}",
            GetType().Name, block.Metadata.RelativePath, block.Metadata.Sequence, block.Metadata.TargetIndex,
            block.Metadata.SourceOffset, block.Length, block.Metadata.Flags);
        await (_writer ?? throw new InvalidOperationException("Provider 尚未绑定输出通道."))
            .WriteAsync(block, cancellationToken);
        _producedBlocks++;
        _producedBytes += block.Length;
    }

    /// <summary>Engine 注入后初始化阶段私有状态。</summary>
    protected virtual Task OnInitializeAsync(CancellationToken cancellationToken = default)
    {
        return Task.CompletedTask;
    }

    /// <summary>执行静态配置校验。</summary>
    protected virtual Task OnValidateAsync(CancellationToken cancellationToken = default)
    {
        return Task.CompletedTask;
    }

    /// <summary>在通道绑定后准备运行资源。</summary>
    protected virtual Task OnPrepareAsync(CancellationToken cancellationToken = default)
    {
        return Task.CompletedTask;
    }

    /// <summary>进入运行状态前执行阶段特定启动逻辑。</summary>
    protected virtual Task OnStartAsync(CancellationToken cancellationToken = default)
    {
        return Task.CompletedTask;
    }

    /// <summary>释放阶段特定资源。</summary>
    protected virtual Task OnDisposeAsync(CancellationToken cancellationToken = default)
    {
        return Task.CompletedTask;
    }

    /// <summary>产生数据块；基类会在本方法结束后完成输出通道。</summary>
    /// <param name="cancellationToken">取消令牌。</param>
    /// <returns>异步产生任务。</returns>
    protected abstract Task ProduceCoreAsync(CancellationToken cancellationToken = default);
}
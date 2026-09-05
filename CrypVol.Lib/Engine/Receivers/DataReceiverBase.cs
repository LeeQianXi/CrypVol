using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading.Channels;
using CrypVol.Lib.Engine.Models;

namespace CrypVol.Lib.Engine.Receivers;

/// <summary>数据接收阶段基类，封装 Engine 与最终输入通道的绑定。</summary>
public abstract class DataReceiverBase : IDataReceiver
{
    private ChannelReader<DataBlock>? _reader;

    /// <summary>生命周期期间注入的处理引擎。</summary>
    protected ProcessingEngine Engine { get; private set; } = null!;

    /// <summary>已从最终输入通道读取的数据块数量。</summary>
    protected long ReceivedBlockCount { get; private set; }

    /// <summary>已从最终输入通道读取的数据字节数。</summary>
    protected long ReceivedByteCount { get; private set; }

    /// <inheritdoc />
    public void BindChannel(ChannelReader<DataBlock> reader)
    {
        _reader = reader ?? throw new ArgumentNullException(nameof(reader));
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
            Engine.LogDebug("Receiver {Receiver} 初始化耗时 {ElapsedMilliseconds} ms", GetType().Name,
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
            Engine.LogDebug("Receiver {Receiver} 静态校验耗时 {ElapsedMilliseconds} ms", GetType().Name,
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
            Engine.LogDebug("Receiver {Receiver} 资源预处理耗时 {ElapsedMilliseconds} ms", GetType().Name,
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
            Engine.LogDebug("Receiver {Receiver} 启动钩子耗时 {ElapsedMilliseconds} ms", GetType().Name,
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
            Engine.LogDebug("Receiver {Receiver} 释放钩子耗时 {ElapsedMilliseconds} ms", GetType().Name,
                stopwatch.ElapsedMilliseconds);
        }
    }

    /// <inheritdoc />
    public abstract Task ReceiveAsync(CancellationToken cancellationToken = default);

    /// <summary>确认 Engine 已为 Receiver 绑定输入通道。</summary>
    protected void EnsureChannelBound()
    {
        if (_reader is null) throw new InvalidOperationException("Receiver 尚未绑定输入通道。");
    }

    /// <summary>读取 Engine 绑定的最终数据流。</summary>
    /// <param name="cancellationToken">取消令牌。</param>
    /// <returns>最终数据块异步流。</returns>
    protected async IAsyncEnumerable<DataBlock> ReadAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var reader = _reader ?? throw new InvalidOperationException("Receiver 尚未绑定输入通道。");
        var stopwatch = Stopwatch.StartNew();
        try
        {
            await foreach (var block in reader.ReadAllAsync(cancellationToken))
            {
                ReceivedBlockCount++;
                ReceivedByteCount += block.Length;
                Engine.LogTrace(
                    "Receiver {Receiver} 接收块: {Path}, Seq={Sequence}, Target={TargetIndex}, Length={Length}, Flags=0x{Flags:X2}",
                    GetType().Name, block.Metadata.RelativePath, block.Metadata.Sequence, block.Metadata.TargetIndex,
                    block.Length, block.Metadata.Flags);
                yield return block;
            }
        }
        finally
        {
            var status = cancellationToken.IsCancellationRequested ? "Canceled" : "Finished";
            var throughput = stopwatch.Elapsed.TotalSeconds > 0
                ? ReceivedByteCount / 1024d / 1024d / stopwatch.Elapsed.TotalSeconds
                : 0d;
            Engine.LogDebug(
                "Receiver {Receiver} 输入完成: Status={Status}, Blocks={Blocks}, Bytes={Bytes}, ElapsedMs={ElapsedMilliseconds}, ThroughputMiBPerSecond={ThroughputMiBPerSecond:F2}",
                GetType().Name, status, ReceivedBlockCount, ReceivedByteCount, stopwatch.ElapsedMilliseconds, throughput);
        }
    }

    /// <summary>Engine 注入后初始化阶段私有状态。</summary>
    /// <param name="cancellationToken">取消令牌。</param>
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
}
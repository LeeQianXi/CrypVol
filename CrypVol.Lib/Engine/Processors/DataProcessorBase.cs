using System.Diagnostics;
using System.Threading.Channels;
using CrypVol.Lib.Engine.Models;

namespace CrypVol.Lib.Engine.Processors;

/// <summary>数据处理阶段基类，封装 Engine 与相邻通道的绑定和块所有权。</summary>
public abstract class DataProcessorBase : IDataProcessor
{
    private long _filteredBlocks;
    private long _inputBlocks;
    private long _inputBytes;
    private long _outputBlocks;
    private long _outputBytes;
    private ChannelReader<DataBlock>? _reader;
    private ChannelWriter<DataBlock>? _writer;

    /// <summary>生命周期期间注入的处理引擎。</summary>
    protected ProcessingEngine Engine { get; private set; } = null!;

    /// <inheritdoc />
    public void BindChannel(ChannelReader<DataBlock> reader, ChannelWriter<DataBlock> writer)
    {
        _reader = reader ?? throw new ArgumentNullException(nameof(reader));
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
            Engine.LogDebug("Processor {Processor} 初始化耗时 {ElapsedMilliseconds} ms", GetType().Name,
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
            Engine.LogDebug("Processor {Processor} 静态校验耗时 {ElapsedMilliseconds} ms", GetType().Name,
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
            Engine.LogDebug("Processor {Processor} 资源预处理耗时 {ElapsedMilliseconds} ms", GetType().Name,
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
            Engine.LogDebug("Processor {Processor} 启动钩子耗时 {ElapsedMilliseconds} ms", GetType().Name,
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
            Engine.LogDebug("Processor {Processor} 释放钩子耗时 {ElapsedMilliseconds} ms", GetType().Name,
                stopwatch.ElapsedMilliseconds);
        }
    }

    /// <inheritdoc />
    public async Task ProcessAsync(CancellationToken cancellationToken = default)
    {
        var reader = _reader ?? throw new InvalidOperationException("Processor 尚未绑定输入通道。");
        var writer = _writer ?? throw new InvalidOperationException("Processor 尚未绑定输出通道。");
        var stopwatch = Stopwatch.StartNew();
        Exception? error = null;
        try
        {
            await foreach (var block in reader.ReadAllAsync(cancellationToken))
            {
                _inputBlocks++;
                _inputBytes += block.Length;
                DataBlock? output = null;
                try
                {
                    Engine.LogTrace(
                        "Processor {Processor} 接收块: {Path}, Seq={Sequence}, Target={TargetIndex}, Length={Length}, Flags=0x{Flags:X2}",
                        GetType().Name, block.Metadata.RelativePath, block.Metadata.Sequence, block.Metadata.TargetIndex,
                        block.Length, block.Metadata.Flags);
                    output = await ProcessBlockAsync(block, cancellationToken);
                    if (ReferenceEquals(output, block))
                        throw new InvalidOperationException("Processor 不能将输入 DataBlock 作为输出转交。");
                    if (output is not null)
                    {
                        Engine.LogTrace(
                            "Processor {Processor} 输出块: {Path}, Seq={Sequence}, Target={TargetIndex}, Length={Length}, Flags=0x{Flags:X2}",
                            GetType().Name, output.Metadata.RelativePath, output.Metadata.Sequence,
                            output.Metadata.TargetIndex, output.Length, output.Metadata.Flags);
                        await writer.WriteAsync(output, cancellationToken);
                        _outputBlocks++;
                        _outputBytes += output.Length;
                        output = null;
                    }
                    else
                    {
                        _filteredBlocks++;
                        Engine.LogTrace("Processor {Processor} 过滤块: {Path}, Seq={Sequence}", GetType().Name,
                            block.Metadata.RelativePath, block.Metadata.Sequence);
                    }
                }
                finally
                {
                    block.Dispose();
                    output?.Dispose();
                }
            }
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
                ? _outputBytes / 1024d / 1024d / stopwatch.Elapsed.TotalSeconds
                : 0d;
            Engine.LogDebug(
                "Processor {Processor} 处理完成: Status={Status}, InputBlocks={InputBlocks}, InputBytes={InputBytes}, OutputBlocks={OutputBlocks}, OutputBytes={OutputBytes}, FilteredBlocks={FilteredBlocks}, ElapsedMs={ElapsedMilliseconds}, ThroughputMiBPerSecond={ThroughputMiBPerSecond:F2}, ExceptionType={ExceptionType}",
                GetType().Name, status, _inputBlocks, _inputBytes, _outputBlocks, _outputBytes, _filteredBlocks,
                stopwatch.ElapsedMilliseconds, throughput, error?.GetType().Name ?? "None");
        }
    }

    /// <summary>确认 Engine 已为 Processor 绑定输入和输出通道。</summary>
    protected void EnsureChannelsBound()
    {
        if (_reader is null || _writer is null)
            throw new InvalidOperationException("Processor 尚未绑定输入或输出通道。");
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

    /// <summary>处理单个数据块；返回 <see langword="null" /> 可过滤该块。</summary>
    /// <param name="block">输入数据块。</param>
    /// <param name="cancellationToken">取消令牌。</param>
    /// <returns>输出数据块，或 <see langword="null" />。</returns>
    protected abstract ValueTask<DataBlock?> ProcessBlockAsync(DataBlock block,
        CancellationToken cancellationToken = default);
}
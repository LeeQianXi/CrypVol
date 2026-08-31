using System.Collections.Concurrent;
using System.Threading.Channels;
using CrypVol.Lib.Engine.Models;
using CrypVol.Lib.Engine.Processors;
using CrypVol.Lib.Engine.Providers;
using CrypVol.Lib.Engine.Receivers;
using Microsoft.Extensions.Logging;

namespace CrypVol.Lib.Engine;

/// <summary>由 EngineBuilder 构造、配置已冻结的多阶段处理引擎。</summary>
public sealed partial class ProcessingEngine
{
    private const int ChannelCapacity = 1;
    private readonly ILogger? _logger;
    private readonly IReadOnlyList<IDataProcessor> _processors;
    private readonly IDataProvider _provider;
    private readonly IDataReceiver _receiver;

    private readonly ConcurrentDictionary<string, object?> _records = new(StringComparer.Ordinal);
    private int _interrupted;
    private int _started;

    private ProcessingEngine(EngineBuilder builder)
    {
        _provider = builder.Provider;
        _processors = builder.Processors;
        _receiver = builder.Receiver;
        _logger = builder.Logger;
    }

    private IReadOnlyList<Channel<DataBlock>> Channels { get; set; } = [];

    /// <summary>当前引擎状态。</summary>
    public ProcessingEngineState State { get; private set; } = ProcessingEngineState.Ready;

    /// <summary>引擎构造完成后始终为 <see langword="true" />，表示配置不可再变更。</summary>
    public bool IsLocked => true;

    /// <summary>引擎启动前触发。</summary>
    public event EventHandler<ProcessingEngineEventArgs>? Starting;

    /// <summary>全部阶段启动并开始运行后触发。</summary>
    public event EventHandler<ProcessingEngineEventArgs>? Started;

    /// <summary>引擎成功完成后触发。</summary>
    public event EventHandler<ProcessingEngineEventArgs>? Completed;

    /// <summary>引擎失败或取消后触发。</summary>
    public event EventHandler<ProcessingEngineEventArgs>? Failed;

    /// <summary>引擎停止时始终触发。</summary>
    public event EventHandler<ProcessingEngineEventArgs>? Stopped;

    /// <summary>记录当前运行可共享的命名值，供各阶段与事件处理器交换运行信息。</summary>
    /// <param name="name">记录名称。</param>
    /// <param name="value">记录值。</param>
    public void SetRecord(string name, object? value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        _records[name] = value;
    }

    /// <summary>使用强类型键记录当前运行可共享的命名值。</summary>
    public void SetRecord<T>(EngineRecordKey<T> key, T value)
    {
        ArgumentNullException.ThrowIfNull(key);
        SetRecord(key.Name, value);
    }

    /// <summary>读取当前运行的命名记录。</summary>
    /// <typeparam name="T">记录值类型。</typeparam>
    /// <param name="name">记录名称。</param>
    /// <param name="value">读取到的记录值。</param>
    /// <returns>是否存在且类型匹配。</returns>
    public bool TryGetRecord<T>(string name, out T? value)
    {
        if (_records.TryGetValue(name, out var candidate) && candidate is T typed)
        {
            value = typed;
            return true;
        }

        value = default;
        return false;
    }

    /// <summary>使用强类型键读取当前运行记录。</summary>
    public bool TryGetRecord<T>(EngineRecordKey<T> key, out T? value)
    {
        ArgumentNullException.ThrowIfNull(key);
        return TryGetRecord(key.Name, out value);
    }

    /// <summary>记录跟踪日志，供各阶段与事件处理器调用。</summary>
    /// <param name="message">日志模板。</param>
    /// <param name="args">日志参数。</param>
    public void LogTrace(string message, params object?[] args)
    {
        _logger?.LogTrace(message, args);
    }

    /// <summary>记录信息日志，供各阶段与事件处理器调用。</summary>
    /// <param name="message">日志模板。</param>
    /// <param name="args">日志参数。</param>
    public void LogInformation(string message, params object?[] args)
    {
        _logger?.LogInformation(message, args);
    }

    /// <summary>记录警告日志，供各阶段与事件处理器调用。</summary>
    /// <param name="message">日志模板。</param>
    /// <param name="args">日志参数。</param>
    public void LogWarning(string message, params object?[] args)
    {
        _logger?.LogWarning(message, args);
    }

    /// <summary>记录错误日志，供各阶段与事件处理器调用。</summary>
    /// <param name="exception">异常。</param>
    /// <param name="message">日志模板。</param>
    /// <param name="args">日志参数。</param>
    public void LogError(Exception exception, string message, params object?[] args)
    {
        _logger?.LogError(exception, message, args);
    }

    /// <summary>一键启动引擎；每个 Processor 作为独立阶段运行，阶段间使用容量为 1 的有界通道。</summary>
    /// <param name="cancellationToken">取消令牌。</param>
    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        if (Interlocked.Exchange(ref _started, 1) != 0)
            throw new InvalidOperationException("处理引擎只能启动一次。");

        State = ProcessingEngineState.Preparing;
        using var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        try
        {
            await InitializeStagesAsync(linkedCancellation.Token);
            await ValidateStagesAsync(linkedCancellation.Token);
            await PrepareStagesAsync(linkedCancellation.Token);
            BindChannels();
            Starting?.Invoke(this, new ProcessingEngineEventArgs());
            LogInformation("数据流程启动: {ProcessorCount} 个处理器，通道容量 {ChannelCapacity}",
                _processors.Count, ChannelCapacity);

            await StartStagesAsync(linkedCancellation.Token);
            State = ProcessingEngineState.Running;
            Started?.Invoke(this, new ProcessingEngineEventArgs());

            var tasks = new List<Task>(_processors.Count + 2)
            {
                RunReceiverAsync(linkedCancellation),
                RunProviderAsync(linkedCancellation)
            };
            tasks.AddRange(_processors.Select((t, i) => RunProcessorAsync(t, i, linkedCancellation)));
            await Task.WhenAll(tasks);

            State = ProcessingEngineState.Completed;
            Completed?.Invoke(this, new ProcessingEngineEventArgs());
            LogInformation("数据流程完成");
        }
        catch (Exception ex)
        {
            await InterruptAsync(linkedCancellation, ex);
            State = ex is OperationCanceledException
                ? ProcessingEngineState.Canceled
                : ProcessingEngineState.Faulted;
            Failed?.Invoke(this, new ProcessingEngineEventArgs(ex));
            LogError(ex, "数据流程失败");
            throw;
        }
        finally
        {
            try
            {
                DrainPendingBlocks();
                await DisposeStagesAsync(CancellationToken.None);
            }
            finally
            {
                Stopped?.Invoke(this, new ProcessingEngineEventArgs());
            }
        }
    }

    private void BindChannels()
    {
        List<Channel<DataBlock>> channels = [];
        var channel = CreateChannel();
        channels.Add(channel);
        _provider.BindChannel(channel.Writer);
        var reader = channel.Reader;
        foreach (var processor in _processors)
        {
            var nextChannel = CreateChannel();
            channels.Add(nextChannel);
            processor.BindChannel(reader, nextChannel.Writer);
            reader = nextChannel.Reader;
        }

        _receiver.BindChannel(reader);
        Channels = channels.AsReadOnly();
    }

    private static Channel<DataBlock> CreateChannel()
    {
        return Channel.CreateBounded<DataBlock>(new BoundedChannelOptions(ChannelCapacity)
        {
            SingleReader = true,
            SingleWriter = true,
            FullMode = BoundedChannelFullMode.Wait
        });
    }

    private Task InitializeStagesAsync(CancellationToken cancellationToken)
    {
        return Task.WhenAll([
            _provider.InitializeAsync(this, cancellationToken),
            _receiver.InitializeAsync(this, cancellationToken),
            .. _processors.Select(p => p.InitializeAsync(this, cancellationToken))
        ]);
    }

    private Task ValidateStagesAsync(CancellationToken cancellationToken)
    {
        return Task.WhenAll([
            _provider.ValidateAsync(cancellationToken),
            _receiver.ValidateAsync(cancellationToken),
            .. _processors.Select(p => p.ValidateAsync(cancellationToken))
        ]);
    }

    private Task PrepareStagesAsync(CancellationToken cancellationToken)
    {
        return Task.WhenAll([
            _provider.PrepareAsync(cancellationToken),
            _receiver.PrepareAsync(cancellationToken),
            .. _processors.Select(p => p.PrepareAsync(cancellationToken))
        ]);
    }

    private Task StartStagesAsync(CancellationToken cancellationToken)
    {
        return Task.WhenAll([
            _provider.StartAsync(cancellationToken),
            _receiver.StartAsync(cancellationToken),
            .. _processors.Select(p => p.StartAsync(cancellationToken))
        ]);
    }

    private Task DisposeStagesAsync(CancellationToken cancellationToken)
    {
        return Task.WhenAll([
            _provider.DisposeAsync(cancellationToken),
            _receiver.DisposeAsync(cancellationToken),
            .. _processors.Select(p => p.DisposeAsync(cancellationToken))
        ]);
    }

    private async Task RunProviderAsync(CancellationTokenSource cancellation)
    {
        try
        {
            await _provider.ProduceAsync(cancellation.Token);
        }
        catch (Exception ex)
        {
            await InterruptAsync(cancellation, ex);
            throw;
        }
    }

    private async Task RunProcessorAsync(IDataProcessor processor, int index, CancellationTokenSource cancellation)
    {
        try
        {
            await processor.ProcessAsync(cancellation.Token);
        }
        catch (Exception ex)
        {
            await InterruptAsync(cancellation, ex);
            throw;
        }
    }

    private async Task RunReceiverAsync(CancellationTokenSource cancellation)
    {
        try
        {
            await _receiver.ReceiveAsync(cancellation.Token);
        }
        catch (Exception ex)
        {
            await InterruptAsync(cancellation, ex);
            throw;
        }
    }

    /// <summary>中断全部阶段，解除通道写入等待并保留最先发生的失败原因。</summary>
    /// <param name="cancellation">当前流程共享的取消源。</param>
    /// <param name="error">触发中断的异常。</param>
    private async Task InterruptAsync(CancellationTokenSource cancellation, Exception? error)
    {
        if (Interlocked.Exchange(ref _interrupted, 1) != 0)
            return;

        foreach (var channel in Channels)
            channel.Writer.TryComplete(error);

        await cancellation.CancelAsync();
    }

    /// <summary>在所有阶段退出后释放通道中尚未消费的数据块。</summary>
    private void DrainPendingBlocks()
    {
        foreach (var channel in Channels)
            while (channel.Reader.TryRead(out var block))
                block.Dispose();
    }

    public static EngineBuilder Builder()
    {
        return new EngineBuilder();
    }
}

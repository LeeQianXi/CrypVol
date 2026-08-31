using CrypVol.Lib.Engine.Models;

namespace CrypVol.Lib.Engine;

/// <summary>通过 Engine Hook 观察一次运行并捕获指定运行记录。</summary>
public sealed class ProcessingEngineObserver : IDisposable
{
    private readonly ProcessingEngine _engine;
    private readonly List<Action<ProcessingEngine>> _recordCaptures = [];
    private readonly Dictionary<string, object?> _records = new(StringComparer.Ordinal);

    /// <summary>创建并立即订阅引擎事件的观察器。</summary>
    /// <param name="engine">被观察的已构造引擎。</param>
    public ProcessingEngineObserver(ProcessingEngine engine)
    {
        _engine = engine ?? throw new ArgumentNullException(nameof(engine));
        _engine.Started += OnStarted;
        _engine.Completed += OnCompleted;
        _engine.Failed += OnFailed;
        _engine.Stopped += OnStopped;
    }

    /// <summary>引擎实际开始处理的时间。</summary>
    public DateTimeOffset? StartedAt { get; private set; }

    /// <summary>引擎停止的时间。</summary>
    public DateTimeOffset? StoppedAt { get; private set; }

    /// <summary>失败 Hook 捕获的异常。</summary>
    public Exception? Exception { get; private set; }

    /// <inheritdoc />
    public void Dispose()
    {
        _engine.Started -= OnStarted;
        _engine.Completed -= OnCompleted;
        _engine.Failed -= OnFailed;
        _engine.Stopped -= OnStopped;
    }

    /// <summary>在 Completed Hook 中捕获一个强类型运行记录。</summary>
    /// <typeparam name="T">记录值类型。</typeparam>
    /// <param name="key">待捕获的记录键。</param>
    public void Capture<T>(EngineRecordKey<T> key)
    {
        ArgumentNullException.ThrowIfNull(key);
        _recordCaptures.Add(engine =>
        {
            if (engine.TryGetRecord(key, out var value)) _records[key.Name] = value;
        });
    }

    /// <summary>启动被观察引擎。</summary>
    /// <param name="cancellationToken">取消令牌。</param>
    public Task RunAsync(CancellationToken cancellationToken = default)
    {
        return _engine.StartAsync(cancellationToken);
    }

    /// <summary>读取已由 Completed Hook 捕获的运行记录。</summary>
    /// <typeparam name="T">记录值类型。</typeparam>
    /// <param name="key">记录键。</param>
    /// <param name="value">捕获的值。</param>
    /// <returns>是否已捕获且类型匹配。</returns>
    public bool TryGetCaptured<T>(EngineRecordKey<T> key, out T? value)
    {
        if (_records.TryGetValue(key.Name, out var candidate) && candidate is T typed)
        {
            value = typed;
            return true;
        }

        value = default;
        return false;
    }

    private void OnStarted(object? sender, ProcessingEngineEventArgs eventArgs)
    {
        StartedAt = DateTimeOffset.UtcNow;
    }

    private void OnCompleted(object? sender, ProcessingEngineEventArgs eventArgs)
    {
        foreach (var capture in _recordCaptures) capture(_engine);
    }

    private void OnFailed(object? sender, ProcessingEngineEventArgs eventArgs)
    {
        Exception = eventArgs.Exception;
    }

    private void OnStopped(object? sender, ProcessingEngineEventArgs eventArgs)
    {
        StoppedAt = DateTimeOffset.UtcNow;
    }
}
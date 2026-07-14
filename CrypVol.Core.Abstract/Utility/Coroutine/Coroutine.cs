// ReSharper disable CheckNamespace

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using Avalonia.Threading;
using CrypVol.Core.Abstract.Utility.Coroutine;

namespace AvaloniaUtility;

public interface ICoroutine : IDisposable, IAsyncDisposable
{
    public Status CoroutineStatus { get; }
    void Continue();
    void Stop();

    /// <summary>
    ///     Coroutine完成回调
    /// </summary>
    event Action? Completed;

    /// <summary>
    ///     Coroutine失败回调
    /// </summary>
    event Action<Exception?>? Failed;
}

public enum Status
{
    /// 刚创建
    New,

    /// 空闲
    Free,

    /// 正在运行
    Running,

    /// 被暂停运行
    Stopping,

    /// 等待耗时任务
    Waiting,

    /// 已完成
    Completed,

    /// 失败
    Failed,

    /// 销毁
    Disposed
}

public sealed class Coroutine : ICoroutine
{
    private readonly IAsyncEnumerator<YieldInstruction?>? _asyncIter;
    private readonly bool _isAsync;
    private readonly SemaphoreSlim _sync = new(1, 1);
    private readonly IEnumerator<YieldInstruction?>? _syncIter;
    private readonly CancellationToken _token;
    private volatile Status _status = Status.New;

    internal Coroutine(IEnumerator<YieldInstruction?> iter, bool createRunning, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(iter);
        _isAsync = false;
        _syncIter = iter;
        _token = token;
        Internal.RegisterInstance(this);
        if (createRunning) _status = Status.Free;
    }

    internal Coroutine(IAsyncEnumerator<YieldInstruction?> iter, bool createRunning, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(iter);
        _isAsync = true;
        _asyncIter = iter;
        _token = token;
        Internal.RegisterInstance(this);
        if (createRunning) _status = Status.Free;
    }

    public void Continue()
    {
        _sync.Wait(_token);
        if (_status is Status.New or Status.Stopping) _status = Status.Free;
        _sync.Release();
    }

    public void Stop()
    {
        _sync.Wait(_token);
        if (_status is Status.Free) _status = Status.Stopping;
        _sync.Release();
    }

    public event Action? Completed;
    public event Action<Exception?>? Failed;

    public Status CoroutineStatus => _status;

    public void Dispose()
    {
        _status = Status.Disposed;
        if (_isAsync)
            _ = _asyncIter?.DisposeAsync();
        else
            _syncIter?.Dispose();
    }

    public async ValueTask DisposeAsync()
    {
        _status = Status.Disposed;
        if (_isAsync)
            await (_asyncIter?.DisposeAsync() ?? ValueTask.CompletedTask);
        else
            _syncIter?.Dispose();
    }

    ~Coroutine()
    {
        Dispose();
    }

    private async Task OnTick()
    {
        //阻止重入
        if (!await _sync.WaitAsync(TimeSpan.FromMilliseconds(Internal.FrameTimeMs * 2), _token))
            return;
        var start = Internal.Sw.Elapsed.TotalMilliseconds;
        try
        {
            if (_status is Status.Stopping) return;
            //到此处Status必定为Running
            var (hasNext, nextInstruction) = await MoveToNextInstructionAsync().ConfigureAwait(false);
            if (!hasNext)
            {
                CompleteCoroutine();
                return;
            }

            if (nextInstruction is not null)
                await ExecuteYieldInstructionAsync(nextInstruction).ConfigureAwait(false);
            _status = Status.Free;
        }
        catch (Exception ex)
        {
        }
        finally
        {
            Internal.Accumulator -= Internal.Sw.Elapsed.TotalMilliseconds - start;
            _sync.Release();
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private async ValueTask<(bool, YieldInstruction?)> MoveToNextInstructionAsync()
    {
        try
        {
            if (_isAsync)
            {
                if (!await _asyncIter!.MoveNextAsync().ConfigureAwait(false)) return (false, null);
                return (true, _asyncIter.Current);
            }

            if (!_syncIter!.MoveNext()) return (false, null);
            return (true, _syncIter.Current);
        }
        catch (Exception ex)
        {
            HandleCoroutineException(ex);
            throw;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void CompleteCoroutine()
    {
        if (_status is Status.Running or Status.Waiting or Status.Free)
        {
            _status = Status.Completed;
            Completed?.Invoke();
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private async ValueTask ExecuteYieldInstructionAsync(YieldInstruction instruction)
    {
        ArgumentNullException.ThrowIfNull(instruction);
        _status = Status.Waiting;
        try
        {
            await instruction.Execute(_token).ConfigureAwait(false);
            _status = Status.Running;
        }
        catch (Exception ex)
        {
            HandleCoroutineException(ex);
        }
    }

    private void HandleCoroutineException(Exception ex)
    {
        if (ex is OperationCanceledException)
            CompleteCoroutine();
        _status = Status.Failed;
        Failed?.Invoke(ex);
    }


    private static class Internal
    {
        public const double FrameTimeMs = 1_000d / 90d;
        public const double MaxFrameTimeMs = 1_000d / 10d;

        private static readonly DispatcherTimer GlobalTimer;
        internal static readonly Stopwatch Sw;
        internal static double Accumulator;

        private static readonly HashSet<Coroutine> Instances = [];
        private static readonly ConcurrentQueue<Coroutine> ToAdd = [];

        static Internal()
        {
            Sw = Stopwatch.StartNew();
            GlobalTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromMilliseconds(1)
            };
            GlobalTimer.Tick += OnGlobalTick;
            GlobalTimer.Start();
        }

        private static void OnGlobalTick(object? sender, EventArgs e)
        {
            var delta = Sw.Elapsed.TotalMilliseconds;
            Sw.Restart();
            Accumulator += delta;
            if (Accumulator > FrameTimeMs)
                OnGlobalFrame();
            Accumulator %= FrameTimeMs;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void OnGlobalFrame()
        {
            Instances.UnionWith(ToAdd);
            ToAdd.Clear();
            List<Coroutine>? toRemove = null;
            foreach (var cor in Instances)
                switch (Interlocked.CompareExchange(ref cor._status, Status.Running, Status.Free))
                {
                    case Status.Free:
                        Dispatcher.UIThread.Invoke(cor.OnTick);
                        break;
                    case Status.Completed:
                    case Status.Failed:
                        cor.Dispose();
                        break;
                    case Status.Disposed:
                        (toRemove ??= []).Add(cor);
                        break;
                }

            if (toRemove is null) return;
            Instances.ExceptWith(toRemove);
        }

        public static void RegisterInstance(Coroutine coroutine)
        {
            ArgumentNullException.ThrowIfNull(coroutine);
            ToAdd.Enqueue(coroutine);
        }
    }
}
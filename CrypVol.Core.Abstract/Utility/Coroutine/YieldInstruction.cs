namespace CrypVol.Core.Abstract.Utility.Coroutine;

public abstract record YieldInstruction
{
    internal virtual Task Execute(CancellationToken token)
    {
        return Task.CompletedTask;
    }
}

public sealed record WaitForSeconds : YieldInstruction
{
    private readonly TimeProvider _timeProvider;
    private readonly TimeSpan _timeSpan;

    public WaitForSeconds(int milliseconds) : this(TimeSpan.FromMilliseconds(milliseconds))
    {
    }

    public WaitForSeconds(TimeSpan timeSpan) : this(timeSpan, TimeProvider.System)
    {
    }

    public WaitForSeconds(TimeSpan timeSpan, TimeProvider timeProvider)
    {
        _timeSpan = timeSpan;
        _timeProvider = timeProvider;
    }

    internal override async Task Execute(CancellationToken token)
    {
        await Task.Delay(_timeSpan, _timeProvider, token);
    }
}

public sealed record WaitForTask : YieldInstruction
{
    private readonly Task _task;

    public WaitForTask(Task task)
    {
        _task = task;
    }

    internal override async Task Execute(CancellationToken token)
    {
        try
        {
            await _task.WaitAsync(token).ConfigureAwait(false);
        }
        catch (TaskCanceledException)
        {
        }
    }
}

public sealed record WaitWhenCondition : YieldInstruction
{
    private readonly bool _condition;
    private readonly TimeSpan _pollingInterval;
    private readonly Func<CancellationToken, Task<bool>> _predicate;

    public WaitWhenCondition(Func<CancellationToken, Task<bool>> predicate, bool condition = true,
        TimeSpan? pollingInterval = null)
    {
        _predicate = predicate ?? throw new ArgumentNullException(nameof(predicate));
        _predicate = predicate;
        _condition = condition;
        _pollingInterval = pollingInterval ?? TimeSpan.FromMilliseconds(50); // 默认轮询间隔
    }

    public WaitWhenCondition(Func<bool> predicate, bool condition = true, TimeSpan? pollingInterval = null)
        : this(_ => Task.FromResult(predicate()), condition, pollingInterval)
    {
    }

    internal override async Task Execute(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            var cond = await _predicate(token).ConfigureAwait(false);
            if (cond == _condition) return;
            try
            {
                await Task.Delay(_pollingInterval, token).ConfigureAwait(false);
            }
            catch (TaskCanceledException)
            {
                break;
            }
        }

        token.ThrowIfCancellationRequested();
    }

    public static WaitWhenCondition UntilTrue(Func<bool> predicate, TimeSpan? pollingInterval = null)
    {
        return new WaitWhenCondition(_ => Task.FromResult(predicate()), true,
            pollingInterval ?? TimeSpan.FromMilliseconds(50));
    }

    public static WaitWhenCondition UntilTrue(Func<CancellationToken, Task<bool>> predicate,
        TimeSpan? pollingInterval = null)
    {
        return new WaitWhenCondition(predicate, true, pollingInterval ?? TimeSpan.FromMilliseconds(50));
    }

    public static WaitWhenCondition UntilFalse(Func<bool> predicate, TimeSpan? pollingInterval = null)
    {
        return new WaitWhenCondition(_ => Task.FromResult(predicate()), false,
            pollingInterval ?? TimeSpan.FromMilliseconds(50));
    }

    public static WaitWhenCondition UntilFalse(Func<CancellationToken, Task<bool>> predicate,
        TimeSpan? pollingInterval = null)
    {
        return new WaitWhenCondition(predicate, false, pollingInterval ?? TimeSpan.FromMilliseconds(50));
    }
}
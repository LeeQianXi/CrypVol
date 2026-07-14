// ReSharper disable CheckNamespace

using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using AvaloniaUtility;
using CrypVol.Core.Abstract.Utility.Coroutine;

namespace CrypVol.Core.Abstract;

public interface ICoroutinator
{
    CancellationTokenSource CoroutineCancelTokenSource { get; }
}

[SuppressMessage("Performance", "CA1822:将成员标记为 static")]
public static class Extensions
{
    extension(ICoroutinator cor)
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public ICoroutine StartCoroutine(Func<IEnumerator<YieldInstruction?>> routine, bool createRunning = true)
        {
            ArgumentNullException.ThrowIfNull(cor);
            ArgumentNullException.ThrowIfNull(routine);
            return new Coroutine(routine.Invoke(), createRunning, cor.CoroutineCancelTokenSource.Token);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public ICoroutine StartCoroutine(Func<IAsyncEnumerator<YieldInstruction?>> routine, bool createRunning = true)
        {
            ArgumentNullException.ThrowIfNull(cor);
            ArgumentNullException.ThrowIfNull(routine);
            return new Coroutine(routine.Invoke(), createRunning, cor.CoroutineCancelTokenSource.Token);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public ICoroutine StartCoroutine(Func<CancellationToken, IEnumerator<YieldInstruction?>> routine,
            bool createRunning = true)
        {
            ArgumentNullException.ThrowIfNull(cor);
            ArgumentNullException.ThrowIfNull(routine);
            return new Coroutine(routine.Invoke(cor.CoroutineCancelTokenSource.Token), createRunning,
                cor.CoroutineCancelTokenSource.Token);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public ICoroutine StartCoroutine(Func<CancellationToken, IAsyncEnumerator<YieldInstruction?>> routine,
            bool createRunning = true)
        {
            ArgumentNullException.ThrowIfNull(cor);
            ArgumentNullException.ThrowIfNull(routine);
            return new Coroutine(routine.Invoke(cor.CoroutineCancelTokenSource.Token), createRunning,
                cor.CoroutineCancelTokenSource.Token);
        }
    }
}
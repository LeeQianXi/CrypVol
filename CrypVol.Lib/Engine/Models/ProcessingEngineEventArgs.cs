namespace CrypVol.Lib.Engine.Models;

/// <summary>引擎事件参数。</summary>
public sealed class ProcessingEngineEventArgs : EventArgs
{
    /// <summary>创建引擎事件参数。</summary>
    /// <param name="exception">失败事件的异常；其他事件为 <see langword="null" />。</param>
    public ProcessingEngineEventArgs(Exception? exception = null)
    {
        Exception = exception;
    }

    /// <summary>失败事件关联的异常。</summary>
    public Exception? Exception { get; }
}
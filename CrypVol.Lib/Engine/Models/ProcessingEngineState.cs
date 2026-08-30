namespace CrypVol.Lib.Engine.Models;

/// <summary>处理引擎的运行状态。</summary>
public enum ProcessingEngineState
{
    /// <summary>已构造、尚未启动。</summary>
    Ready,

    /// <summary>启动前准备。</summary>
    Preparing,

    /// <summary>正在处理。</summary>
    Running,

    /// <summary>处理成功完成。</summary>
    Completed,

    /// <summary>处理被取消。</summary>
    Canceled,

    /// <summary>处理失败。</summary>
    Faulted
}
namespace CrypVol.Lib.Engine;

/// <summary>异步阶段的启动、校验、预处理与停止生命周期。</summary>
public interface IAsyncLifeCycle
{
    /// <summary>注入引擎并初始化阶段内部状态。</summary>
    /// <param name="engine">当前处理引擎。</param>
    /// <param name="cancellationToken">取消令牌。</param>
    Task InitializeAsync(ProcessingEngine engine, CancellationToken cancellationToken = default);

    /// <summary>校验阶段配置与运行前置条件。</summary>
    /// <param name="cancellationToken">取消令牌。</param>
    Task ValidateAsync(CancellationToken cancellationToken = default);

    /// <summary>执行启动前预处理。</summary>
    /// <param name="cancellationToken">取消令牌。</param>
    Task PrepareAsync(CancellationToken cancellationToken = default);

    /// <summary>通知阶段开始运行。</summary>
    /// <param name="cancellationToken">取消令牌。</param>
    Task StartAsync(CancellationToken cancellationToken = default);

    /// <summary>销毁阶段执行销毁逻辑</summary>
    /// <param name="cancellationToken">取消令牌。</param>
    Task DisposeAsync(CancellationToken cancellationToken = default);
}
namespace CrypVol.Lib.Engine;

/// <summary>异步阶段的初始化、静态校验、通道绑定后预处理、启动与释放生命周期。</summary>
public interface IAsyncLifeCycle
{
    /// <summary>注入引擎并初始化阶段内部状态。</summary>
    /// <param name="engine">当前处理引擎。</param>
    /// <param name="cancellationToken">取消令牌。</param>
    Task InitializeAsync(ProcessingEngine engine, CancellationToken cancellationToken = default);

    /// <summary>静态校验阶段配置与运行前置条件，不应处理数据或创建运行资源。</summary>
    /// <param name="cancellationToken">取消令牌。</param>
    Task ValidateAsync(CancellationToken cancellationToken = default);

    /// <summary>在 Engine 完成通道绑定后执行启动前资源预处理。</summary>
    /// <param name="cancellationToken">取消令牌。</param>
    Task PrepareAsync(CancellationToken cancellationToken = default);

    /// <summary>通知阶段开始运行。</summary>
    /// <param name="cancellationToken">取消令牌。</param>
    Task StartAsync(CancellationToken cancellationToken = default);

    /// <summary>销毁阶段执行销毁逻辑</summary>
    /// <param name="cancellationToken">取消令牌。</param>
    Task DisposeAsync(CancellationToken cancellationToken = default);
}
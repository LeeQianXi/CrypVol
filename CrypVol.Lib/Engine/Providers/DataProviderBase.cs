using System.Threading.Channels;
using CrypVol.Lib.Engine.Models;

namespace CrypVol.Lib.Engine.Providers;

/// <summary>数据提供阶段基类，封装 Engine 与输出通道的绑定。</summary>
public abstract class DataProviderBase : IDataProvider
{
    private ChannelWriter<DataBlock>? _writer;

    /// <summary>生命周期期间注入的处理引擎。</summary>
    protected ProcessingEngine Engine { get; private set; } = null!;

    /// <inheritdoc />
    public void BindChannel(ChannelWriter<DataBlock> writer)
    {
        _writer = writer ?? throw new ArgumentNullException(nameof(writer));
    }

    /// <inheritdoc />
    public async Task InitializeAsync(ProcessingEngine engine, CancellationToken cancellationToken = default)
    {
        Engine = engine ?? throw new ArgumentNullException(nameof(engine));
        await OnInitializeAsync(cancellationToken);
    }

    /// <inheritdoc />
    public virtual Task ValidateAsync(CancellationToken cancellationToken = default)
    {
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public virtual Task PrepareAsync(CancellationToken cancellationToken = default)
    {
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public virtual Task StartAsync(CancellationToken cancellationToken = default)
    {
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public virtual Task DisposeAsync(CancellationToken cancellationToken = default)
    {
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public async Task ProduceAsync(CancellationToken cancellationToken = default)
    {
        var writer = _writer ?? throw new InvalidOperationException("Provider 尚未绑定输出通道。");
        Exception? error = null;
        try
        {
            await ProduceCoreAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            error = ex;
            throw;
        }
        finally
        {
            writer.TryComplete(error);
            if (error is null) Engine.LogDebug("Provider {Provider} 已完成输出通道", GetType().Name);
            else
                Engine.LogDebug("Provider {Provider} 因 {ExceptionType} 完成输出通道", GetType().Name,
                    error.GetType().Name);
        }
    }

    /// <summary>写出一个数据块；反压由 Engine 创建的有界通道提供。</summary>
    /// <param name="block">待写出的数据块。</param>
    /// <param name="cancellationToken">取消令牌。</param>
    protected async Task WriteAsync(DataBlock block, CancellationToken cancellationToken = default)
    {
        Engine.LogTrace(
            "Provider {Provider} 输出块: {Path}, Seq={Sequence}, Target={TargetIndex}, Offset={Offset}, Length={Length}, Flags=0x{Flags:X2}",
            GetType().Name, block.Metadata.RelativePath, block.Metadata.Sequence, block.Metadata.TargetIndex,
            block.Metadata.SourceOffset, block.Length, block.Metadata.Flags);
        await (_writer ?? throw new InvalidOperationException("Provider 尚未绑定输出通道."))
            .WriteAsync(block, cancellationToken);
    }

    /// <summary>Engine 注入后初始化阶段私有状态。</summary>
    /// <param name="cancellationToken">取消令牌。</param>
    protected virtual Task OnInitializeAsync(CancellationToken cancellationToken = default)
    {
        return Task.CompletedTask;
    }

    /// <summary>产生数据块；基类会在本方法结束后完成输出通道。</summary>
    /// <param name="cancellationToken">取消令牌。</param>
    /// <returns>异步产生任务。</returns>
    protected abstract Task ProduceCoreAsync(CancellationToken cancellationToken = default);
}
using System.Threading.Channels;
using CrypVol.Lib.Engine.Models;

namespace CrypVol.Lib.Engine.Receivers;

/// <summary>数据接收阶段基类，封装 Engine 与最终输入通道的绑定。</summary>
public abstract class DataReceiverBase : IDataReceiver
{
    private ChannelReader<DataBlock>? _reader;

    /// <summary>生命周期期间注入的处理引擎。</summary>
    protected ProcessingEngine Engine { get; private set; } = null!;

    /// <inheritdoc />
    public void BindChannel(ChannelReader<DataBlock> reader)
    {
        _reader = reader ?? throw new ArgumentNullException(nameof(reader));
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
    public abstract Task ReceiveAsync(CancellationToken cancellationToken = default);

    /// <summary>读取 Engine 绑定的最终数据流。</summary>
    /// <param name="cancellationToken">取消令牌。</param>
    /// <returns>最终数据块异步流。</returns>
    protected IAsyncEnumerable<DataBlock> ReadAsync(CancellationToken cancellationToken = default)
    {
        return (_reader ?? throw new InvalidOperationException("Receiver 尚未绑定输入通道。"))
            .ReadAllAsync(cancellationToken);
    }

    /// <summary>Engine 注入后初始化阶段私有状态。</summary>
    /// <param name="cancellationToken">取消令牌。</param>
    protected virtual Task OnInitializeAsync(CancellationToken cancellationToken = default)
    {
        return Task.CompletedTask;
    }
}
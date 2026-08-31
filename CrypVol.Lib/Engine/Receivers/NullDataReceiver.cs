namespace CrypVol.Lib.Engine.Receivers;

/// <summary>消费并释放全部数据块、不产生外部输出的接收阶段。</summary>
public sealed class NullDataReceiver : DataReceiverBase
{
    /// <inheritdoc />
    public override async Task ReceiveAsync(CancellationToken cancellationToken = default)
    {
        await foreach (var block in ReadAsync(cancellationToken))
            block.Dispose();
    }
}
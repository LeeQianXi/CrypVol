using System.Threading.Channels;
using CrypVol.Lib.Engine.Models;

namespace CrypVol.Lib.Engine.Receivers;

/// <summary>处理流程的数据接收阶段。</summary>
public interface IDataReceiver : IAsyncLifeCycle
{
    /// <summary>从 Engine 绑定的最终输入通道接收数据块。</summary>
    /// <param name="cancellationToken">取消令牌。</param>
    Task ReceiveAsync(CancellationToken cancellationToken = default);

    void BindChannel(ChannelReader<DataBlock> reader);
}
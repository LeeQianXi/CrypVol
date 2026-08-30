using System.Threading.Channels;
using CrypVol.Lib.Engine.Models;

namespace CrypVol.Lib.Engine.Providers;

/// <summary>处理流程的数据提供阶段。</summary>
public interface IDataProvider : IAsyncLifeCycle
{
    /// <summary>将数据块写入 Engine 绑定的输出通道，并在结束时完成该输出通道。</summary>
    /// <param name="cancellationToken">取消令牌。</param>
    Task ProduceAsync(CancellationToken cancellationToken = default);

    void BindChannel(ChannelWriter<DataBlock> writer);
}
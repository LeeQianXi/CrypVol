using System.Threading.Channels;
using CrypVol.Lib.Engine.Models;

namespace CrypVol.Lib.Engine.Processors;

/// <summary>处理流程的单阶段数据处理器。</summary>
public interface IDataProcessor : IAsyncLifeCycle
{
    /// <summary>从 Engine 绑定的输入通道读取并写入其输出通道，结束时完成输出通道。</summary>
    /// <param name="cancellationToken">取消令牌。</param>
    Task ProcessAsync(CancellationToken cancellationToken = default);

    void BindChannel(ChannelReader<DataBlock> reader, ChannelWriter<DataBlock> writer);
}
using System.Threading.Channels;
using CrypVol.Lib.Engine.Models;

namespace CrypVol.Lib.Engine.Processors;

/// <summary>数据处理阶段基类，封装 Engine 与相邻通道的绑定和块所有权。</summary>
public abstract class DataProcessorBase : IDataProcessor
{
    private ChannelReader<DataBlock>? _reader;
    private ChannelWriter<DataBlock>? _writer;

    /// <summary>生命周期期间注入的处理引擎。</summary>
    protected ProcessingEngine Engine { get; private set; } = null!;

    /// <inheritdoc />
    public void BindChannel(ChannelReader<DataBlock> reader, ChannelWriter<DataBlock> writer)
    {
        _reader = reader ?? throw new ArgumentNullException(nameof(reader));
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
    public async Task ProcessAsync(CancellationToken cancellationToken = default)
    {
        var reader = _reader ?? throw new InvalidOperationException("Processor 尚未绑定输入通道。");
        var writer = _writer ?? throw new InvalidOperationException("Processor 尚未绑定输出通道。");
        Exception? error = null;
        try
        {
            await foreach (var block in reader.ReadAllAsync(cancellationToken))
            {
                DataBlock? output = null;
                try
                {
                    Engine.LogTrace(
                        "Processor {Processor} 接收块: {Path}, Seq={Sequence}, Target={TargetIndex}, Length={Length}, Flags=0x{Flags:X2}",
                        GetType().Name, block.Metadata.RelativePath, block.Metadata.Sequence, block.Metadata.TargetIndex,
                        block.Length, block.Metadata.Flags);
                    output = await ProcessBlockAsync(block, cancellationToken);
                    if (ReferenceEquals(output, block))
                        throw new InvalidOperationException("Processor 不能将输入 DataBlock 作为输出转交。");
                    if (output is not null)
                    {
                        Engine.LogTrace(
                            "Processor {Processor} 输出块: {Path}, Seq={Sequence}, Target={TargetIndex}, Length={Length}, Flags=0x{Flags:X2}",
                            GetType().Name, output.Metadata.RelativePath, output.Metadata.Sequence,
                            output.Metadata.TargetIndex, output.Length, output.Metadata.Flags);
                        await writer.WriteAsync(output, cancellationToken);
                        output = null;
                    }
                    else
                    {
                        Engine.LogTrace("Processor {Processor} 过滤块: {Path}, Seq={Sequence}", GetType().Name,
                            block.Metadata.RelativePath, block.Metadata.Sequence);
                    }
                }
                finally
                {
                    block.Dispose();
                    output?.Dispose();
                }
            }
        }
        catch (Exception ex)
        {
            error = ex;
            throw;
        }
        finally
        {
            writer.TryComplete(error);
            if (error is null) Engine.LogDebug("Processor {Processor} 已完成输出通道", GetType().Name);
            else
                Engine.LogDebug("Processor {Processor} 因 {ExceptionType} 完成输出通道", GetType().Name,
                    error.GetType().Name);
        }
    }

    /// <summary>Engine 注入后初始化阶段私有状态。</summary>
    /// <param name="cancellationToken">取消令牌。</param>
    protected virtual Task OnInitializeAsync(CancellationToken cancellationToken = default)
    {
        return Task.CompletedTask;
    }

    /// <summary>处理单个数据块；返回 <see langword="null" /> 可过滤该块。</summary>
    /// <param name="block">输入数据块。</param>
    /// <param name="cancellationToken">取消令牌。</param>
    /// <returns>输出数据块，或 <see langword="null" />。</returns>
    protected abstract ValueTask<DataBlock?> ProcessBlockAsync(DataBlock block,
        CancellationToken cancellationToken = default);
}
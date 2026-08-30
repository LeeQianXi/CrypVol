using System.Buffers;
using CrypVol.Lib.Engine;
using CrypVol.Lib.Engine.Models;
using CrypVol.Lib.Engine.Processors;
using CrypVol.Lib.Engine.Providers;
using CrypVol.Lib.Engine.Receivers;
using Xunit;

namespace CrypVol.Tests;

/// <summary>验证具备有界通道、事件和专用阶段生命周期的处理引擎。</summary>
public sealed class ProcessingEngineTests
{
    /// <summary>处理器应按注册顺序连接，并在内部通过 Engine 完成通信。</summary>
    [Fact]
    public async Task StartAsync_ConnectsOrderedProcessorStages()
    {
        var metadata = CreateMetadata();
        var provider = new SingleBlockProvider(metadata, 2);
        var firstProcessor = new AppendProcessor(3);
        var secondProcessor = new AppendProcessor(4);
        var receiver = new CollectingReceiver();
        var engine = ProcessingEngine.Builder()
            .UseProvider(provider)
            .AddProcessor(firstProcessor)
            .AddProcessor(secondProcessor)
            .UseReceiver(receiver)
            .Build();

        await engine.StartAsync();

        var received = Assert.Single(receiver.Blocks);
        Assert.Same(metadata, received.Metadata);
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, received.Data.ToArray());
        Assert.Equal(new[] { "initialize", "validate", "prepare", "start", "process", "dispose" },
            firstProcessor.LifeCycle);
        Assert.Equal(new[] { "initialize", "validate", "prepare", "start", "process", "dispose" },
            secondProcessor.LifeCycle);
        Assert.True(engine.TryGetRecord<int>("processed-blocks", out var processedBlocks));
        Assert.Equal(2, processedBlocks);
        received.Dispose();
    }

    /// <summary>引擎生命周期应通过标准事件触发，而不是通过处理器 Hook 触发。</summary>
    [Fact]
    public async Task StartAsync_RaisesEngineEvents()
    {
        var events = new List<string>();
        var engine = ProcessingEngine.Builder()
            .UseProvider(new SingleBlockProvider(CreateMetadata(), 1))
            .UseReceiver(new CollectingReceiver())
            .Build();
        engine.Starting += (_, _) => events.Add("starting");
        engine.Started += (_, _) => events.Add("started");
        engine.Completed += (_, _) => events.Add("completed");
        engine.Stopped += (_, _) => events.Add("stopped");

        await engine.StartAsync();

        Assert.Equal(new[] { "starting", "started", "completed", "stopped" }, events);
    }

    /// <summary>构造完成后 EngineBuilder 应锁定。</summary>
    [Fact]
    public void Build_LocksBuilder()
    {
        var builder = ProcessingEngine.Builder()
            .UseProvider(new SingleBlockProvider(CreateMetadata(), 1))
            .UseReceiver(new CollectingReceiver());

        var engine = builder.Build();

        Assert.True(engine.IsLocked);
        Assert.Throws<InvalidOperationException>(() => builder.AddProcessor(new AppendProcessor(3)));
    }

    /// <summary>缺少数据提供者时 EngineBuilder 应拒绝构造流程。</summary>
    [Fact]
    public void Build_WithoutProvider_Throws()
    {
        var builder = ProcessingEngine.Builder().UseReceiver(new CollectingReceiver());
        Assert.Throws<InvalidOperationException>(() => builder.Build());
    }

    /// <summary>任一处理阶段失败时，引擎应取消所有阶段并完成其释放生命周期。</summary>
    [Fact]
    public async Task StartAsync_ProcessorFailure_InterruptsAllStages()
    {
        var provider = new WaitingProvider(CreateMetadata());
        var processor = new FailingProcessor();
        var receiver = new CancellationObservingReceiver();
        var engine = ProcessingEngine.Builder()
            .UseProvider(provider)
            .AddProcessor(processor)
            .UseReceiver(receiver)
            .Build();

        await Assert.ThrowsAsync<InvalidDataException>(() => engine.StartAsync());

        Assert.Equal(ProcessingEngineState.Faulted, engine.State);
        Assert.True(provider.Canceled);
        Assert.True(provider.Disposed);
        Assert.True(processor.Disposed);
        Assert.True(receiver.Disposed);
    }

    private static BlockMetadata CreateMetadata()
    {
        return new BlockMetadata
        {
            RelativePath = "data.bin",
            SourceFullPath = "/tmp/data.bin",
            TargetIndex = 0,
            Length = 2
        };
    }

    /// <summary>仅提供一个数据块的测试提供阶段。</summary>
    private sealed class SingleBlockProvider(BlockMetadata metadata, int length) : DataProviderBase
    {
        /// <inheritdoc />
        protected override async Task ProduceCoreAsync(CancellationToken cancellationToken = default)
        {
            var buffer = ArrayPool<byte>.Shared.Rent(length);
            for (var i = 0; i < length; i++) buffer[i] = (byte)(i + 1);
            await WriteAsync(new DataBlock(buffer, length, metadata), cancellationToken);
        }
    }

    /// <summary>在数据尾部追加一个字节的测试处理阶段。</summary>
    private sealed class AppendProcessor(byte value) : DataProcessorBase
    {
        /// <summary>生命周期调用记录。</summary>
        public List<string> LifeCycle { get; } = [];

        /// <inheritdoc />
        protected override Task OnInitializeAsync(CancellationToken cancellationToken = default)
        {
            LifeCycle.Add("initialize");
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public override Task ValidateAsync(CancellationToken cancellationToken = default)
        {
            LifeCycle.Add("validate");
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public override Task PrepareAsync(CancellationToken cancellationToken = default)
        {
            LifeCycle.Add("prepare");
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public override Task StartAsync(CancellationToken cancellationToken = default)
        {
            LifeCycle.Add("start");
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        protected override ValueTask<DataBlock?> ProcessBlockAsync(DataBlock block,
            CancellationToken cancellationToken = default)
        {
            LifeCycle.Add("process");
            Engine.SetRecord("processed-blocks", (Engine.TryGetRecord<int>("processed-blocks", out var count)
                ? count
                : 0) + 1);
            var buffer = ArrayPool<byte>.Shared.Rent(block.Length + 1);
            block.Data.CopyTo(buffer);
            buffer[block.Length] = value;
            return ValueTask.FromResult<DataBlock?>(new DataBlock(buffer, block.Length + 1, block.Metadata));
        }

        /// <inheritdoc />
        public override Task DisposeAsync(CancellationToken cancellationToken = default)
        {
            LifeCycle.Add("dispose");
            return Task.CompletedTask;
        }
    }

    /// <summary>收集数据块且将所有权保留给测试的接收阶段。</summary>
    private sealed class CollectingReceiver : DataReceiverBase
    {
        /// <summary>已接收的数据块。</summary>
        public List<DataBlock> Blocks { get; } = [];

        /// <inheritdoc />
        public override async Task ReceiveAsync(CancellationToken cancellationToken = default)
        {
            await foreach (var block in ReadAsync(cancellationToken))
                Blocks.Add(block);
        }
    }

    /// <summary>写出首个块后等待引擎取消的测试提供阶段。</summary>
    private sealed class WaitingProvider(BlockMetadata metadata) : DataProviderBase
    {
        /// <summary>是否观察到取消。</summary>
        public bool Canceled { get; private set; }

        /// <summary>是否已释放。</summary>
        public bool Disposed { get; private set; }

        /// <inheritdoc />
        protected override async Task ProduceCoreAsync(CancellationToken cancellationToken = default)
        {
            var buffer = ArrayPool<byte>.Shared.Rent(1);
            buffer[0] = 1;
            await WriteAsync(new DataBlock(buffer, 1, metadata), cancellationToken);
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                Canceled = true;
                throw;
            }
        }

        /// <inheritdoc />
        public override Task DisposeAsync(CancellationToken cancellationToken = default)
        {
            Disposed = true;
            return Task.CompletedTask;
        }
    }

    /// <summary>收到任意块即失败的测试处理阶段。</summary>
    private sealed class FailingProcessor : DataProcessorBase
    {
        /// <summary>是否已释放。</summary>
        public bool Disposed { get; private set; }

        /// <inheritdoc />
        protected override ValueTask<DataBlock?> ProcessBlockAsync(DataBlock block,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromException<DataBlock?>(new InvalidDataException("测试处理器失败。"));

        /// <inheritdoc />
        public override Task DisposeAsync(CancellationToken cancellationToken = default)
        {
            Disposed = true;
            return Task.CompletedTask;
        }
    }

    /// <summary>观察取消并确认接收阶段被终止的测试接收阶段。</summary>
    private sealed class CancellationObservingReceiver : DataReceiverBase
    {
        /// <summary>是否观察到取消。</summary>
        public bool Canceled { get; private set; }

        /// <summary>是否已释放。</summary>
        public bool Disposed { get; private set; }

        /// <inheritdoc />
        public override async Task ReceiveAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                await foreach (var block in ReadAsync(cancellationToken))
                    block.Dispose();
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                Canceled = true;
                throw;
            }
        }

        /// <inheritdoc />
        public override Task DisposeAsync(CancellationToken cancellationToken = default)
        {
            Disposed = true;
            return Task.CompletedTask;
        }
    }
}

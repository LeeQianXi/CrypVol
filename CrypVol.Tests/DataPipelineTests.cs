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
        var completedRecord = 0;
        var engine = ProcessingEngine.Builder()
            .UseProvider(provider)
            .AddProcessor(firstProcessor)
            .AddProcessor(secondProcessor)
            .UseReceiver(receiver)
            .Build();
        engine.Completed += (sender, _) =>
        {
            var completedEngine = Assert.IsType<ProcessingEngine>(sender);
            Assert.True(completedEngine.TryGetRecord("processed-blocks", out completedRecord));
        };

        await engine.StartAsync();

        var received = Assert.Single(receiver.Blocks);
        Assert.Same(metadata, received.Metadata);
        Assert.Equal(new byte[]
        {
            1, 2, 3, 4
        }, received.Data.ToArray());
        Assert.Equal(new[]
            {
                "initialize", "validate", "prepare", "start", "process", "dispose"
            },
            firstProcessor.LifeCycle);
        Assert.Equal(new[]
            {
                "initialize", "validate", "prepare", "start", "process", "dispose"
            },
            secondProcessor.LifeCycle);
        Assert.True(engine.TryGetRecord<int>("processed-blocks", out var processedBlocks));
        Assert.Equal(2, processedBlocks);
        Assert.Equal(2, completedRecord);
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

        Assert.Equal(new[]
        {
            "starting", "started", "completed", "stopped"
        }, events);
    }

    /// <summary>启动阶段必须先让下游就绪，再启动上游生产阶段。</summary>
    [Fact]
    public async Task StartAsync_StartsStagesFromReceiverToProvider()
    {
        var order = new List<string>();
        var engine = ProcessingEngine.Builder()
            .UseProvider(new StartOrderProvider(order))
            .AddProcessor(new StartOrderProcessor(order, "processor-1"))
            .AddProcessor(new StartOrderProcessor(order, "processor-2"))
            .UseReceiver(new StartOrderReceiver(order))
            .Build();

        await engine.StartAsync();

        Assert.Equal(["receiver", "processor-2", "processor-1", "provider"], order);
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

    /// <summary>提供阶段失败时，接收阶段应被取消，且失败与停止事件各只触发一次。</summary>
    [Fact]
    public async Task StartAsync_ProviderFailure_InterruptsReceiverAndRaisesFailureEvents()
    {
        var provider = new FailingProvider();
        var receiver = new CancellationObservingReceiver();
        var events = new List<string>();
        var engine = ProcessingEngine.Builder()
            .UseProvider(provider)
            .UseReceiver(receiver)
            .Build();
        engine.Failed += (_, _) => events.Add("failed");
        engine.Stopped += (_, _) => events.Add("stopped");

        await Assert.ThrowsAsync<InvalidDataException>(() => engine.StartAsync());

        Assert.Equal(ProcessingEngineState.Faulted, engine.State);
        Assert.True(provider.Disposed);
        Assert.True(receiver.Disposed);
        Assert.Equal(["failed", "stopped"], events);
    }

    /// <summary>接收阶段失败时，提供阶段应停止等待并释放全部资源。</summary>
    [Fact]
    public async Task StartAsync_ReceiverFailure_InterruptsProvider()
    {
        var provider = new WaitingProvider(CreateMetadata());
        var receiver = new FailingReceiver();
        var engine = ProcessingEngine.Builder()
            .UseProvider(provider)
            .UseReceiver(receiver)
            .Build();

        await Assert.ThrowsAsync<InvalidDataException>(() => engine.StartAsync());

        Assert.Equal(ProcessingEngineState.Faulted, engine.State);
        Assert.True(provider.Disposed);
        Assert.True(receiver.Disposed);
    }

    /// <summary>外部取消应中断各阶段，并将引擎置为已取消状态。</summary>
    [Fact]
    public async Task StartAsync_ExternalCancellation_InterruptsAllStages()
    {
        var provider = new WaitingProvider(CreateMetadata());
        var receiver = new CancellationObservingReceiver();
        var engine = ProcessingEngine.Builder()
            .UseProvider(provider)
            .UseReceiver(receiver)
            .Build();
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => engine.StartAsync(cancellation.Token));

        Assert.Equal(ProcessingEngineState.Canceled, engine.State);
        Assert.True(provider.Canceled);
        Assert.True(provider.Disposed);
        Assert.True(receiver.Canceled);
        Assert.True(receiver.Disposed);
    }

    /// <summary>多个数据块经由有界通道时，接收顺序必须保持提供顺序。</summary>
    [Fact]
    public async Task StartAsync_PreservesOrderAcrossMultipleBlocks()
    {
        var receiver = new CollectingReceiver();
        var engine = ProcessingEngine.Builder()
            .UseProvider(new MultipleBlockProvider(CreateMetadata(), 16))
            .AddProcessor(new AppendProcessor(255))
            .UseReceiver(receiver)
            .Build();

        await engine.StartAsync();

        Assert.Equal(Enumerable.Range(0, 16).Select(i => (byte)i),
            receiver.Blocks.Select(block => block.Data.Span[0]));
        Assert.All(receiver.Blocks, block => Assert.Equal(255, block.Data.Span[1]));
        foreach (var block in receiver.Blocks) block.Dispose();
    }

    /// <summary>无输出接收阶段应完整消费并释放数据流，使验证类流程能够正常完成。</summary>
    [Fact]
    public async Task StartAsync_NullDataReceiver_DrainsPipeline()
    {
        var processor = new AppendProcessor(7);
        var engine = ProcessingEngine.Builder()
            .UseProvider(new MultipleBlockProvider(CreateMetadata(), 4))
            .AddProcessor(processor)
            .UseReceiver(new NullDataReceiver())
            .Build();

        await engine.StartAsync();

        Assert.Equal(ProcessingEngineState.Completed, engine.State);
        Assert.Equal(4, processor.LifeCycle.Count(stage => stage == "process"));
        Assert.Contains("dispose", processor.LifeCycle);
    }

    /// <summary>观察器应通过 Completed Hook 捕获强类型运行记录与运行状态。</summary>
    [Fact]
    public async Task Observer_CapturesTypedRecordFromCompletedHook()
    {
        var key = new EngineRecordKey<int>("processed-blocks");
        var processor = new AppendProcessor(1);
        var engine = ProcessingEngine.Builder()
            .UseProvider(new SingleBlockProvider(CreateMetadata(), 1))
            .AddProcessor(processor)
            .UseReceiver(new NullDataReceiver())
            .Build();
        using var observer = new ProcessingEngineObserver(engine);
        observer.Capture(key);

        await observer.RunAsync();

        Assert.NotNull(observer.StartedAt);
        Assert.NotNull(observer.StoppedAt);
        Assert.Null(observer.Exception);
        Assert.True(observer.TryGetCaptured(key, out var processedBlocks));
        Assert.Equal(1, processedBlocks);
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

    /// <summary>连续提供多个块的测试提供阶段。</summary>
    private sealed class MultipleBlockProvider(BlockMetadata metadata, int count) : DataProviderBase
    {
        /// <inheritdoc />
        protected override async Task ProduceCoreAsync(CancellationToken cancellationToken = default)
        {
            for (var i = 0; i < count; i++)
            {
                var buffer = ArrayPool<byte>.Shared.Rent(1);
                buffer[0] = (byte)i;
                await WriteAsync(new DataBlock(buffer, 1, metadata), cancellationToken);
            }
        }
    }

    /// <summary>启动后立即失败的测试提供阶段。</summary>
    private sealed class FailingProvider : DataProviderBase
    {
        /// <summary>是否已释放。</summary>
        public bool Disposed { get; private set; }

        /// <inheritdoc />
        protected override Task ProduceCoreAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromException(new InvalidDataException("测试提供者失败。"));
        }

        /// <inheritdoc />
        public override Task DisposeAsync(CancellationToken cancellationToken = default)
        {
            Disposed = true;
            return Task.CompletedTask;
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

    /// <summary>记录启动顺序的空提供阶段。</summary>
    private sealed class StartOrderProvider(List<string> order) : DataProviderBase
    {
        /// <inheritdoc />
        public override Task StartAsync(CancellationToken cancellationToken = default)
        {
            order.Add("provider");
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        protected override Task ProduceCoreAsync(CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }
    }

    /// <summary>记录启动顺序的空处理阶段。</summary>
    private sealed class StartOrderProcessor(List<string> order, string name) : DataProcessorBase
    {
        /// <inheritdoc />
        public override Task StartAsync(CancellationToken cancellationToken = default)
        {
            order.Add(name);
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        protected override ValueTask<DataBlock?> ProcessBlockAsync(DataBlock block,
            CancellationToken cancellationToken = default)
        {
            return ValueTask.FromResult<DataBlock?>(null);
        }
    }

    /// <summary>记录启动顺序的空接收阶段。</summary>
    private sealed class StartOrderReceiver(List<string> order) : DataReceiverBase
    {
        /// <inheritdoc />
        public override Task StartAsync(CancellationToken cancellationToken = default)
        {
            order.Add("receiver");
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public override async Task ReceiveAsync(CancellationToken cancellationToken = default)
        {
            await foreach (var block in ReadAsync(cancellationToken)) block.Dispose();
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
            CancellationToken cancellationToken = default)
        {
            return ValueTask.FromException<DataBlock?>(new InvalidDataException("测试处理器失败。"));
        }

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

    /// <summary>启动后立即失败的测试接收阶段。</summary>
    private sealed class FailingReceiver : DataReceiverBase
    {
        /// <summary>是否已释放。</summary>
        public bool Disposed { get; private set; }

        /// <inheritdoc />
        public override Task ReceiveAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromException(new InvalidDataException("测试接收者失败。"));
        }

        /// <inheritdoc />
        public override Task DisposeAsync(CancellationToken cancellationToken = default)
        {
            Disposed = true;
            return Task.CompletedTask;
        }
    }
}

using CrypVol.Lib.Engine.Processors;
using CrypVol.Lib.Engine.Providers;
using CrypVol.Lib.Engine.Receivers;
using Microsoft.Extensions.Logging;

namespace CrypVol.Lib.Engine;

public sealed partial class ProcessingEngine
{
    /// <summary>动态配置数据提供、处理和接收阶段的 EngineBuilder。</summary>
    public sealed class EngineBuilder
    {
        private readonly List<IDataProcessor> _processors = [];
        private bool _locked;
        private IDataProvider? _provider;
        private IDataReceiver? _receiver;

        internal EngineBuilder()
        {
        }

        internal IDataProvider Provider
        {
            get
            {
                EnsureLocked();
                return _provider!;
            }
        }

        internal IDataReceiver Receiver
        {
            get
            {
                EnsureLocked();
                return _receiver!;
            }
        }

        internal IReadOnlyList<IDataProcessor> Processors => _processors.AsReadOnly();
        internal ILogger? Logger { get; private set; }

        /// <summary>设置唯一的数据提供者。</summary>
        public EngineBuilder UseProvider(IDataProvider provider)
        {
            EnsureUnlocked();
            _provider = provider ?? throw new ArgumentNullException(nameof(provider));
            return this;
        }

        /// <summary>追加一个数据处理器，处理器按注册顺序执行。</summary>
        public EngineBuilder AddProcessor(IDataProcessor processor)
        {
            EnsureUnlocked();
            _processors.Add(processor ?? throw new ArgumentNullException(nameof(processor)));
            return this;
        }

        /// <summary>设置唯一的数据接收者。</summary>
        public EngineBuilder UseReceiver(IDataReceiver receiver)
        {
            EnsureUnlocked();
            _receiver = receiver ?? throw new ArgumentNullException(nameof(receiver));
            return this;
        }

        /// <summary>设置可选日志。</summary>
        public EngineBuilder WithLogger(ILogger? logger)
        {
            EnsureUnlocked();
            Logger = logger;
            return this;
        }

        /// <summary>锁定 EngineBuilder 并构造不可变引擎。</summary>
        public ProcessingEngine Build()
        {
            EnsureUnlocked();
            var provider = _provider ?? throw new InvalidOperationException("尚未配置数据提供者。");
            var receiver = _receiver ?? throw new InvalidOperationException("尚未配置数据接收者。");
            _locked = true;
            return new ProcessingEngine(this);
        }

        private void EnsureUnlocked()
        {
            if (_locked) throw new InvalidOperationException("引擎已经构造完成，配置已锁定。");
        }

        private void EnsureLocked()
        {
            if (!_locked) throw new InvalidOperationException("引擎尚未构造完成。");
        }
    }
}
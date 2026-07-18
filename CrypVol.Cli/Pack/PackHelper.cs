using System.Collections.Concurrent;
using System.CommandLine;
using System.Security.Cryptography;
using System.Threading.Channels;
using CrypVol.Lib;
using Microsoft.Extensions.FileSystemGlobbing;
using Microsoft.Extensions.FileSystemGlobbing.Abstractions;

namespace CrypVol.Cli.Pack;

public static partial class PackHelper
{
    private static CancellationTokenSource GlobalCancellationTokenSource { get; set; } = null!;
    private static PackConfig GlobalConfig { get; set; } = null!;

    /// <summary>
    ///     读取任务分配
    /// </summary>
    private static Channel<FileEntry> TaskChannel { get; } = Channel.CreateUnbounded<FileEntry>();

    /// <summary>
    ///     原始数据队列
    /// </summary>
    private static Channel<RawBlock> RawBlockChannel { get; } = Channel.CreateBounded<RawBlock>(200);

    /// <summary>
    ///     处理后数据队列
    /// </summary>
    private static Channel<EncryptedBlock> EncryptedBlockChannel { get; } = Channel.CreateBounded<EncryptedBlock>(200);

    /// <summary>
    ///     卷上下文映射
    /// </summary>
    private static ConcurrentDictionary<int, VolumeContext> VolumeContexts { get; } = new();

    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        GlobalCancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(token);
        // 初始化参数
        Verbose = args.GetValue(CommandDefinition.Verbose);
        var inputPath = args.GetRequiredValue(CommandDefinition.Pack.InputPath);
        if (!inputPath.Exists)
            switch (inputPath)
            {
                case FileInfo:
                    GeneralLog("文件\"{0}\"不存在", inputPath.Name);
                    return 0;
                case DirectoryInfo:
                    GeneralLog("目录\"{0}\"不存在", inputPath.Name);
                    return 0;
                default:
                    throw new FileNotFoundException();
            }

        var config = new PackConfig();

        if (inputPath is DirectoryInfo directoryInfo)
        {
            var filter = new Matcher();
            var include = args.GetValue(CommandDefinition.Pack.Include);
            filter.AddInclude(string.IsNullOrWhiteSpace(include) ? "**/*" : include);
            var exclude = args.GetValue(CommandDefinition.Pack.Exclude);
            if (!string.IsNullOrWhiteSpace(exclude)) filter.AddExclude(exclude);
            var result = filter.Execute(new DirectoryInfoWrapper(directoryInfo));
            if (!result.HasMatches)
            {
                GeneralLog("目录\"{0}\"没有可处理的文件", inputPath.Name);
                return 0;
            }

            config.SourceDir = directoryInfo.FullName;
            config.Files = result.Files.Select(i => new FileInfo(Path.Combine(directoryInfo.FullName, i.Path)));
        }
        else
        {
            config.SourceDir = (inputPath as FileInfo)!.Directory!.FullName;
            config.Files = (inputPath as FileInfo)!.Yield();
        }

        var outputPath = args.GetRequiredValue(CommandDefinition.Pack.OutputPath);
        if (!outputPath.Exists)
        {
            outputPath.Create();
            VerboseLog("成功创建输出目录\"{0}\"", outputPath.Name);
        }

        config.OutputDir = outputPath.FullName;

        var prefix = args.GetValue(CommandDefinition.Pack.OutputPrefix);
        if (string.IsNullOrWhiteSpace(prefix))
        {
            GeneralLog("无效的卷前缀:{0}", prefix);
            return 0;
        }

        config.OutputPrefix = prefix;

        var volumeSize = args.GetValue(CommandDefinition.Pack.VolumeSize);
        config.VolumeDataCapacity = 1L * 1024 * 1024 * volumeSize;
        var encryptionMode = args.GetValue(CommandDefinition.Pack.Mode);
        config.Mode = encryptionMode;
        config.Cek = RandomNumberGenerator.GetBytes(32);
        config.Salt = RandomNumberGenerator.GetBytes(32);
        switch (encryptionMode)
        {
            case EncryptionMode.Password:
                var password = args.GetValue(CommandDefinition.Pack.Password);
                if (string.IsNullOrWhiteSpace(password))
                {
                    GeneralLog("无效的密码输入");
                    return 0;
                }

                config.Password = password;
                break;
            case EncryptionMode.Asymmetric:
                var keyFile = args.GetValue(CommandDefinition.Pack.PublicKey);
                config.PublicKey = keyFile ?? [];
                break;
            case EncryptionMode.None:
            case EncryptionMode.PlainKey:
            default:
                break;
        }

        var keyOutputPath = args.GetValue(CommandDefinition.Pack.KeyOutputPath);
        config.KeyOutputDir = keyOutputPath!.FullName;
        var processThreads = args.GetValue(CommandDefinition.Pack.Threads);
        processThreads = Math.Max(Math.Min(processThreads, Environment.ProcessorCount), 1);
        config.ComputeThreads = processThreads;
        var compress = args.GetValue(CommandDefinition.Pack.Compress);
        config.EnableCompression = compress;
        GlobalConfig = config;
        // 启动程序
        await CreateCvkAsync(GlobalCancellationTokenSource.Token);
        await PreTreatmentAsync(GlobalCancellationTokenSource.Token);
        await ScheduleAsync(GlobalCancellationTokenSource.Token);
        return 0;
    }

    /// <summary>
    ///     Cvk文件生成
    /// </summary>
    private static partial Task CreateCvkAsync(CancellationToken token);

    /// <summary>
    ///     预处理文件列表
    /// </summary>
    private static partial Task PreTreatmentAsync(CancellationToken token);

    private static partial Task ReadLoopAsync(CancellationToken token);
    private static partial Task ComputeLoopAsync(CancellationToken token);
    private static partial Task RerouteLoopAsync(CancellationToken token);
    private static partial Task WriteLoopAsync(VolumeContext ctx, CancellationToken token);

    private static async Task ScheduleAsync(CancellationToken token)
    {
        VerboseLog("启动调度器");
        var reroute = RerouteLoopAsync(token);
        var writer = ScheduleWriterAsync(token);
        var compute = ScheduleComputeAsync(token);
        var reader = ScheduleReaderAsync(token);
        var publisher = TaskChannel.Writer;
        foreach (var ctx in VolumeContexts.Values)
        {
            foreach (var fileEntry in ctx.Entries)
            {
                await publisher.WriteAsync(fileEntry, token);
            }
        }
        publisher.Complete();
        await Task.WhenAll(reroute, reader, compute, writer);
    }

    private static async Task ScheduleReaderAsync(CancellationToken token)
    {
        VerboseLog("启动 读并发 调度器");
        var tasks = Enumerable.Range(0, 6)
            .Select(_ => ReadLoopAsync(token))
            .ToList();
        await Task.WhenAll(tasks);
        RawBlockChannel.Writer.Complete();
        VerboseLog("读并发 成功完成");
    }

    private static async Task ScheduleComputeAsync(CancellationToken token)
    {
        VerboseLog("启动 压缩/加密并发 调度器");
        var tasks = Enumerable.Range(0, GlobalConfig.ComputeThreads)
            .Select(_ => ComputeLoopAsync(token))
            .ToList();
        await Task.WhenAll(tasks);
        EncryptedBlockChannel.Writer.Complete();
        VerboseLog("压缩/加密并发 成功完成");
    }

    private static readonly SemaphoreSlim WriterScheduleSlim = new(2, 2);

    private static async Task ScheduleWriterAsync(CancellationToken token)
    {
        VerboseLog("启动 写并发 调度器");
        var index = 0;
        var tasks = new List<Task>();
        while (index < VolumeContexts.Count)
        {
            await WriterScheduleSlim.WaitAsync(token);
            var ctx = VolumeContexts[index];
            var task = WriteLoopAsync(ctx, token).ContinueWith(t =>
            {
                if (t.IsFaulted)
                {
                    GlobalCancellationTokenSource.Cancel();
                }

                WriterScheduleSlim.Release();
            }, token);
            tasks.Add(task);
            index++;
        }

        await Task.WhenAll(tasks);
        VerboseLog("写并发 成功完成");
    }
}
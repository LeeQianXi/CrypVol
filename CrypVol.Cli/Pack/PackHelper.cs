using System.Collections.Concurrent;
using System.CommandLine;
using System.Security.Cryptography;
using CrypVol.Lib;
using Microsoft.Extensions.FileSystemGlobbing;
using Microsoft.Extensions.FileSystemGlobbing.Abstractions;

namespace CrypVol.Cli.Pack;

/// <summary>
///     三层缓冲（L1读 -> L2算 -> L3写）并行打包器
///     架构核心：固定槽位环形流转 + 有界信号量背压控制
/// </summary>
public static partial class PackHelper
{
    private static CancellationTokenSource GlobalCancellationTokenSource { get; } = new();
    private static PackConfig GlobalConfig { get; set; } = null!;

    private static ConcurrentDictionary<int, VolumeContext> VolumeContexts { get; } = new();

    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
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
            config.Files = result.Files.Select(i => new FileInfo(i.Path));
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
        return 0;
    }

    private static partial Task CreateCvkAsync(CancellationToken token);

    private static async Task PreTreatmentAsync(CancellationToken token)
    {
        foreach (var fileInfo in GlobalConfig.Files)
            VerboseLog("PreTreatment:{0}", fileInfo.FullName);
    }
}
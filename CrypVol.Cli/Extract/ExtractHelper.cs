using System.CommandLine;
using CrypVol.Lib;
using CrypVol.Lib.Crypto;
using CrypVol.Lib.Helper;
using CrypVol.Lib.Helper.Models;
using CrypVol.Lib.Volume;
using Microsoft.Extensions.Logging;

namespace CrypVol.Cli.Extract;

public static class ExtractHelper
{
    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        var rawInput = args.GetRequiredValue(CommandDefinition.Extract.VolFiles);
        var outputDir = args.GetValue(CommandDefinition.Extract.Output)!;

        var loggerFactory = Program.LoggerFactory;
        var logger = loggerFactory.CreateLogger(nameof(ExtractHelper));
        var discoveryLogger = loggerFactory.CreateLogger("VolumeDiscovery");

        // 1. 快速校验 + 解析卷文件
        if (!outputDir.Exists) outputDir.Create();
        var volFiles = VolumeDiscovery.Discover(rawInput, discoveryLogger).ToList()
            .AsReadOnly();
        if (volFiles.Count is 0)
        {
            logger.LogWarning("无可处理文件");
            return 1;
        }

        // 2. 密钥加载（昂贵的密码学操作，提前做完）
        CvkCredentials? creds;
        var keyFile = args.GetValue(CommandDefinition.Extract.KeyFile);
        if (keyFile is null)
        {
            keyFile = VolumeDiscovery.DiscoverKeyFile(volFiles, discoveryLogger);
            if (keyFile is not null)
                discoveryLogger.LogInformation("自动发现密钥文件: {KeyFileFullName}", keyFile.FullName);
        }

        if (keyFile is not null)
            try
            {
                var cvk = await CvkLoader.LoadAsync(keyFile,
                    args.GetValue(CommandDefinition.Extract.Password),
                    args.GetValue(CommandDefinition.Extract.PrivkeyKey),
                    args.GetValue(CommandDefinition.Extract.PrivkeyKeyPass), token, logger);
                creds = cvk.ToCredentials();
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "无法加载密钥文件");
                return 1;
            }
        else
            creds = new CvkCredentials(EncryptionMode.None, null!);

        // 3. Engine（最昂贵的 I/O+计算）
        var engine = new CrypVolHelper
        {
            Logger = loggerFactory.CreateLogger("CrypVol")
        };
        var result = await engine.ExtractAsync(new ExtractOptions
        {
            VolumeFiles = volFiles,
            OutputDir = outputDir,
            Credentials = creds,
            Overwrite = args.GetValue(CommandDefinition.Extract.Overwrite),
            IncludePattern = args.GetValue(CommandDefinition.Extract.Include),
            ExcludePattern = args.GetValue(CommandDefinition.Extract.Exclude)
        }, token);

        if (!result.Success)
        {
            logger.LogError("提取失败: {ResultError}", result.Error);
            return 1;
        }

        logger.LogInformation("提取完成：{FileCount} 个文件 → {OutputDirectory}", result.FileCount,
            outputDir.FullName);
        return 0;
    }
}

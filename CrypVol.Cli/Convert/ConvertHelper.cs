using System.CommandLine;
using CrypVol.Lib.Crypto;
using CrypVol.Lib.Crypto.Container;
using CrypVol.Lib.Crypto.Models;
using CrypVol.Lib.Helper;
using CrypVol.Lib.Helper.Models;
using CrypVol.Lib.Volume;
using Microsoft.Extensions.Logging;

namespace CrypVol.Cli.Convert;

public static class ConvertHelper
{
    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        var rawInput = args.GetRequiredValue(CommandDefinition.Convert.VolFiles);
        var outputDir = args.GetValue(CommandDefinition.Convert.Output)!;
        var prefix = args.GetValue(CommandDefinition.Convert.OutputPrefix) ?? "converted";
        var loggerFactory = Program.LoggerFactory;
        var logger = loggerFactory.CreateLogger(nameof(ConvertHelper));
        var discoveryLogger = loggerFactory.CreateLogger("VolumeDiscovery");

        // 1. 解析输入卷。此处不修改任何文件；凭据校验完成后才会创建输出或备份。
        var volFiles = VolumeDiscovery.Discover(rawInput, discoveryLogger).ToList()
            .AsReadOnly();
        if (volFiles.Count is 0)
        {
            await Console.Error.WriteLineAsync("无可处理文件");
            return 1;
        }

        // 2. 加载旧 CEK
        CvkCredentials oldCreds;
        var oldKeyFile = args.GetValue(CommandDefinition.Convert.OldKeyFile);
        if (oldKeyFile is null)
        {
            oldKeyFile = VolumeDiscovery.DiscoverKeyFile(volFiles, discoveryLogger);
            if (oldKeyFile is not null)
                discoveryLogger.LogInformation("自动发现密钥文件: {KeyFileFullName}", oldKeyFile.FullName);
        }

        if (oldKeyFile is not null)
            try
            {
                var cvk = await CvkLoader.LoadAsync(oldKeyFile,
                    args.GetValue(CommandDefinition.Convert.OldPassword),
                    args.GetValue(CommandDefinition.Convert.OldPrivkey),
                    args.GetValue(CommandDefinition.Convert.OldPrivkeyPass), token, logger);
                oldCreds = cvk.ToCredentials();
            }
            catch (Exception ex)
            {
                await Console.Error.WriteLineAsync($"无法加载原始密钥文件: {ex.Message}");
                return 1;
            }
        else
            oldCreds = new CvkCredentials(EncryptionMode.None, null!);

        // 3. 目标必须是已有 CVK。禁止在未指定密钥时静默降级为明文。
        var newKeyFile = args.GetValue(CommandDefinition.Convert.KeyFile);
        if (newKeyFile is null)
        {
            await Console.Error.WriteLineAsync("转换必须指定目标密钥文件：--key-file <cvk-file>");
            return 1;
        }

        CvkCredentials newCreds;
        try
        {
            var cvk = await CvkLoader.LoadAsync(newKeyFile,
                args.GetValue(CommandDefinition.Convert.Password),
                args.GetValue(CommandDefinition.Convert.PrivkeyKey),
                args.GetValue(CommandDefinition.Convert.PrivkeyKeyPass), token, logger);
            newCreds = cvk.ToCredentials();
        }
        catch (Exception ex)
        {
            await Console.Error.WriteLineAsync($"无法加载目标密钥文件: {ex.Message}");
            return 1;
        }

        // 4. 所有可失败的前置校验均已完成，此后才允许产生外部副作用。
        try
        {
            if (!outputDir.Exists) outputDir.Create();

            if (args.GetValue(CommandDefinition.Convert.Backup))
                foreach (var file in volFiles.Where(static file => file.Exists))
                    File.Copy(file.FullName, file.FullName + ".bak", true);
        }
        catch (Exception ex)
        {
            await Console.Error.WriteLineAsync($"无法准备转换输出或备份: {ex.Message}");
            return 1;
        }

        // 5. Engine
        var engine = new CrypVolHelper
        {
            Logger = loggerFactory.CreateLogger("CrypVol")
        };
        ConvertResult result;
        try
        {
            result = await engine.ConvertAsync(new ConvertOptions
            {
                VolumeFiles = volFiles,
                OutputDir = outputDir,
                OutputPrefix = prefix,
                OldCredentials = oldCreds,
                NewCredentials = newCreds
            }, token);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            await Console.Error.WriteLineAsync("转换已取消");
            return 1;
        }
        catch (Exception ex)
        {
            await Console.Error.WriteLineAsync($"转换失败: {ex.Message}");
            return 1;
        }

        if (!result.Success)
        {
            await Console.Error.WriteLineAsync($"转换失败: {result.Error}");
            return 1;
        }

        Console.WriteLine($"密钥轮换完成：{result.VolumeCount} 个卷 → {outputDir.FullName}");
        return 0;
    }
}
using System.CommandLine;
using CrypVol.Lib.Crypto;
using CrypVol.Lib.Helper;
using CrypVol.Lib.Helper.Models;
using CrypVol.Lib.Volume;
using Microsoft.Extensions.Logging;

namespace CrypVol.Cli.Repair;

public static class RepairHelper
{
    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        var rawInput = args.GetRequiredValue(CommandDefinition.Repair.VolFiles);

        var loggerFactory = Program.LoggerFactory;
        var logger = loggerFactory.CreateLogger(nameof(RepairHelper));
        var discoveryLogger = loggerFactory.CreateLogger("VolumeDiscovery");

        // 1. 发现所有卷文件
        var volFiles = VolumeDiscovery.Discover(rawInput, discoveryLogger).ToList()
            .AsReadOnly();
        if (volFiles.Count is 0)
        {
            await Console.Error.WriteLineAsync("无可处理文件");
            return 1;
        }

        // 2. 密钥加载
        CvkCredentials creds;
        var keyFile = args.GetValue(CommandDefinition.Repair.KeyFile);
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
                    args.GetValue(CommandDefinition.Repair.Password),
                    args.GetValue(CommandDefinition.Repair.PrivkeyKey),
                    args.GetValue(CommandDefinition.Repair.PrivkeyKeyPass), token, logger);
                creds = cvk.ToCredentials();
            }
            catch (Exception ex)
            {
                await Console.Error.WriteLineAsync($"密钥加载失败: {ex.Message}");
                return 1;
            }
        else
            creds = new CvkCredentials(EncryptionMode.None, null!);

        // 3. Engine 修复
        var engine = new CrypVolHelper
        {
            Logger = loggerFactory.CreateLogger("CrypVol")
        };
        var result = await engine.RepairAsync(new RepairOptions
        {
            VolumeFiles = volFiles,
            Credentials = creds,
            OutputDir = args.GetValue(CommandDefinition.Repair.Output),
            Backup = args.GetValue(CommandDefinition.Repair.Backup),
            VerifyReport = args.GetValue(CommandDefinition.Repair.VerifyReport)
        }, token);

        if (!result.Success)
        {
            await Console.Error.WriteLineAsync($"修复失败: {result.Error}");
            return 1;
        }

        if (result.RepairedBlocks == 0)
        {
            Console.WriteLine("未发现损坏块，无需修复");
        }
        else
        {
            Console.WriteLine($"修复损坏块: {result.RepairedBlocks}");
            foreach (var v in result.RepairedVolumes)
                Console.WriteLine($"修复卷: {v}");
        }

        return 0;
    }
}
using System.CommandLine;
using CrypVol.Lib;
using CrypVol.Lib.Crypto;
using CrypVol.Lib.Helper;
using CrypVol.Lib.Helper.Models;
using CrypVol.Lib.Volume;

namespace CrypVol.Cli.Convert;

public static class ConvertHelper
{
    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        var rawInput = args.GetRequiredValue(CommandDefinition.Convert.VolFiles);
        var outputDir = args.GetValue(CommandDefinition.Convert.Output)!;
        var prefix = args.GetValue(CommandDefinition.Convert.OutputPrefix) ?? "converted";

        var loggerFactory = Program.LoggerFactory;

        // 1. 快速校验 + 解析卷文件
        if (!outputDir.Exists) outputDir.Create();
        var volFiles = VolumeDiscovery.Discover(rawInput, loggerFactory.CreateLogger("VolumeDiscovery")).ToList()
            .AsReadOnly();
        if (volFiles.Count is 0)
        {
            Console.Error.WriteLine("无可处理文件");
            return 1;
        }

        if (args.GetValue(CommandDefinition.Convert.Backup))
            foreach (var f in volFiles)
                if (f.Exists)
                    File.Copy(f.FullName, f.FullName + ".bak", true);

        // 2. 加载旧 CEK
        CvkCredentials? oldCreds;
        var oldKeyFile = args.GetValue(CommandDefinition.Convert.OldKeyFile);
        if (oldKeyFile is null)
        {
            oldKeyFile = VolumeDiscovery.DiscoverKeyFile(volFiles, loggerFactory.CreateLogger("VolumeDiscovery"));
            if (oldKeyFile is not null)
                Console.WriteLine($"自动发现密钥文件: {oldKeyFile.FullName}");
        }

        if (oldKeyFile is not null)
            try
            {
                var cvk = await CvkLoader.LoadAsync(oldKeyFile,
                    args.GetValue(CommandDefinition.Convert.OldPassword),
                    args.GetValue(CommandDefinition.Convert.OldPrivkey),
                    args.GetValue(CommandDefinition.Convert.OldPrivkeyPass), token);
                oldCreds = cvk.ToCredentials();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.Message);
                return 1;
            }
        else
            oldCreds = new CvkCredentials(EncryptionMode.None, null!);

        // 3. 获取新 CEK（二选一）
        CvkCredentials? newCreds;
        var newKeyFile = args.GetValue(CommandDefinition.Convert.KeyFile);
        if (newKeyFile is not null)
            try
            {
                var cvk = await CvkLoader.LoadAsync(newKeyFile,
                    args.GetValue(CommandDefinition.Convert.Password),
                    args.GetValue(CommandDefinition.Convert.PrivkeyKey),
                    args.GetValue(CommandDefinition.Convert.PrivkeyKeyPass), token);
                newCreds = cvk.ToCredentials();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.Message);
                return 1;
            }
        else
            newCreds = new CvkCredentials(EncryptionMode.None, null!);

        // 4. Engine
        var engine = new CrypVolHelper
        {
            Logger = loggerFactory.CreateLogger("CrypVol")
        };
        var result = await engine.ConvertAsync(new ConvertOptions
        {
            VolumeFiles = volFiles,
            OutputDir = outputDir,
            OutputPrefix = prefix,
            OldCredentials = oldCreds,
            NewCredentials = newCreds
        }, token);

        if (!result.Success)
        {
            Console.Error.WriteLine($"错误: {result.Error}");
            return 1;
        }

        Console.WriteLine($"密钥轮换完成：{result.VolumeCount} 个卷 → {outputDir.FullName}");
        return 0;
    }
}

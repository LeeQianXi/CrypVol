using System.CommandLine;
using CrypVol.Lib;
using CrypVol.Lib.Crypto;
using CrypVol.Lib.Engine;
using CrypVol.Lib.Engine.Models;
using CrypVol.Lib.Volume;

namespace CrypVol.Cli.Verify;

public static class VerifyHelper
{
    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        var rawInput = args.GetRequiredValue(CommandDefinition.Verify.VolFiles);

        var loggerFactory = Program.LoggerFactory;

        // 1. 发现所有卷文件
        var volFiles = VolumeDiscovery.Discover(rawInput, loggerFactory.CreateLogger("VolumeDiscovery")).ToList()
            .AsReadOnly();
        if (volFiles.Count is 0)
        {
            Console.Error.WriteLine("无可处理文件");
            return 2;
        }

        // 2. 密钥加载
        CvkCredentials creds;
        var keyFile = args.GetValue(CommandDefinition.Verify.KeyFile);
        if (keyFile is null)
        {
            keyFile = VolumeDiscovery.DiscoverKeyFile(volFiles, loggerFactory.CreateLogger("VolumeDiscovery"));
            if (keyFile is not null)
                Console.WriteLine($"自动发现密钥文件: {keyFile.FullName}");
        }

        if (keyFile is not null)
            try
            {
                var reader = new CvkReader(
                    keyFile,
                    args.GetValue(CommandDefinition.Verify.Password),
                    args.GetValue(CommandDefinition.Verify.PrivkeyKey),
                    args.GetValue(CommandDefinition.Verify.PrivkeyKeyPass)
                )
                {
                    Logger = loggerFactory.CreateLogger("CvkReader")
                };
                creds = await reader.LoadKeyAsync(token);
            }
            catch (Exception ex)
            {
                await Console.Error.WriteLineAsync($"密钥加载失败: {ex.Message}");
                return 2;
            }
        else
            creds = new CvkCredentials(EncryptionMode.None, null!);

        // 3. Engine 校验
        var engine = new CrypVolEngine
        {
            Logger = loggerFactory.CreateLogger("CrypVol")
        };
        var result = await engine.VerifyAsync(new VerifyOptions
        {
            VolumeFiles = volFiles,
            Credentials = creds,
            Quick = args.GetValue(CommandDefinition.Verify.Quick),
            IncludePattern = args.GetValue(CommandDefinition.Verify.Include),
            ExcludePattern = args.GetValue(CommandDefinition.Verify.Exclude)
        }, token);

        if (!result.Success)
        {
            await Console.Error.WriteLineAsync($"错误: {result.Error}");
            return 2;
        }

        // 4. 输出结果
        Console.WriteLine($"文件总数: {result.TotalFiles}");
        Console.WriteLine($"数据块总数: {result.TotalBlocks}");

        if (result.CorruptedBlocks == 0)
        {
            Console.WriteLine("状态: 完整无损");
        }
        else
        {
            Console.WriteLine($"损坏文件: {result.CorruptedFiles}");
            Console.WriteLine($"损坏数据块: {result.CorruptedBlocks}");
            foreach (var e in result.CorruptedEntries)
                Console.WriteLine($"  {e.FilePath} offset={e.CvpOffset} size={e.BlockSize}");

            var repairReport = args.GetValue(CommandDefinition.Verify.RepairReport);
            if (repairReport is not null)
            {
                await File.WriteAllLinesAsync(repairReport.FullName,
                    result.CorruptedEntries.Select(e => $"{e.FilePath}\t{e.CvpOffset}\t{e.BlockSize}"), token);
                Console.WriteLine($"损坏报告: {repairReport.FullName}");
            }

            return 1;
        }

        return 0;
    }
}

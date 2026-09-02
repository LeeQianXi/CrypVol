using System.CommandLine;
using CrypVol.Lib.Crypto;
using CrypVol.Lib.Crypto.Models;
using CrypVol.Lib.Helper;
using CrypVol.Lib.Helper.Models;
using CrypVol.Lib.Volume;
using Microsoft.Extensions.Logging;

namespace CrypVol.Cli.Verify;

public static class VerifyHelper
{
    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        var rawInput = args.GetRequiredValue(CommandDefinition.Verify.VolFiles);

        var loggerFactory = Program.LoggerFactory;
        var logger = loggerFactory.CreateLogger(nameof(VerifyHelper));
        var discoveryLogger = loggerFactory.CreateLogger("VolumeDiscovery");

        // 1. 发现所有卷文件
        var volFiles = VolumeDiscovery.Discover(rawInput, discoveryLogger).ToList()
            .AsReadOnly();
        if (volFiles.Count is 0)
        {
            await Console.Error.WriteLineAsync("无可处理文件");
            return 2;
        }

        // 2. 密钥加载
        CvkCredentials creds;
        var keyFile = args.GetValue(CommandDefinition.Verify.KeyFile);
        if (keyFile is null)
        {
            keyFile = VolumeDiscovery.DiscoverKeyFile(volFiles, discoveryLogger);
            if (keyFile is not null)
                discoveryLogger.LogInformation("自动发现密钥文件: {KeyFileFullName}", keyFile.FullName);
        }

        if (keyFile is not null)
            try
            {
                var cvk = await CvkOperations.LoadAsync(keyFile,
                    args.GetValue(CommandDefinition.Verify.Password),
                    args.GetValue(CommandDefinition.Verify.PrivkeyKey),
                    args.GetValue(CommandDefinition.Verify.PrivkeyKeyPass), token, logger);
                creds = CvkOperations.ToCredentials(cvk);
            }
            catch (Exception ex)
            {
                await Console.Error.WriteLineAsync($"密钥加载失败: {ex.Message}");
                return 2;
            }
        else
            creds = new CvkCredentials(CvkKeyProtection.Plain, ReadOnlyMemory<byte>.Empty);

        // 3. Engine 校验
        var engine = new CrypVolHelper
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
            await Console.Error.WriteLineAsync($"校验失败: {result.Error}");
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
                Console.WriteLine($"  {e.FilePath} volume={e.VolumePath} offset={e.CvpOffset} size={e.BlockSize}");

            var repairReport = args.GetValue(CommandDefinition.Verify.RepairReport);
            if (repairReport is not null)
                try
                {
                    repairReport.Directory?.Create();
                    await File.WriteAllLinesAsync(repairReport.FullName,
                        result.CorruptedEntries.Select(e =>
                            $"{e.VolumePath}\t{e.CvpOffset}\t{e.BlockSize}\t{e.FilePath}"), token);
                    Console.WriteLine($"损坏报告: {repairReport.FullName}");
                }
                catch (Exception ex)
                {
                    await Console.Error.WriteLineAsync($"无法写入损坏报告 {repairReport.FullName}: {ex.Message}");
                    return 2;
                }

            return 1;
        }

        return 0;
    }
}
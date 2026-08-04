using System.CommandLine;
using CrypVol.Lib;
using CrypVol.Lib.Crypto;
using CrypVol.Lib.Engine;
using CrypVol.Lib.Engine.Models;
using CrypVol.Lib.Volume;
using Microsoft.Extensions.FileSystemGlobbing;

namespace CrypVol.Cli.Browse;

public static class BrowseHelper
{
    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        var rawInput = args.GetRequiredValue(CommandDefinition.Browse.VolFiles);
        var longFormat = args.GetValue(CommandDefinition.Browse.LongFormat);

        // 1. 解析卷文件 + 密钥加载
        var volFiles = VolumeDiscovery.Discover(rawInput).ToList().AsReadOnly();
        if (volFiles.Count is 0)
        {
            Console.WriteLine("无可处理文件");
            return 1;
        }

        CvkCredentials? creds;
        var keyFile = args.GetValue(CommandDefinition.Browse.KeyFile);
        if (keyFile is null)
        {
            keyFile = VolumeDiscovery.DiscoverKeyFile(volFiles);
            if (keyFile is not null)
                Console.WriteLine($"自动发现密钥文件: {keyFile.FullName}");
        }
        if (keyFile is not null)
            try
            {
                var reader = new CvkReader(
                    keyFile,
                    args.GetValue(CommandDefinition.Browse.Password),
                    args.GetValue(CommandDefinition.Browse.PrivkeyKey),
                    args.GetValue(CommandDefinition.Browse.PrivkeyKeyPass)
                );
                creds = await reader.LoadKeyAsync(token);
            }
            catch (Exception ex)
            {
                //TODO 加载cvk失败
                Console.WriteLine(ex.Message);
                return 1;
            }
        else
            creds = new CvkCredentials(EncryptionMode.None, null!);

        // 2. Engine（扫描卷头）
        var engine = new CrypVolEngine();
        var result = await engine.BrowseAsync(new BrowseOptions
        {
            VolumeFiles = volFiles,
            Credentials = creds
        }, token);
        if (!result.Success)
        {
            Console.WriteLine($"错误: {result.Error}");
            return 1;
        }

        // 3. 过滤 + 输出（纯内存操作）
        var files = result.Files;
        var inc = args.GetValue(CommandDefinition.Browse.Include);
        var exc = args.GetValue(CommandDefinition.Browse.Exclude);
        if (!string.IsNullOrWhiteSpace(inc) || !string.IsNullOrWhiteSpace(exc))
        {
            var m = new Matcher();
            if (!string.IsNullOrWhiteSpace(inc)) m.AddInclude(inc);
            if (!string.IsNullOrWhiteSpace(exc)) m.AddExclude(exc);
            files = files.Where(f => m.Match(f.Path).HasMatches).ToList();
        }

        Console.WriteLine($"共 {files.Count} 个文件 ({result.VolumeCount} 个卷):\n");
        foreach (var f in files)
            Console.WriteLine(longFormat
                ? $"{Fmt(f.Size),10}  分{f.FragmentCount}段  卷[{string.Join(",", f.Volumes)}]  {f.Path}"
                : $"  {f.Path}");
        return 0;
    }

    private static string Fmt(long b)
    {
        return b switch
        {
            < 1024 => $"{b}B", < 1048576 => $"{b / 1024.0:F1}K",
            < 1073741824 => $"{b / 1048576.0:F1}M", _ => $"{b / 1073741824.0:F2}G"
        };
    }
}
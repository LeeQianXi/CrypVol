using System.CommandLine;
using CrypVol.Lib;

namespace CrypVol.Cli.Browse;

public static class BrowseHelper
{
    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        var volFiles = args.GetRequiredValue(CommandDefinition.Browse.VolFiles);
        var longFormat = args.GetValue(CommandDefinition.Browse.LongFormat);

        var engine = new CrypVolEngine();
        var result = await engine.BrowseAsync(
            volFiles.Select(f => f.FullName).ToList(),
            args.GetValue(CommandDefinition.Browse.KeyFile)?.FullName,
            args.GetValue(CommandDefinition.Browse.Password),
            token);

        if (!result.Success)
        {
            Console.WriteLine($"错误: {result.Error}");
            return 1;
        }

        Console.WriteLine($"共 {result.Files.Count} 个文件 ({result.VolumeCount} 个卷):\n");

        foreach (var f in result.Files)
            if (longFormat)
            {
                var volStr = string.Join(",", f.Volumes);
                Console.WriteLine($"{FormatSize(f.Size),10}  分{f.FragmentCount}段  卷[{volStr}]  {f.Path}");
            }
            else
            {
                Console.WriteLine($"  {f.Path}");
            }

        return 0;
    }

    private static string FormatSize(long bytes)
    {
        return bytes switch
        {
            < 1024 => $"{bytes}B",
            < 1024 * 1024 => $"{bytes / 1024.0:F1}K",
            < 1024 * 1024 * 1024 => $"{bytes / (1024.0 * 1024):F1}M",
            _ => $"{bytes / (1024.0 * 1024 * 1024):F2}G"
        };
    }
}
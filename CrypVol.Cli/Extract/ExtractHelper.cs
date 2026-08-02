using System.CommandLine;
using CrypVol.Lib;
using CrypVol.Lib.Models;

namespace CrypVol.Cli.Extract;

public static class ExtractHelper
{
    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        var volFiles = args.GetRequiredValue(CommandDefinition.Extract.VolFiles);
        var outputDir = args.GetValue(CommandDefinition.Extract.Output)!;

        var engine = new CrypVolEngine();
        if (args.GetValue(CommandDefinition.Verbose))
            engine.Progress = new ConsoleProgress();

        var result = await engine.ExtractAsync(new ExtractOptions
        {
            VolumePaths = volFiles.Select(f => f.FullName).ToList(),
            OutputDir = outputDir.FullName,
            KeyFilePath = args.GetValue(CommandDefinition.Extract.KeyFile)?.FullName,
            Password = args.GetValue(CommandDefinition.Extract.Password),
            PrivateKeyPath = args.GetValue(CommandDefinition.Extract.PrivkeyKey)?.FullName,
            Overwrite = args.GetValue(CommandDefinition.Extract.Overwrite),
            Threads = args.GetValue(CommandDefinition.Extract.Threads)
        }, token);

        if (!result.Success)
        {
            Console.WriteLine($"错误: {result.Error}");
            return 1;
        }

        Console.WriteLine($"提取完成：{result.FileCount} 个文件 → {outputDir.FullName}");
        return 0;
    }
}
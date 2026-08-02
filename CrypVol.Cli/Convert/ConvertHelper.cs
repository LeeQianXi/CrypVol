using System.CommandLine;
using CrypVol.Lib;

namespace CrypVol.Cli.Convert;

public static class ConvertHelper
{
    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        var volFiles = args.GetRequiredValue(CommandDefinition.Convert.VolFiles);
        var outputDir = args.GetValue(CommandDefinition.Convert.Output)!;
        var prefix = args.GetValue(CommandDefinition.Convert.OutputPrefix);
        if (string.IsNullOrWhiteSpace(prefix))
            prefix = "converted";

        var engine = new CrypVolEngine();
        if (args.GetValue(CommandDefinition.Verbose))
            engine.Progress = new ConsoleProgress();

        var result = await engine.ConvertAsync(
            volFiles.Select(f => f.FullName).ToList(),
            outputDir.FullName,
            prefix,
            args.GetValue(CommandDefinition.Convert.OldKeyFile)?.FullName,
            args.GetValue(CommandDefinition.Convert.OldPassword),
            args.GetValue(CommandDefinition.Convert.KeyFile)?.FullName,
            args.GetValue(CommandDefinition.Convert.Mode),
            args.GetValue(CommandDefinition.Convert.Password),
            args.GetValue(CommandDefinition.Convert.PublicKey)?.Select(f => f.FullName).ToList(),
            args.GetValue(CommandDefinition.Convert.Threads),
            token);

        if (!result.Success)
        {
            Console.WriteLine($"错误: {result.Error}");
            return 1;
        }

        Console.WriteLine($"密钥轮换完成：{result.VolumeCount} 个卷 → {outputDir.FullName}");
        return 0;
    }
}
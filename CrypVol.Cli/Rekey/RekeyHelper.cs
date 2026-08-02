using System.CommandLine;
using CrypVol.Lib;
using CrypVol.Lib.Models;

namespace CrypVol.Cli.Rekey;

public static class RekeyHelper
{
    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        var cvkFile = args.GetRequiredValue(CommandDefinition.Rekey.CvkFile);
        var toMode = args.GetValue(CommandDefinition.Rekey.ToMode);

        var engine = new CrypVolEngine();
        if (args.GetValue(CommandDefinition.Verbose))
            engine.Progress = new ConsoleProgress();

        var result = await engine.RekeyAsync(new RekeyOptions
        {
            SourceCvkPath = cvkFile.FullName,
            OutputPath = args.GetValue(CommandDefinition.Rekey.Output)?.FullName,
            TargetMode = toMode,
            SourcePassword = args.GetValue(CommandDefinition.Rekey.Password),
            NewPassword = args.GetValue(CommandDefinition.Rekey.NewPassword),
            PublicKeyPaths = args.GetValue(CommandDefinition.Rekey.PublicKey)?.Select(f => f.FullName).ToList(),
            SourcePrivateKeyPath = args.GetValue(CommandDefinition.Rekey.PrivkeyKey)?.FullName,
            Backup = args.GetValue(CommandDefinition.Rekey.Backup)
        }, token);

        if (!result.Success)
        {
            Console.WriteLine($"错误: {result.Error}");
            return 1;
        }

        Console.WriteLine($"密钥已重新封装 → {result.OutputPath}");
        return 0;
    }
}
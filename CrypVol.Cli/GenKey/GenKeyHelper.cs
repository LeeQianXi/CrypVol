using System.CommandLine;
using CrypVol.Lib;
using CrypVol.Lib.Crypto;

namespace CrypVol.Cli.GenKey;

public static class GenKeyHelper
{
    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        var outputDir = args.GetValue(CommandDefinition.GenKey.Output)!;
        var name = args.GetValue(CommandDefinition.GenKey.Name)!;
        var mode = args.GetValue(CommandDefinition.GenKey.Mode);
        var password = args.GetValue(CommandDefinition.GenKey.Password);
        var pubKeys = args.GetValue(CommandDefinition.GenKey.PublicKey)?.ToList() ?? [];

        var loggerFactory = Program.LoggerFactory;

        // 1. 快速校验
        if (!outputDir.Exists) outputDir.Create();
        if (mode == EncryptionMode.Password && string.IsNullOrWhiteSpace(password))
        {
            Console.Error.WriteLine("Password 模式需要 --password");
            return 1;
        }

        if (mode == EncryptionMode.Asymmetric && !pubKeys.Any())
        {
            Console.Error.WriteLine("Asymmetric 模式需要 --public-key");
            return 1;
        }

        // 2. 生成密钥
        try
        {
            var writer = new CvkWriter(mode, password, pubKeys,
                args.GetValue(CommandDefinition.GenKey.Comment))
            {
                Logger = loggerFactory.CreateLogger("CvkWriter")
            };
            await writer.WriteCvkAsync(outputDir, name, token);
            Console.WriteLine($"密钥已生成: {Path.Combine(outputDir.FullName, name + ".cvk")}  ({mode})");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"错误: {ex.Message}");
            return 1;
        }
    }
}

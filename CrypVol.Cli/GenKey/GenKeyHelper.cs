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

        // 1. 快速校验
        if (mode == EncryptionMode.None)
        {
            Console.Error.WriteLine("genkey 不支持 None 模式");
            return 1;
        }
        if (string.IsNullOrWhiteSpace(name) || name.EndsWith(".cvk", StringComparison.OrdinalIgnoreCase)
            || name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || name.Contains(Path.DirectorySeparatorChar)
            || name.Contains(Path.AltDirectorySeparatorChar))
        {
            Console.Error.WriteLine("密钥名称应为不含扩展名的合法文件名");
            return 1;
        }
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
            outputDir.Create();
            var cvk = CvkDocument.CreateNew(mode);
            cvk.Password = password;
            cvk.Comment = args.GetValue(CommandDefinition.GenKey.Comment);
            foreach (var publicKey in pubKeys) cvk.AddPublicKey(publicKey);
            await cvk.WriteAsync(new FileInfo(Path.Combine(outputDir.FullName, $"{name}.cvk")), token);
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

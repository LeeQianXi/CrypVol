using System.CommandLine;
using System.Security.Cryptography;
using CrypVol.Lib;

namespace CrypVol.Cli.GenKey;

public static class GenKeyHelper
{
    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        var output = args.GetRequiredValue(CommandDefinition.GenKey.Output);
        var mode = args.GetValue(CommandDefinition.GenKey.Mode);
        var password = args.GetValue(CommandDefinition.GenKey.Password);
        var pubKeyPaths = args.GetValue(CommandDefinition.GenKey.PublicKey);
        var prefix = args.GetValue(CommandDefinition.GenKey.Prefix);
        var comment = args.GetValue(CommandDefinition.GenKey.Comment);

        var outputPath = output.FullName;
        var dir = Path.GetDirectoryName(outputPath);
        if (dir is not null && !Directory.Exists(dir)) Directory.CreateDirectory(dir);

        try
        {
            var cek = RandomNumberGenerator.GetBytes(32);
            var salt = RandomNumberGenerator.GetBytes(32);

            var prefixName = string.IsNullOrWhiteSpace(prefix)
                ? Path.GetFileNameWithoutExtension(outputPath)
                : prefix;

            await CvkGenerator.CreateAsync(
                Path.GetDirectoryName(outputPath) ?? ".",
                prefixName,
                mode,
                cek, salt,
                password,
                pubKeyPaths?.Select(p => new FileInfo(p.FullName)),
                token);

            // 重命名为用户指定的路径
            var generatedPath = Path.Combine(
                Path.GetDirectoryName(outputPath) ?? ".", $"{prefixName}.cvk");
            if (generatedPath != outputPath)
                File.Move(generatedPath, outputPath, true);

            Console.WriteLine($"密钥已生成: {outputPath}  ({mode})");
            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"错误: {ex.Message}");
            return 1;
        }
    }
}
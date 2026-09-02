using System.CommandLine;
using CrypVol.Lib.Crypto;
using CrypVol.Lib.Crypto.Models;

namespace CrypVol.Cli.GenKey;

public static class GenKeyHelper
{
    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        var outputDir = args.GetValue(CommandDefinition.GenKey.Output)!;
        var name = args.GetValue(CommandDefinition.GenKey.Name)!;
        var mode = args.GetValue(CommandDefinition.GenKey.Mode);
        var algorithm = args.GetValue(CommandDefinition.GenKey.Algorithm);
        // None 仅表示“未指定算法”；实际默认算法由封装级别决定。
        if (algorithm == CvkKeyWrapAlgorithm.None)
            algorithm = mode switch
            {
                CvkKeyProtection.Plain => CvkKeyWrapAlgorithm.None,
                CvkKeyProtection.Password => CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256,
                CvkKeyProtection.PublicKey => CvkKeyWrapAlgorithm.RsaOaepSha256,
                _ => algorithm
            };

        var password = args.GetValue(CommandDefinition.GenKey.Password);
        var cekText = args.GetValue(CommandDefinition.GenKey.Cek);
        var pubKeys = args.GetValue(CommandDefinition.GenKey.PublicKey)?.ToList() ?? [];
        if (string.IsNullOrWhiteSpace(name) || name.EndsWith(".cvk", StringComparison.OrdinalIgnoreCase)
                                            || name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
                                            name.Contains(Path.DirectorySeparatorChar)
                                            || name.Contains(Path.AltDirectorySeparatorChar))
        {
            await Console.Error.WriteLineAsync("密钥名称应为不含扩展名的合法文件名");
            return 1;
        }

        try
        {
            var route = CvkEncapsulationRoute.Resolve(mode, algorithm);
            if (route.RequiresPassword && string.IsNullOrWhiteSpace(password))
                throw new ArgumentException("Password 封装级别必须提供 --password。", nameof(password));
            if (!route.RequiresPassword && !string.IsNullOrWhiteSpace(password))
                throw new ArgumentException("只有 Password 封装级别可以使用 --password。", nameof(password));
            if (route.RequiresRecipients && pubKeys.Count == 0)
                throw new ArgumentException("PublicKey 封装级别至少需要一个 --public-key。", nameof(pubKeys));
            if (!route.RequiresRecipients && pubKeys.Count > 0)
                throw new ArgumentException("只有 PublicKey 封装级别可以使用 --public-key。", nameof(pubKeys));

            ReadOnlyMemory<byte>? cek = null;
            if (!string.IsNullOrWhiteSpace(cekText))
            {
                if (cekText.Length != 64)
                    throw new ArgumentException("--cek 必须是恰好 64 个十六进制字符（32 字节）。", nameof(cekText));
                try { cek = System.Convert.FromHexString(cekText); }
                catch (FormatException ex) { throw new ArgumentException("--cek 不是有效的十六进制值。", nameof(cekText), ex); }
            }

            // 生成新 CEK；公钥仅作为 CEK 的接收者元数据加入，不在 CLI 中自行处理密钥体。
            outputDir.Create();
            var cvk = CvkOperations.CreateNew(mode, algorithm, cek);
            cvk.Comment = args.GetValue(CommandDefinition.GenKey.Comment);
            foreach (var publicKey in pubKeys)
                CvkOperations.AddPublicKey(cvk, publicKey);

            var outputFile = new FileInfo(Path.Combine(outputDir.FullName, $"{name}.cvk"));
            await CvkOperations.WriteAsync(cvk, outputFile, password, token);
            Console.WriteLine($"密钥已生成: {outputFile.FullName}");
            Console.WriteLine($"封装级别: {route.Level}; 算法: {route.Algorithm}");
            if (route.RequiresRecipients)
                Console.WriteLine($"公钥接收者: {cvk.RecipientKeys.Count}");
            return 0;
        }
        catch (OperationCanceledException)
        {
            await Console.Error.WriteLineAsync("密钥生成已取消");
            return 2;
        }
        catch (Exception ex)
        {
            await Console.Error.WriteLineAsync($"生成密钥失败: {ex.Message}");
            return 1;
        }
    }
}
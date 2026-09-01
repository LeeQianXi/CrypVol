using System.CommandLine;
using CrypVol.Lib.Crypto;

namespace CrypVol.Cli.Info;

public static class InfoHelper
{
    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        var keyFile = args.GetRequiredValue(CommandDefinition.Info.KeyFile);
        var logger = Program.LoggerFactory.CreateLogger(nameof(InfoHelper));

        try
        {
            var metadata = CvkLoader.ReadMetadata(keyFile.FullName);
            Console.WriteLine($"文件: {keyFile.Name}");
            Console.WriteLine($"保护模式: {ModeLabel(metadata.ProtectionMode)} ({metadata.ProtectionMode})");
            Console.WriteLine($"加密算法: {metadata.Algorithm}");
        }
        catch (Exception ex)
        {
            await Console.Error.WriteLineAsync($"无法读取 CVK 头: {ex.Message}");
            return 1;
        }

        try
        {
            var document = await CvkLoader.LoadAsync(keyFile,
                args.GetValue(CommandDefinition.Info.Password),
                args.GetValue(CommandDefinition.Info.PrivkeyKey),
                args.GetValue(CommandDefinition.Info.PrivkeyKeyPass), token, logger);

            Console.WriteLine("状态: 已解封并验证");
            Console.WriteLine($"内容模式: {ModeLabel(document.EncryptionMode)} ({document.EncryptionMode})");
            Console.WriteLine($"加密算法: {document.EncryptionAlgorithm}");
            Console.WriteLine($"CEK 指纹: {System.Convert.ToHexString(document.Cek.Span)[..8]}...");
            if (!string.IsNullOrWhiteSpace(document.Comment))
                Console.WriteLine($"注释: {document.Comment}");
            if (!string.IsNullOrWhiteSpace(document.Label)) Console.WriteLine($"标签: {document.Label}");
            if (!string.IsNullOrWhiteSpace(document.Description)) Console.WriteLine($"描述: {document.Description}");
            if (document.CreatedAt is not null) Console.WriteLine($"创建时间: {document.CreatedAt:O}");
            if (!string.IsNullOrWhiteSpace(document.Generator)) Console.WriteLine($"生成器: {document.Generator}");

            if (document.EncryptionMode == EncryptionMode.Asymmetric)
            {
                Console.WriteLine($"公钥接收者: {document.PublicKeyRecipients.Count}");
                foreach (var recipient in document.PublicKeyRecipients)
                    Console.WriteLine($"  - {recipient.KeyId}");
            }
        }
        catch (Exception ex)
        {
            await Console.Error.WriteLineAsync($"无法解封 CVK: {ex.Message}");
            return 1;
        }

        return 0;
    }

    private static string ModeLabel(EncryptionMode m)
    {
        return m switch
        {
            EncryptionMode.PlainKey => "明文",
            EncryptionMode.Password => "密码保护",
            EncryptionMode.Asymmetric => "公钥保护",
            _ => "未知"
        };
    }
}

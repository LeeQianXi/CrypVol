using System.CommandLine;
using CrypVol.Lib;
using CrypVol.Lib.Crypto;
using Microsoft.Extensions.Logging;

namespace CrypVol.Cli.Info;

public static class InfoHelper
{
    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        var keyFile = args.GetRequiredValue(CommandDefinition.Info.KeyFile);
        var logger = Program.LoggerFactory.CreateLogger(nameof(InfoHelper));

        try
        {
            var envelopeMode = CvkLoader.ReadMode(keyFile.FullName);
            Console.WriteLine($"文件: {keyFile.Name}");
            Console.WriteLine($"封装模式: {EnvelopeModeLabel(envelopeMode)} ({envelopeMode})");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "无法读取 CVK 头");
            return 1;
        }

        try
        {
            var document = await CvkLoader.LoadAsync(keyFile,
                args.GetValue(CommandDefinition.Info.Password),
                args.GetValue(CommandDefinition.Info.PrivkeyKey),
                args.GetValue(CommandDefinition.Info.PrivkeyKeyPass), token);

            Console.WriteLine("状态: 已解封并验证");
            Console.WriteLine($"内容模式: {ModeLabel(document.EncryptionMode)} ({document.EncryptionMode})");
            Console.WriteLine($"CEK 指纹: {System.Convert.ToHexString(document.Cek)[..8]}...");
            if (!string.IsNullOrWhiteSpace(document.Comment))
                Console.WriteLine($"注释: {document.Comment}");

            if (document.EncryptionMode == EncryptionMode.Asymmetric)
            {
                Console.WriteLine($"公钥接收者: {document.PublicKeyRecipients.Count}");
                foreach (var recipient in document.PublicKeyRecipients)
                    Console.WriteLine($"  - {recipient.KeyId}");
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "无法解封 CVK");
            return 1;
        }

        return 0;
    }

    private static string EnvelopeModeLabel(EnvelopeMode mode)
    {
        return mode switch
        {
            EnvelopeMode.Plain => "明文 CEK",
            EnvelopeMode.Password => "密码保护",
            EnvelopeMode.PublicKey => "公钥保护",
            _ => "未知"
        };
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
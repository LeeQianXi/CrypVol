using System.CommandLine;
using CrypVol.Lib;
using CrypVol.Lib.Crypto;

namespace CrypVol.Cli.Info;

public static class InfoHelper
{
    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        var keyFile = args.GetRequiredValue(CommandDefinition.Info.KeyFile);
        var loggerFactory = Program.LoggerFactory;

        try
        {
            var c = await new CvkReader(keyFile,
                    args.GetValue(CommandDefinition.Info.Password),
                    args.GetValue(CommandDefinition.Info.PrivkeyKey),
                    args.GetValue(CommandDefinition.Info.PrivkeyKeyPass))
                {
                    Logger = loggerFactory.CreateLogger("CvkReader")
                }
                .LoadKeyAsync(token);

            Console.WriteLine(
                $"{keyFile.Name}: {ModeLabel(c.EncryptionMode)} (验证通过, CEK: {System.Convert.ToHexString(c.Cek)[..8]}...)");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"读取失败: {ex.Message}");
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

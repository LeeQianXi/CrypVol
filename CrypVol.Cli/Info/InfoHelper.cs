using System.CommandLine;
using CrypVol.Lib;

namespace CrypVol.Cli.Info;

public static class InfoHelper
{
    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        var files = args.GetRequiredValue(CommandDefinition.Info.InputFiles);

        foreach (var f in files)
        {
            if (f is not FileInfo fi) continue;
            try
            {
                var mode = KeyEnvelope.ReadMode(fi.FullName);
                var label = mode switch
                {
                    EnvelopeMode.Plain => "明文",
                    EnvelopeMode.Password => "密码保护",
                    EnvelopeMode.PublicKey => "公钥保护",
                    _ => "未知"
                };
                var size = new FileInfo(fi.FullName).Length;
                Console.WriteLine($"{fi.Name}: {label} ({size} bytes)");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"{fi.Name}: 读取失败 ({ex.Message})");
            }
        }

        await Task.CompletedTask;
        return 0;
    }
}
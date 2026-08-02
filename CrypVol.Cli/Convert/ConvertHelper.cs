using System.CommandLine;

namespace CrypVol.Cli.Convert;

/// <summary>
///     块级密钥轮换：用旧 CEK 解密每个数据块，用新 CEK 重新加密，不解压不还原文件。
/// </summary>
public static class ConvertHelper
{
    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        var verbose = args.GetValue(CommandDefinition.Verbose);
        var volFiles = args.GetValue(CommandDefinition.Convert.VolFiles);
        var oldKeyFile = args.GetValue(CommandDefinition.Convert.OldKeyFile);
        var oldPassword = args.GetValue(CommandDefinition.Convert.OldPassword);
        var oldPrivkey = args.GetValue(CommandDefinition.Convert.OldPrivkey);
        var oldPrivkeyPass = args.GetValue(CommandDefinition.Convert.OldPrivkeyPass);
        var output = args.GetValue(CommandDefinition.Convert.Output);
        var prefix = args.GetValue(CommandDefinition.Convert.OutputPrefix);
        var mode = args.GetValue(CommandDefinition.Convert.Mode);
        var password = args.GetValue(CommandDefinition.Convert.Password);
        var publicKey = args.GetValue(CommandDefinition.Convert.PublicKey);
        var threads = args.GetValue(CommandDefinition.Convert.Threads);
        var backup = args.GetValue(CommandDefinition.Convert.Backup);

        // TODO: 实现块级密钥轮换逻辑
        await Task.CompletedTask;
        return 0;
    }
}

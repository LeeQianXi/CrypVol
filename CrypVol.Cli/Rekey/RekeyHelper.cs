using System.CommandLine;

namespace CrypVol.Cli.Rekey;

/// <summary>
///     重新封装密钥信封，更换 .cvk 的保护方式（密码/公钥），CEK 不变。
/// </summary>
public static class RekeyHelper
{
    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        var verbose = args.GetValue(CommandDefinition.Verbose);
        var cvkFile = args.GetValue(CommandDefinition.Rekey.CvkFile);
        var output = args.GetValue(CommandDefinition.Rekey.Output);
        var toMode = args.GetValue(CommandDefinition.Rekey.ToMode);
        var password = args.GetValue(CommandDefinition.Rekey.Password);
        var newPassword = args.GetValue(CommandDefinition.Rekey.NewPassword);
        var publicKey = args.GetValue(CommandDefinition.Rekey.PublicKey);
        var privkeyKey = args.GetValue(CommandDefinition.Rekey.PrivkeyKey);
        var privkeyPass = args.GetValue(CommandDefinition.Rekey.PrivkeyKeyPass);
        var backup = args.GetValue(CommandDefinition.Rekey.Backup);

        // TODO: 实现密钥信封重新封装逻辑
        await Task.CompletedTask;
        return 0;
    }
}

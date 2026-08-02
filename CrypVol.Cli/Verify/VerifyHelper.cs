using System.CommandLine;

namespace CrypVol.Cli.Verify;

/// <summary>
///     校验数据卷的完整性
/// </summary>
public static class VerifyHelper
{
    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        var verbose = args.GetValue(CommandDefinition.Verbose);
        var volFiles = args.GetValue(CommandDefinition.Verify.VolFiles);
        var keyFile = args.GetValue(CommandDefinition.Verify.KeyFile);
        var password = args.GetValue(CommandDefinition.Verify.Password);
        var privkeyKey = args.GetValue(CommandDefinition.Verify.PrivkeyKey);
        var privkeyPass = args.GetValue(CommandDefinition.Verify.PrivkeyKeyPass);
        var threads = args.GetValue(CommandDefinition.Verify.Threads);
        var include = args.GetValue(CommandDefinition.Verify.Include);
        var exclude = args.GetValue(CommandDefinition.Verify.Exclude);
        var quick = args.GetValue(CommandDefinition.Verify.Quick);
        var repairReport = args.GetValue(CommandDefinition.Verify.RepairReport);

        // TODO: 实现完整性校验逻辑
        await Task.CompletedTask;
        return 0;
    }
}
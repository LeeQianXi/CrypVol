using System.CommandLine;

namespace CrypVol.Cli.Repair;

/// <summary>
///     尝试修复损坏的数据卷
/// </summary>
public static class RepairHelper
{
    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        var verbose = args.GetValue(CommandDefinition.Verbose);
        var volFiles = args.GetValue(CommandDefinition.Repair.VolFiles);
        var output = args.GetValue(CommandDefinition.Repair.Output);
        var keyFile = args.GetValue(CommandDefinition.Repair.KeyFile);
        var password = args.GetValue(CommandDefinition.Repair.Password);
        var privkeyKey = args.GetValue(CommandDefinition.Repair.PrivkeyKey);
        var privkeyPass = args.GetValue(CommandDefinition.Repair.PrivkeyKeyPass);
        var threads = args.GetValue(CommandDefinition.Repair.Threads);
        var backup = args.GetValue(CommandDefinition.Repair.Backup);
        var verifyReport = args.GetValue(CommandDefinition.Repair.VerifyReport);

        // TODO: 实现修复逻辑
        await Task.CompletedTask;
        return 0;
    }
}
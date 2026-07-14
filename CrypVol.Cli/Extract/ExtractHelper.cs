using System.CommandLine;

namespace CrypVol.Cli.Extract;

public static class ExtractHelper
{
    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        args.GetValue(CommandDefinition.Verbose);
        args.GetValue(CommandDefinition.Extract.VolFiles);
        args.GetValue(CommandDefinition.Extract.KeyFile);
        args.GetValue(CommandDefinition.Extract.Output);
        args.GetValue(CommandDefinition.Extract.Password);
        args.GetValue(CommandDefinition.Extract.PrivkeyKey);
        args.GetValue(CommandDefinition.Extract.PrivkeyKeyPass);
        args.GetValue(CommandDefinition.Extract.Threads);
        args.GetValue(CommandDefinition.Extract.Rescue);
        args.GetValue(CommandDefinition.Extract.Overwrite);
        args.GetValue(CommandDefinition.Extract.KeepPermissions);
        args.GetValue(CommandDefinition.Extract.Include);
        args.GetValue(CommandDefinition.Extract.Exclude);
        return 0;
    }
}
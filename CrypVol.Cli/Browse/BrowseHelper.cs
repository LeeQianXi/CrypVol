using System.CommandLine;

namespace CrypVol.Cli.Browse;

public static class BrowseHelper
{
    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        args.GetValue(CommandDefinition.Verbose);
        args.GetValue(CommandDefinition.Browse.VolFiles);
        args.GetValue(CommandDefinition.Browse.Output);
        args.GetValue(CommandDefinition.Browse.OutputFormat);
        args.GetValue(CommandDefinition.Browse.ShowFragments);
        args.GetValue(CommandDefinition.Browse.KeyFile);
        args.GetValue(CommandDefinition.Browse.Password);
        args.GetValue(CommandDefinition.Browse.PrivkeyKey);
        args.GetValue(CommandDefinition.Browse.PrivkeyKeyPass);
        args.GetValue(CommandDefinition.Browse.Rescue);
        args.GetValue(CommandDefinition.Browse.Include);
        args.GetValue(CommandDefinition.Browse.Exclude);
        return 0;
    }
}
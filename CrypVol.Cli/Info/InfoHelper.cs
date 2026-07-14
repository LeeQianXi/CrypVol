using System.CommandLine;

namespace CrypVol.Cli.Info;

public static class InfoHelper
{
    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        args.GetValue(CommandDefinition.Verbose);
        args.GetValue(CommandDefinition.Info.InputFiles);
        return 0;
    }
}
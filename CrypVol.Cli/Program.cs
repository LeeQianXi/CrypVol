namespace CrypVol.Cli;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        var command = CommandDefinition.BuildCommand();
        var result = command.Parse(args);
        return await result.InvokeAsync();
    }
}
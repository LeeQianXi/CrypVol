using Microsoft.Extensions.Logging;

namespace CrypVol.Cli;

internal static class Program
{
    public static ILoggerFactory LoggerFactory { get; private set; } = null!;

    private static async Task<int> Main(string[] args)
    {
        var command = CommandDefinition.BuildCommand();
        var result = command.Parse(args);

        // 从 args 提取日志级别，设置 LoggerFactory 最小级别
        var logLevel = result.GetValue(CommandDefinition.Verbose);
        LoggerFactory = Microsoft.Extensions.Logging.LoggerFactory.Create(builder =>
        {
            builder.SetMinimumLevel(logLevel);
            builder.AddSimpleConsole(o => { o.SingleLine = true; });
        });

        return await result.InvokeAsync();
    }
}

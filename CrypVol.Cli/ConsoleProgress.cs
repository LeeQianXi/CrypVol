using CrypVol.Lib.Engine.Models;

namespace CrypVol.Cli;

internal sealed class ConsoleProgress : IProgress<ProgressReport>
{
    public void Report(ProgressReport value)
    {
        if (value.Total > 0)
            Console.WriteLine($"[{value.Phase}] {value.Completed}/{value.Total} {value.Detail}");
    }
}
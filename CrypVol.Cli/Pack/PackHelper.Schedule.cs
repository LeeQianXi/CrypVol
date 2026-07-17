namespace CrypVol.Cli.Pack;

public static partial class PackHelper
{
    private static partial async Task PreTreatmentAsync(CancellationToken token)
    {
        foreach (var fileInfo in GlobalConfig.Files)
            VerboseLog("PreTreatment:{0}", fileInfo.FullName);
    }
}
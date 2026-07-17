using System.Diagnostics.CodeAnalysis;

namespace CrypVol.Cli.Pack;

public static partial class PackHelper
{
    /// <summary>
    ///     是否开启详细日志
    /// </summary>
    public static bool Verbose { get; private set; }

    private static void GeneralLog([StringSyntax("CompositeFormat")] string format, params object?[] args)
    {
        Console.Out.WriteLine(format, args);
    }

    private static void VerboseLog([StringSyntax("CompositeFormat")] string format, params object?[] args)
    {
        if (!Verbose) return;
        Console.Out.WriteLine(format, args);
    }

    private static void GeneralLog([StringSyntax("CompositeFormat")] string format, object? arg0)
    {
        Console.Out.WriteLine(format, arg0);
    }

    private static void VerboseLog([StringSyntax("CompositeFormat")] string format, object? arg0)
    {
        if (!Verbose) return;
        Console.Out.WriteLine(format, arg0);
    }

    private static void GeneralLog(string? value)
    {
        Console.Out.WriteLine(value);
    }

    private static void VerboseLog(string? value)
    {
        if (!Verbose) return;
        Console.Out.WriteLine(value);
    }
}
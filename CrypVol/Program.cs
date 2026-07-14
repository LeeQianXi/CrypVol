using Avalonia;
using Avalonia.ReactiveUI;
using CrypVol.Core;
using CrypVol.Core.Views;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace CrypVol;

public class Program
{
    private static readonly IHost Host;

    static Program()
    {
        Host = Microsoft.Extensions.Hosting.Host.CreateDefaultBuilder()
            .ConfigureServices(ConfigureServices)
            .Build();
    }

    private static void ConfigureServices(HostBuilderContext context, IServiceCollection collection)
    {
        var config = context.Configuration;
        collection
            .UseAvaloniaCore<CrypVolWindow>()
            .UseCrypVolCore();
    }

    [STAThread]
    public static async Task Main(string[] args)
    {
        await Host.StartAsync();
        BuildAvaloniaApp()
            .StartWithClassicDesktopLifetime(args);
        await Host.StopAsync();
    }

    public static AppBuilder BuildAvaloniaApp()
    {
        return AppBuilder.Configure(() => Host.Services.GetRequiredService<CrypVolApp>())
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace()
            .UseReactiveUI();
    }
}
using CrypVol.Core.Abstract.ViewModels;
using CrypVol.Core.Abstract.Views;
using CrypVol.Lib.Utility;
using Microsoft.Extensions.DependencyInjection;

namespace CrypVol.Core;

public class ServiceLocator : StaticSingleton<ServiceLocator>
{
    public static IServiceProvider ServiceProvider { get; internal set; } = null!;

    public ICrypVolWindow CrypVolWindow => ServiceProvider.GetRequiredService<ICrypVolWindow>();
    public ICrypVolViewModel CrypVolViewModel => ServiceProvider.GetRequiredService<ICrypVolViewModel>();
}
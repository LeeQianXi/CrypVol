using System.Reactive.Linq;
using Avalonia;
using CrypVol.Core.Abstract.Services;
using CrypVol.Core.Abstract.ViewModels;
using CrypVol.Core.Abstract.Views;
using CrypVol.Core.ViewModels;
using CrypVol.Core.Views;
using CrypVol.Lib;
using DynamicData;
using FluentValidation;
using Microsoft.Extensions.DependencyInjection;

namespace CrypVol.Core;

public static class Extensions
{
    public static IObservable<TResult> LiveStat<T, TResult>(
        this IObservable<IChangeSet<T>> changes,
        Func<IReadOnlyCollection<T>, TResult> query) where T : notnull
    {
        return changes.QueryWhenChanged(query).DistinctUntilChanged();
    }

    extension(IServiceCollection collection)
    {
        public IServiceCollection UseAvaloniaCore<TStartUp>()
            where TStartUp : class, IStartupWindow
        {
            return collection
                .AddMultiSingleton<Application, CrypVolApp>()
                .AddMultiSingleton<IStartupWindow, TStartUp>();
        }

        public IServiceCollection UseCrypVolCore()
        {
            return collection
                .AddValidatorsFromAssembly(typeof(Extensions).Assembly, includeInternalTypes: true)
                .AddSingleton<ICrypVolWindow, CrypVolWindow>(p =>
                    (CrypVolWindow)p.GetRequiredService<IStartupWindow>())
                .AddMultiSingleton<ICrypVolViewModel, CrypVolViewModel>();
        }
    }
}
using System.Reactive;
using System.Reactive.Linq;
using Avalonia.Collections;
using Avalonia.Controls.Notifications;
using Avalonia.Platform.Storage;
using CommunityToolkit.Mvvm.Input;
using CrypVol.Core.Abstract.Utility;
using CrypVol.Core.Abstract.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ReactiveUI;

namespace CrypVol.Core.ViewModels;

public partial class CrypVolViewModel(IServiceProvider serviceProvider) : ViewModelBase, ICrypVolViewModel
{
    public override IServiceProvider ServiceProvider { get; } = serviceProvider;

    public override ILogger Logger { get; } = serviceProvider.GetRequiredService<ILogger<CrypVolViewModel>>();

    public IAvaloniaList<ITreeViewHeaderViewModel> TabList { get; } = new AvaloniaList<ITreeViewHeaderViewModel>();

    public Interaction<INotification, Unit> NotifyScreenInteraction { get; } = new();

    public Interaction<Unit, IReadOnlyList<IStorageFolder>> OpenFolderInteraction { get; } = new();

    public Interaction<Unit, IReadOnlyList<IStorageFile>> OpenCrypVolInteraction { get; } = new();

    [RelayCommand]
    private async Task OpenFolder()
    {
        var list = await OpenFolderInteraction.Handle(Unit.Default);
        TabList.AddRange(list.Select(item => new FileTreeViewModel(serviceProvider)
        {
            Header = item.Name
        }));
    }

    [RelayCommand]
    private async Task OpenCrypVol()
    {
        var list = await OpenCrypVolInteraction.Handle(Unit.Default);
        TabList.AddRange(list.Select(item => new CrypVolTreeViewModel(serviceProvider)
        {
            Header = item.Name
        }));
    }
}
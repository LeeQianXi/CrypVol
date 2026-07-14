using System.Reactive;
using Avalonia.Collections;
using Avalonia.Controls.Notifications;
using Avalonia.Platform.Storage;
using CommunityToolkit.Mvvm.Input;
using CrypVol.Core.Abstract.Services;
using ReactiveUI;

namespace CrypVol.Core.Abstract.ViewModels;

public interface ICrypVolViewModel : IDependencyInjection
{
    IAvaloniaList<ITreeViewHeaderViewModel> TabList { get; }

    IAsyncRelayCommand OpenFolderCommand { get; }
    IAsyncRelayCommand OpenCrypVolCommand { get; }

    #region Interaction

    Interaction<INotification, Unit> NotifyScreenInteraction { get; }
    Interaction<Unit, IReadOnlyList<IStorageFolder>> OpenFolderInteraction { get; }
    Interaction<Unit, IReadOnlyList<IStorageFile>> OpenCrypVolInteraction { get; }

    #endregion
}
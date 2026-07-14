using CommunityToolkit.Mvvm.Input;
using ReactiveUI;

namespace CrypVol.Core;

public partial class AppCommand : ReactiveObject
{
    private static ServiceLocator ServiceLocator => ServiceLocator.Instance;

    [RelayCommand]
    private void OpenFolder()
    {
        ServiceLocator.CrypVolWindow.ViewModel?.OpenFolderCommand.Execute(null);
    }

    [RelayCommand]
    private void OpenCrypVol()
    {
        ServiceLocator.CrypVolWindow.ViewModel?.OpenCrypVolCommand.Execute(null);
    }

    [RelayCommand]
    private void CloseApp()
    {
        ServiceLocator.CrypVolWindow.Close();
    }
}
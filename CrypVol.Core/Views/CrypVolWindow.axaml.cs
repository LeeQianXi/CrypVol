using System.Reactive;
using Avalonia.Controls.Notifications;
using Avalonia.Platform.Storage;
using CrypVol.Core.Abstract;
using CrypVol.Core.Abstract.Services;
using CrypVol.Core.Abstract.Utility;
using CrypVol.Core.Abstract.ViewModels;
using CrypVol.Core.Abstract.Views;
using ReactiveUI;

namespace CrypVol.Core.Views;

public partial class CrypVolWindow : ViewModelWindowBase<ICrypVolViewModel>, IStartupWindow, ICrypVolWindow, ICoroutinator
{
    public CrypVolWindow()
    {
        InitializeComponent();
        ViewModel!.NotifyScreenInteraction.RegisterHandler(NotifyScreenInteraction);
        ViewModel.OpenFolderInteraction.RegisterHandler(OpenFolderInteraction);
        ViewModel.OpenCrypVolInteraction.RegisterHandler(OpenCrypVolInteraction);
    }

    public CancellationTokenSource CoroutineCancelTokenSource { get; } = new();


    private void NotifyScreenInteraction(IInteractionContext<INotification, Unit> context)
    {
        Manager.Show(context.Input);
        context.SetOutput(Unit.Default);
    }

    private async Task OpenFolderInteraction(IInteractionContext<Unit, IReadOnlyList<IStorageFolder>> context)
    {
        context.SetOutput(await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            AllowMultiple = true,
            SuggestedStartLocation = await StorageProvider.TryGetFolderFromPathAsync(Environment.CurrentDirectory)
        }));
    }

    private async Task OpenCrypVolInteraction(IInteractionContext<Unit, IReadOnlyList<IStorageFile>> context)
    {
        context.SetOutput(await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            AllowMultiple = true,
            FileTypeFilter =
            [
                CrypFilePickerFileTypes.CrypVolFile
            ],
            SuggestedFileType = CrypFilePickerFileTypes.CrypVolFile,
            SuggestedStartLocation = await StorageProvider.TryGetFolderFromPathAsync(Environment.CurrentDirectory)
        }));
    }
}
using CrypVol.Core.Abstract;
using CrypVol.Core.Abstract.Services;
using CrypVol.Core.Abstract.Utility;
using CrypVol.Core.Abstract.ViewModels;
using CrypVol.Core.Abstract.Views;

namespace CrypVol.Core.Views;

public partial class CrypVolWindow : ViewModelWindowBase<ICrypVolViewModel>, IStartupWindow, ICrypVolWindow, ICoroutinator
{
    public CrypVolWindow()
    {
        InitializeComponent();
    }

    public CancellationTokenSource CoroutineCancelTokenSource { get; } = new();
}
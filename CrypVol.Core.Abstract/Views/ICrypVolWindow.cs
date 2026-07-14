using CrypVol.Core.Abstract.Services;
using CrypVol.Core.Abstract.ViewModels;

namespace CrypVol.Core.Abstract.Views;

public interface ICrypVolWindow : IWindow
{
    ICrypVolViewModel? ViewModel { get; set; }
}
using Avalonia.Controls;
using CrypVol.Core.Abstract.Services;
using Microsoft.Extensions.Logging;

namespace CrypVol.Core.Abstract.Utility;

public abstract class ViewModelWindowBase<T> : Window, IWindow where T : class, IDependencyInjection
{
    public T? ViewModel
    {
        get => DataContext as T;
        set => DataContext = value;
    }

    public ILogger Logger => ViewModel?.Logger!;
}
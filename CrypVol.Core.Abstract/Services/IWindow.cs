using Avalonia.Controls;

namespace CrypVol.Core.Abstract.Services;

public interface IWindow
{
    public void Show();
    public void Show(Window owner);
    public Task ShowDialog(Window owner);
    public Task<TResult> ShowDialog<TResult>(Window owner);
    void Hide();
    void Close();
}
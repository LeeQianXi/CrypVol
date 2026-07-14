using CrypVol.Core.Abstract.Utility;
using CrypVol.Core.Abstract.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace CrypVol.Core.ViewModels;

public class FileTreeViewModel(IServiceProvider serviceProvider) : ViewModelBase, IFileTreeViewModel
{
    public override IServiceProvider ServiceProvider { get; } = serviceProvider;

    public override ILogger Logger { get; } = serviceProvider.GetRequiredService<ILogger<CrypVolViewModel>>();
    public string Header { get; set; } = string.Empty;
}
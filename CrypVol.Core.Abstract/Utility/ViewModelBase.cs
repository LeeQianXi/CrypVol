using CrypVol.Core.Abstract.Services;
using Microsoft.Extensions.Logging;
using ReactiveUI;

namespace CrypVol.Core.Abstract.Utility;

public abstract class ViewModelBase : ReactiveObject, IDependencyInjection
{
    public abstract IServiceProvider ServiceProvider { get; }
    public abstract ILogger Logger { get; }
}
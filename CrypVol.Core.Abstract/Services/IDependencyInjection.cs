using Microsoft.Extensions.Logging;

namespace CrypVol.Core.Abstract.Services;

public interface IDependencyInjection
{
    IServiceProvider ServiceProvider { get; }
    ILogger Logger { get; }
}
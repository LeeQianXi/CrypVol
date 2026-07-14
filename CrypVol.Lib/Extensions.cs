using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace CrypVol.Lib;

public static class Extensions
{
    extension(IServiceCollection services)
    {
        public IServiceCollection AddMultiSingleton<TI1,
            [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)]
            TO>() where TO : notnull, TI1
        {
            return services
                .Add([
                    new ServiceDescriptor(typeof(TO), typeof(TO), ServiceLifetime.Singleton),
                    new ServiceDescriptor(typeof(TI1), static sp => sp.GetRequiredService<TO>(),
                        ServiceLifetime.Singleton)
                ]);
        }

        public IServiceCollection AddMultiSingleton<TI1,
            [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)]
            TO>(
            TO instance
        ) where TO : notnull, TI1
        {
            return services
                .Add([
                    new ServiceDescriptor(typeof(TO), instance),
                    new ServiceDescriptor(typeof(TI1), instance)
                ]);
        }


        public IServiceCollection AddMultiInstance<TI1,
            [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)]
            TO>(
            ServiceLifetime lifetime
        ) where TO : notnull, TI1
        {
            return services
                .Add([
                    new ServiceDescriptor(typeof(TO), typeof(TO), lifetime),
                    new ServiceDescriptor(typeof(TI1), static sp => sp.GetRequiredService<TO>(), lifetime)
                ]);
        }

        public IServiceCollection AddMultiInstance<TI1,
            [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)]
            TO>(
            Func<IServiceProvider, TO> factory,
            ServiceLifetime lifetime
        ) where TO : notnull, TI1
        {
            return services
                .Add([
                    new ServiceDescriptor(typeof(TO), sp => factory(sp), lifetime),
                    new ServiceDescriptor(typeof(TI1), static sp => sp.GetRequiredService<TO>(), lifetime)
                ]);
        }

        public IServiceCollection AddMultiSingleton<TI1, TI2,
            [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)]
            TO>() where TO : notnull, TI1, TI2
        {
            return services
                .Add([
                    new ServiceDescriptor(typeof(TO), typeof(TO), ServiceLifetime.Singleton),
                    new ServiceDescriptor(typeof(TI1), static sp => sp.GetRequiredService<TO>(),
                        ServiceLifetime.Singleton),
                    new ServiceDescriptor(typeof(TI2), static sp => sp.GetRequiredService<TO>(),
                        ServiceLifetime.Singleton)
                ]);
        }

        public IServiceCollection AddMultiSingleton<TI1, TI2,
            [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)]
            TO>(
            TO instance
        ) where TO : notnull, TI1, TI2
        {
            return services
                .Add([
                    new ServiceDescriptor(typeof(TO), instance),
                    new ServiceDescriptor(typeof(TI1), instance),
                    new ServiceDescriptor(typeof(TI2), instance)
                ]);
        }


        public IServiceCollection AddMultiInstance<TI1, TI2,
            [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)]
            TO>(
            ServiceLifetime lifetime
        ) where TO : notnull, TI1, TI2
        {
            return services
                .Add([
                    new ServiceDescriptor(typeof(TO), typeof(TO), lifetime),
                    new ServiceDescriptor(typeof(TI1), static sp => sp.GetRequiredService<TO>(), lifetime),
                    new ServiceDescriptor(typeof(TI2), static sp => sp.GetRequiredService<TO>(), lifetime)
                ]);
        }

        public IServiceCollection AddMultiInstance<TI1, TI2,
            [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)]
            TO>(
            Func<IServiceProvider, TO> factory,
            ServiceLifetime lifetime
        ) where TO : notnull, TI1, TI2
        {
            return services
                .Add([
                    new ServiceDescriptor(typeof(TO), sp => factory(sp), lifetime),
                    new ServiceDescriptor(typeof(TI1), static sp => sp.GetRequiredService<TO>(), lifetime),
                    new ServiceDescriptor(typeof(TI2), static sp => sp.GetRequiredService<TO>(), lifetime)
                ]);
        }

        public IServiceCollection AddMultiSingleton<TI1, TI2, TI3,
            [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)]
            TO>() where TO : notnull, TI1, TI2, TI3
        {
            return services
                .Add([
                    new ServiceDescriptor(typeof(TO), typeof(TO), ServiceLifetime.Singleton),
                    new ServiceDescriptor(typeof(TI1), static sp => sp.GetRequiredService<TO>(),
                        ServiceLifetime.Singleton),
                    new ServiceDescriptor(typeof(TI2), static sp => sp.GetRequiredService<TO>(),
                        ServiceLifetime.Singleton),
                    new ServiceDescriptor(typeof(TI3), static sp => sp.GetRequiredService<TO>(),
                        ServiceLifetime.Singleton)
                ]);
        }

        public IServiceCollection AddMultiSingleton<TI1, TI2, TI3,
            [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)]
            TO>(
            TO instance
        ) where TO : notnull, TI1, TI2, TI3
        {
            return services
                .Add([
                    new ServiceDescriptor(typeof(TO), instance),
                    new ServiceDescriptor(typeof(TI1), instance),
                    new ServiceDescriptor(typeof(TI2), instance),
                    new ServiceDescriptor(typeof(TI3), instance)
                ]);
        }

        public IServiceCollection AddMultiInstance<TI1, TI2, TI3,
            [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)]
            TO>(
            ServiceLifetime lifetime
        ) where TO : notnull, TI1, TI2, TI3
        {
            return services
                .Add([
                    new ServiceDescriptor(typeof(TO), typeof(TO), lifetime),
                    new ServiceDescriptor(typeof(TI1), static sp => sp.GetRequiredService<TO>(), lifetime),
                    new ServiceDescriptor(typeof(TI2), static sp => sp.GetRequiredService<TO>(), lifetime),
                    new ServiceDescriptor(typeof(TI3), static sp => sp.GetRequiredService<TO>(), lifetime)
                ]);
        }

        public IServiceCollection AddMultiInstance<TI1, TI2, TI3,
            [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)]
            TO>(
            Func<IServiceProvider, TO> factory,
            ServiceLifetime lifetime
        ) where TO : notnull, TI1, TI2, TI3
        {
            return services
                .Add([
                    new ServiceDescriptor(typeof(TO), sp => factory(sp), lifetime),
                    new ServiceDescriptor(typeof(TI1), static sp => sp.GetRequiredService<TO>(), lifetime),
                    new ServiceDescriptor(typeof(TI2), static sp => sp.GetRequiredService<TO>(), lifetime),
                    new ServiceDescriptor(typeof(TI3), static sp => sp.GetRequiredService<TO>(), lifetime)
                ]);
        }

        public IServiceCollection AddMultiSingleton<TI1, TI2, TI3, TI4,
            [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)]
            TO>() where TO : notnull, TI1, TI2, TI3, TI4
        {
            return services
                .Add([
                    new ServiceDescriptor(typeof(TO), typeof(TO), ServiceLifetime.Singleton),
                    new ServiceDescriptor(typeof(TI1), static sp => sp.GetRequiredService<TO>(),
                        ServiceLifetime.Singleton),
                    new ServiceDescriptor(typeof(TI2), static sp => sp.GetRequiredService<TO>(),
                        ServiceLifetime.Singleton),
                    new ServiceDescriptor(typeof(TI3), static sp => sp.GetRequiredService<TO>(),
                        ServiceLifetime.Singleton),
                    new ServiceDescriptor(typeof(TI4), static sp => sp.GetRequiredService<TO>(),
                        ServiceLifetime.Singleton)
                ]);
        }

        public IServiceCollection AddMultiSingleton<TI1, TI2, TI3, TI4,
            [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)]
            TO>(
            TO instance
        ) where TO : notnull, TI1, TI2, TI3, TI4
        {
            return services
                .Add([
                    new ServiceDescriptor(typeof(TO), instance),
                    new ServiceDescriptor(typeof(TI1), instance),
                    new ServiceDescriptor(typeof(TI2), instance),
                    new ServiceDescriptor(typeof(TI3), instance),
                    new ServiceDescriptor(typeof(TI4), instance)
                ]);
        }

        public IServiceCollection AddMultiInstance<TI1, TI2, TI3, TI4,
            [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)]
            TO>(
            ServiceLifetime lifetime
        ) where TO : notnull, TI1, TI2, TI3, TI4
        {
            return services
                .Add([
                    new ServiceDescriptor(typeof(TO), typeof(TO), lifetime),
                    new ServiceDescriptor(typeof(TI1), static sp => sp.GetRequiredService<TO>(), lifetime),
                    new ServiceDescriptor(typeof(TI2), static sp => sp.GetRequiredService<TO>(), lifetime),
                    new ServiceDescriptor(typeof(TI3), static sp => sp.GetRequiredService<TO>(), lifetime),
                    new ServiceDescriptor(typeof(TI4), static sp => sp.GetRequiredService<TO>(), lifetime)
                ]);
        }

        public IServiceCollection AddMultiInstance<TI1, TI2, TI3, TI4,
            [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)]
            TO>(
            Func<IServiceProvider, TO> factory,
            ServiceLifetime lifetime
        ) where TO : notnull, TI1, TI2, TI3, TI4
        {
            return services
                .Add([
                    new ServiceDescriptor(typeof(TO), sp => factory(sp), lifetime),
                    new ServiceDescriptor(typeof(TI1), static sp => sp.GetRequiredService<TO>(), lifetime),
                    new ServiceDescriptor(typeof(TI2), static sp => sp.GetRequiredService<TO>(), lifetime),
                    new ServiceDescriptor(typeof(TI3), static sp => sp.GetRequiredService<TO>(), lifetime),
                    new ServiceDescriptor(typeof(TI4), static sp => sp.GetRequiredService<TO>(), lifetime)
                ]);
        }
    }
}
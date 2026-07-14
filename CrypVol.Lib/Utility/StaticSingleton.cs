namespace CrypVol.Lib.Utility;

public abstract class StaticSingleton<T> where T : new()
{
    public static T Instance => Internal._instance;

    private static class Internal
    {
        public static readonly T _instance = new();
    }
}
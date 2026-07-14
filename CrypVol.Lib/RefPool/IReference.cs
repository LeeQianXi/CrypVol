namespace CrypVol.Lib.RefPool;

/// <summary>
///     引用接口。
/// </summary>
public interface IReference
{
    /// <summary>
    ///     清理引用。
    /// </summary>
    void Reset();
}

public interface IReference<T> : IReference where T : class, IReference<T>, new();

public static class ReferenceExtensions
{
    extension<T>(IReference<T> reference) where T : class, IReference<T>, new()
    {
        public static T AcquireReference()
        {
            return ReferencePool.Acquire<T>();
        }

        public static void AddReference(int count)
        {
            ReferencePool.Add<T>(count);
        }

        public static void RemoveReference(int count)
        {
            ReferencePool.Remove<T>(count);
        }

        public static void RemoveAllReference()
        {
            ReferencePool.RemoveAll<T>();
        }
    }
}
using System.Runtime.InteropServices;

namespace CrypVol.Lib.RefPool;

/// <summary>
///     引用池信息。
/// </summary>
[StructLayout(LayoutKind.Auto)]
public readonly struct ReferencePoolInfo
{
    /// <summary>
    ///     初始化引用池信息的新实例。
    /// </summary>
    /// <param name="type">引用池类型。</param>
    /// <param name="unusedReferenceCount">未使用引用数量。</param>
    /// <param name="usingReferenceCount">正在使用引用数量。</param>
    /// <param name="acquireReferenceCount">获取引用数量。</param>
    /// <param name="releaseReferenceCount">归还引用数量。</param>
    /// <param name="addReferenceCount">增加引用数量。</param>
    /// <param name="removeReferenceCount">移除引用数量。</param>
    public ReferencePoolInfo(Type type, int unusedReferenceCount, int usingReferenceCount, int acquireReferenceCount,
        int releaseReferenceCount, int addReferenceCount, int removeReferenceCount)
    {
        Type = type;
        UnusedReferenceCount = unusedReferenceCount;
        UsingReferenceCount = usingReferenceCount;
        AcquireReferenceCount = acquireReferenceCount;
        ReleaseReferenceCount = releaseReferenceCount;
        AddReferenceCount = addReferenceCount;
        RemoveReferenceCount = removeReferenceCount;
    }

    /// <summary>
    ///     获取引用池类型。
    /// </summary>
    public Type Type { get; }

    /// <summary>
    ///     获取未使用引用数量。
    /// </summary>
    public int UnusedReferenceCount { get; }

    /// <summary>
    ///     获取正在使用引用数量。
    /// </summary>
    public int UsingReferenceCount { get; }

    /// <summary>
    ///     获取获取引用数量。
    /// </summary>
    public int AcquireReferenceCount { get; }

    /// <summary>
    ///     获取归还引用数量。
    /// </summary>
    public int ReleaseReferenceCount { get; }

    /// <summary>
    ///     获取增加引用数量。
    /// </summary>
    public int AddReferenceCount { get; }

    /// <summary>
    ///     获取移除引用数量。
    /// </summary>
    public int RemoveReferenceCount { get; }
}
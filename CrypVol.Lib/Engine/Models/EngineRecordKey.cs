namespace CrypVol.Lib.Engine.Models;

/// <summary>Engine 运行记录的强类型键。</summary>
/// <typeparam name="T">记录值类型。</typeparam>
public sealed class EngineRecordKey<T>
{
    /// <summary>记录名称。</summary>
    public string Name { get; }

    /// <summary>创建强类型记录键。</summary>
    /// <param name="name">记录名称。</param>
    public EngineRecordKey(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        Name = name;
    }
}

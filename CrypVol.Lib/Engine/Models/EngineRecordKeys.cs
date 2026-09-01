namespace CrypVol.Lib.Engine.Models;

/// <summary>引擎内置处理器使用的标准运行记录键。</summary>
public static class EngineRecordKeys
{
    /// <summary>File 完整性校验失败的相对路径集合。</summary>
    public static EngineRecordKey<List<string>> FileIntegrityFailures { get; } =
        new("file-integrity-failures");
}
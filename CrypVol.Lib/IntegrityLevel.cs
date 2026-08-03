namespace CrypVol.Lib;

/// <summary>
///     数据完整性校验级别
/// </summary>
public enum IntegrityLevel
{
    /// <summary>不嵌入校验数据</summary>
    None,

    /// <summary>每个数据块（4KB）附带 CRC32 校验值</summary>
    Block,

    /// <summary>每个文件条目末尾附带 SHA256 校验值</summary>
    File,

    /// <summary>每个卷末尾附带整卷 SHA256 校验值（含以上所有级别）</summary>
    Volume
}
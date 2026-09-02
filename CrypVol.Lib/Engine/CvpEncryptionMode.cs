namespace CrypVol.Lib.Engine;

/// <summary>CVP 数据是否使用 CEK 加密。</summary>
public enum CvpEncryptionMode : byte
{
    /// <summary>不加密 CVP 数据。</summary>
    None = 0,

    /// <summary>使用已加载的 CEK 加密 CVP 数据。</summary>
    Cek = 1
}
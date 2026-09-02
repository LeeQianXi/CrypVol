using CrypVol.Lib.Crypto.Keys;
using CrypVol.Lib.Crypto.Models;

namespace CrypVol.Lib.Crypto;

/// <summary>CVK 在内存中的可修改原始数据集合。</summary>
/// <remarks>
///     <para>该类型只描述已经解封或准备封装的 CEK 及其公开元数据。</para>
///     <para>它不负责 Header/Payload 拼装、JSON 转换、文件读写、加密、解密或完整性计算。</para>
/// </remarks>
public sealed class CvkDocument
{
    /// <summary>原始内容加密密钥。仅供解封后的内存流程使用，写入时必须被封装。</summary>
    public byte[] Cek { get; set; } = [];

    /// <summary>CEK 的保护模式。</summary>
    public CvkKeyProtection KeyProtection { get; set; }

    /// <summary>用于封装或派生 CEK 的算法。</summary>
    public CvkKeyWrapAlgorithm KeyWrapAlgorithm { get; set; }

    /// <summary>公钥模式下的接收者公钥材料。</summary>
    /// <remarks>保存公钥材料而不是源文件路径，以便源文件消失后仍可编辑 CVK。</remarks>
    public IList<AsymmetricRecipientKey> RecipientKeys { get; } = new List<AsymmetricRecipientKey>();

    /// <summary>CVK 协议版本。</summary>
    public ushort Version { get; set; } = 1;

    /// <summary>用户可读标签。</summary>
    public string? Label { get; set; }

    /// <summary>用途描述。</summary>
    public string? Description { get; set; }

    /// <summary>附加注释。</summary>
    public string? Comment { get; set; }

    /// <summary>创建时间。</summary>
    public DateTimeOffset? CreatedAt { get; set; }

    /// <summary>生成器标识。</summary>
    public string? Generator { get; set; }
}
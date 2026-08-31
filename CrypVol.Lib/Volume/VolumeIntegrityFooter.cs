using System.Security.Cryptography;
using System.Text;

namespace CrypVol.Lib.Volume;

/// <summary>保存并验证 Volume 级 SHA-256 的固定长度卷尾记录。</summary>
public static class VolumeIntegrityFooter
{
    /// <summary>卷尾魔数的长度。</summary>
    public const int MagicLength = 4;

    /// <summary>SHA-256 摘要的长度。</summary>
    public const int HashLength = 32;

    /// <summary>卷尾记录总长度。</summary>
    public const int Length = MagicLength + HashLength;

    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("CVPF");

    /// <summary>构建卷尾记录。</summary>
    /// <param name="hash">卷正文的 SHA-256 摘要。</param>
    /// <returns>可直接追加到卷末的记录。</returns>
    public static byte[] Create(byte[] hash)
    {
        ArgumentNullException.ThrowIfNull(hash);
        if (hash.Length != HashLength) throw new ArgumentException("卷 SHA-256 摘要长度无效。", nameof(hash));
        var footer = new byte[Length];
        Magic.CopyTo(footer, 0);
        hash.CopyTo(footer, MagicLength);
        return footer;
    }

    /// <summary>判断字节序列是否以卷尾魔数开头。</summary>
    /// <param name="value">待检查的字节序列。</param>
    /// <returns>是否为卷尾魔数。</returns>
    public static bool IsMagic(ReadOnlySpan<byte> value)
    {
        return value.Length >= MagicLength && value[..MagicLength].SequenceEqual(Magic);
    }

    /// <summary>验证卷尾记录和卷正文 SHA-256。</summary>
    /// <param name="path">卷文件路径。</param>
    /// <returns>卷尾有效时返回 true。</returns>
    public static bool Verify(string path)
    {
        using var stream = File.OpenRead(path);
        if (stream.Length < Length) return false;
        stream.Position = stream.Length - Length;
        var footer = new byte[Length];
        if (stream.Read(footer) != footer.Length || !footer.AsSpan(0, MagicLength).SequenceEqual(Magic)) return false;
        stream.Position = 0;
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[1024 * 1024];
        var remaining = stream.Length - Length;
        while (remaining > 0)
        {
            var read = stream.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining));
            if (read == 0) return false;
            hash.AppendData(buffer, 0, read);
            remaining -= read;
        }

        return CryptographicOperations.FixedTimeEquals(footer.AsSpan(MagicLength), hash.GetHashAndReset());
    }

    /// <summary>使用当前卷正文重写卷尾记录。</summary>
    /// <param name="path">卷文件路径。</param>
    public static void Rewrite(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        if (stream.Length < Length) throw new InvalidDataException("卷缺少完整性卷尾。");
        stream.Position = stream.Length - Length;
        var magic = new byte[MagicLength];
        if (stream.Read(magic) != magic.Length || !magic.AsSpan().SequenceEqual(Magic))
            throw new InvalidDataException("卷缺少完整性卷尾。");
        stream.Position = 0;
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[1024 * 1024];
        var remaining = stream.Length - Length;
        while (remaining > 0)
        {
            var read = stream.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining));
            if (read == 0) throw new EndOfStreamException();
            hash.AppendData(buffer, 0, read);
            remaining -= read;
        }

        var footer = Create(hash.GetHashAndReset());
        stream.Position = stream.Length - Length;
        stream.Write(footer);
    }
}
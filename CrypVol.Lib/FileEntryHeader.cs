using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace CrypVol.Lib;

[StructLayout(LayoutKind.Explicit, Size = HeaderSize, Pack = 1)]
public unsafe struct FileEntryHeader()
{
    // ========== 固定元数据头 (25 字节) ==========
    [FieldOffset(0)] public uint Magic = MagicHeader; // 0-3
    [FieldOffset(4)] public ulong FileId; // 4-11
    [FieldOffset(12)] public byte Flags; // 12
    [FieldOffset(13)] public uint FragmentIndex; // 13-16
    [FieldOffset(17)] public long SizeOrTotal; // 17-24

    // ========== 路径数据段 (231 字节) ==========
    [FieldOffset(25)] private fixed byte FilePath[231];

    // ------------------------- 常量 -------------------------
    public const uint MagicHeader = 0x48505643;
    public const int HeaderSize = 256;

    /// <summary>加密后的头部大小: Magic(4) + Nonce(12) + Ciphertext(252) + Tag(16)</summary>
    public const int EncryptedHeaderSize = 284;

    public byte[] ToBytes()
    {
        var buffer = new byte[256];
        fixed (FileEntryHeader* ptr = &this)
        {
            Marshal.Copy((IntPtr)ptr, buffer, 0, 256);
        }

        return buffer;
    }

    /// <summary>将文件路径写入头部的 fixed buffer（最多 231 字节）</summary>
    public void SetFilePath(string path)
    {
        var bytes = Encoding.UTF8.GetBytes(path);
        var len = Math.Min(bytes.Length, 230);
        for (var i = 0; i < len; i++)
            FilePath[i] = bytes[i];
        FilePath[len] = 0;
    }

    /// <summary>加密头部：返回 Magic(4) + Nonce(12) + Ciphertext(252) + Tag(16) = 284 字节</summary>
    public static byte[] Encrypt(FileEntryHeader hdr, byte[] cek)
    {
        var plain = hdr.ToBytes(); // 256B, includes Magic
        var nonce = RandomNumberGenerator.GetBytes(12);
        var payload = plain.AsSpan(4, 252); // skip Magic
        var ciphertext = new byte[252];
        var tag = new byte[16];

        using var aes = new AesGcm(cek, 16);
        aes.Encrypt(nonce, payload, ciphertext, tag);

        var result = new byte[EncryptedHeaderSize]; // 284
        Buffer.BlockCopy(plain, 0, result, 0, 4); // Magic
        Buffer.BlockCopy(nonce, 0, result, 4, 12); // Nonce
        Buffer.BlockCopy(ciphertext, 0, result, 16, 252); // Ciphertext
        Buffer.BlockCopy(tag, 0, result, 268, 16); // Tag
        return result;
    }

    /// <summary>解密头部：读取 284 字节，返回 FileEntryHeader</summary>
    public static FileEntryHeader Decrypt(byte[] encrypted, byte[] cek)
    {
        var nonce = encrypted.AsSpan(4, 12);
        var ciphertext = encrypted.AsSpan(16, 252);
        var tag = encrypted.AsSpan(268, 16);
        var plain = new byte[256];
        Buffer.BlockCopy(encrypted, 0, plain, 0, 4); // copy magic

        using var aes = new AesGcm(cek, 16);
        aes.Decrypt(nonce, ciphertext, tag, plain.AsSpan(4, 252));

        return MemoryMarshal.Read<FileEntryHeader>(plain);
    }

    /// <summary>仅读取加密头中的 Magic（无需解密）</summary>
    public static uint ReadMagic(byte[] encrypted)
    {
        return BitConverter.ToUInt32(encrypted, 0);
    }
}

[Flags]
public enum FileEntryHeaderFlagsEnum : byte
{
    /// 完整段
    Full = 0b_0000_0000,

    /// 跨卷首段（填满卷尾）
    CrossHead = 0b_0000_0001,

    /// 跨卷中间段（占满整卷）
    CrossMid = 0b_0000_0010,

    /// 跨卷尾段（收尾）
    CrossTail = 0b_0000_0011,
    HasExtendedHeader = 0b_0000_0100
}
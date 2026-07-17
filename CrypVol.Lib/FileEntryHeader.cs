using System.Runtime.InteropServices;
using System.Text;

namespace CrypVol.Lib;

[StructLayout(LayoutKind.Explicit, Size = HEADER_SIZE, Pack = 1)]
public unsafe struct FileEntryHeader
{
    // ========== 固定元数据头 (25 字节) ==========
    [FieldOffset(0)] public uint Magic; // 0-3
    [FieldOffset(4)] public ulong FileId; // 4-11
    [FieldOffset(12)] public byte Flags; // 12
    [FieldOffset(13)] public uint SegmentIndex; // 13-16
    [FieldOffset(17)] public ulong SizeOrTotal; // 17-24

    // ========== 路径数据段 (231 字节) ==========
    [FieldOffset(25)] private fixed byte FilePath[231];

    // ------------------------- 常量 -------------------------
    public const uint MAGIC = 0x48505643;
    public const int HEADER_SIZE = 256;

    // ------------------------- 哈希计算 (FNV-1a 64位) -------------------------
    private static ulong ComputeHash(byte[] bytes)
    {
        const ulong offsetBasis = 14695981039346656037UL;
        const ulong prime = 1099511628211UL;
        var hash = offsetBasis;
        foreach (var b in bytes)
        {
            hash ^= b;
            hash *= prime;
        }

        return hash;
    }

    // ------------------------- 路径读写 -------------------------
    public string GetFilePath()
    {
        fixed (byte* ptr = FilePath)
        {
            // 查找第一个 0x00 截断
            var len = 0;
            while (len < 231 && ptr[len] != 0) len++;
            return Encoding.UTF8.GetString(ptr, len);
        }
    }

    /// <exception cref="ArgumentException">路径超过 231 字节限制</exception>
    public void SetFilePath(string path)
    {
        var bytes = Encoding.UTF8.GetBytes(path);
        if (bytes.Length >= 231)
            throw new ArgumentException("路径超过 231 字节限制");
        for (var i = 0; i < bytes.Length; i++) FilePath[i] = bytes[i];
        // 剩余部分置零
        for (var i = bytes.Length; i < 231; i++) FilePath[i] = 0;
        // 自动计算 FileId
        FileId = ComputeHash(bytes);
    }

    // ------------------------- 序列化 / 反序列化 -------------------------
    public byte[] ToBytes()
    {
        var buffer = new byte[256];
        fixed (FileEntryHeader* ptr = &this)
        {
            Marshal.Copy((IntPtr)ptr, buffer, 0, 256);
        }

        return buffer;
    }

    /// <exception cref="ArgumentException">缓冲区不足 256 字节</exception>
    /// <exception cref="InvalidDataException">无效魔数</exception>
    public static FileEntryHeader FromBytes(byte[] buffer)
    {
        if (buffer.Length < 256)
            throw new ArgumentException("缓冲区不足 256 字节");

        fixed (byte* ptr = buffer)
        {
            var header = *(FileEntryHeader*)ptr;
            if (header.Magic != MAGIC)
                throw new InvalidDataException("无效魔数");
            return header;
        }
    }

    // ------------------------- 业务辅助 -------------------------
    public bool IsFirstSegment => SegmentIndex == 0;
    public bool IsCrossHead => Flags == (byte)FileEntryHeaderFlagsEnum.CrossHead;

    /// 获取本段有效数据量（调用者需注意 CrossHead 特殊处理）
    public ulong GetSegmentDataSize()
    {
        // 跨卷首段（Flags=1, Index=0）：数据长度由物理卷尾 EOF 决定，头部返回 0
        if (IsCrossHead && IsFirstSegment) return 0;
        return SizeOrTotal;
    }

    public ulong GetFileTotalSize()
    {
        return IsFirstSegment ? SizeOrTotal : 0;
    }
}

public enum FileEntryHeaderFlagsEnum : byte
{
    /// 完整段
    Full = 0,

    /// 跨卷首段（填满卷尾）
    CrossHead = 1,

    /// 跨卷中间段（占满整卷）
    CrossMid = 2,

    /// 跨卷尾段（收尾）
    CrossTail = 3
}
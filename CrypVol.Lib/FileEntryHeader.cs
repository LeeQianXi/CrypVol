using System.Runtime.InteropServices;

namespace CrypVol.Lib;

[StructLayout(LayoutKind.Explicit, Size = HeaderSize, Pack = 1)]
public unsafe struct FileEntryHeader()
{
    // ========== 固定元数据头 (25 字节) ==========
    [FieldOffset(0)] public uint Magic = MagicHeader; // 0-3
    [FieldOffset(4)] public ulong FileId; // 4-11
    [FieldOffset(12)] public byte Flags; // 12
    [FieldOffset(13)] public uint FragmentIndex; // 13-16
    [FieldOffset(17)] public ulong SizeOrTotal; // 17-24

    // ========== 路径数据段 (231 字节) ==========
    [FieldOffset(25)] private fixed byte FilePath[231];

    // ------------------------- 常量 -------------------------
    public const uint MagicHeader = 0x48505643;
    public const int HeaderSize = 256;
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
    HasExtendedHeader = 0b_0000_0100,
}
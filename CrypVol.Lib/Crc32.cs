using System.Buffers;

namespace CrypVol.Lib;

/// <summary>CRC-32 (IEEE 802.3) 快速实现</summary>
public static class Crc32
{
    private const uint Polynomial = 0xEDB88320u;
    private static readonly uint[] _table = BuildTable();
    private static readonly ThreadLocal<uint[]> _buffer = new(() => new uint[256]);

    private static uint[] BuildTable()
    {
        var table = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            var crc = i;
            for (var j = 0; j < 8; j++)
                crc = (crc & 1) != 0 ? (crc >> 1) ^ Polynomial : crc >> 1;
            table[i] = crc;
        }
        return table;
    }

    /// <summary>计算 CRC32 校验值</summary>
    public static uint Compute(ReadOnlySpan<byte> data)
    {
        var crc = 0xFFFFFFFFu;
        foreach (var b in data)
            crc = (crc >> 8) ^ _table[(crc ^ b) & 0xFF];
        return crc ^ 0xFFFFFFFFu;
    }
}

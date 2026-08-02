using System.Runtime.InteropServices;
using System.Text;

namespace CrypVol.Lib;

/// <summary>扫描 .cvp 卷头，构建文件→片段映射</summary>
public static class VolumeScanner
{
    public static Dictionary<string, List<Fragment>> Scan(List<string> volumes)
    {
        var files = new Dictionary<string, List<Fragment>>();

        foreach (var cvp in volumes)
        {
            using var fs = File.OpenRead(cvp);
            long pos = 0;
            var hdrBuf = new byte[FileEntryHeader.HeaderSize];

            while (pos + FileEntryHeader.HeaderSize <= fs.Length)
            {
                fs.Position = pos;
                if (fs.Read(hdrBuf) < FileEntryHeader.HeaderSize) break;

                var hdr = MemoryMarshal.Read<FileEntryHeader>(hdrBuf);
                if (hdr.Magic != FileEntryHeader.MagicHeader)
                {
                    pos += 4;
                    continue;
                }

                var relPath = ReadPath(hdr);
                var flags = (FileEntryHeaderFlagsEnum)hdr.Flags;
                pos += FileEntryHeader.HeaderSize;

                // 此 header 对应文件的首个片段？
                var isFirst = !flags.HasFlag(FileEntryHeaderFlagsEnum.CrossMid)
                              && !flags.HasFlag(FileEntryHeaderFlagsEnum.CrossTail);

                // 读取该段的所有块
                while (pos + 4 <= fs.Length)
                {
                    var peek = new byte[4];
                    fs.Position = pos;
                    if (fs.Read(peek) < 4) break;
                    if (BitConverter.ToUInt32(peek) == FileEntryHeader.MagicHeader) break;

                    var blockLen = BitConverter.ToInt32(peek);
                    pos += 4;

                    if (!files.TryGetValue(relPath, out var list))
                        files[relPath] = list = [];

                    list.Add(new Fragment(cvp, pos, blockLen, hdr.SizeOrTotal,
                        hdr.Flags, isFirst && list.Count == 0));

                    pos += blockLen;
                }
            }
        }

        return files;
    }

    private static string ReadPath(FileEntryHeader hdr)
    {
        var bytes = hdr.ToBytes();
        var start = 25;
        var end = start;
        while (end < bytes.Length && bytes[end] != 0) end++;
        return Encoding.UTF8.GetString(bytes, start, end - start);
    }

    public record Fragment(string CvpPath, long CvpOffset, int BlockSize, long TotalFileSize, byte Flags, bool IsFirst);
}
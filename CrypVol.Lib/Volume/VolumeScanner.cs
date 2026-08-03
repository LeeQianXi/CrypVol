using System.Runtime.InteropServices;
using System.Text;

namespace CrypVol.Lib.Volume;

/// <summary>扫描 .cvp 卷头，构建文件→片段映射。cek 非 null 时解密加密头。</summary>
public static class VolumeScanner
{
    public static Dictionary<string, List<Fragment>> Scan(IEnumerable<FileInfo> volumes, EncryptionMode mode,
        byte[]? cek = null)
    {
        var files = new Dictionary<string, List<Fragment>>();

        foreach (var cvp in volumes)
        {
            using var fs = File.OpenRead(cvp.FullName);
            long pos = 0;
            var magicBuf = new byte[4];

            while (pos + 4 <= fs.Length)
            {
                fs.Position = pos;
                if (fs.Read(magicBuf) < 4) break;
                if (BitConverter.ToUInt32(magicBuf) != FileEntryHeader.MagicHeader)
                {
                    pos += 4;
                    continue;
                }

                // Try encrypted header first if CEK provided, else plain
                FileEntryHeader hdr;
                int headerLen;
                if (mode is EncryptionMode.None)
                {
                    var plainBuf = new byte[FileEntryHeader.HeaderSize];
                    fs.Position = pos;
                    if (fs.Read(plainBuf) < FileEntryHeader.HeaderSize) break;

                    hdr = MemoryMarshal.Read<FileEntryHeader>(plainBuf);
                    headerLen = FileEntryHeader.HeaderSize;
                }
                else
                {
                    var encBuf = new byte[FileEntryHeader.EncryptedHeaderSize];
                    fs.Position = pos;
                    if (fs.Read(encBuf) < FileEntryHeader.EncryptedHeaderSize) break;

                    try { hdr = FileEntryHeader.Decrypt(encBuf, cek!); }
                    catch
                    {
                        pos += 4;
                        continue;
                    } // corrupt header

                    headerLen = FileEntryHeader.EncryptedHeaderSize;
                }

                string relPath;
                try { relPath = ReadPath(hdr); }
                catch
                {
                    pos += headerLen;
                    continue;
                }

                var flags = (FileEntryHeaderFlagsEnum)hdr.Flags;
                pos += headerLen;

                var isFirst = !flags.HasFlag(FileEntryHeaderFlagsEnum.CrossMid)
                              && !flags.HasFlag(FileEntryHeaderFlagsEnum.CrossTail);

                try
                {
                    while (pos + 4 <= fs.Length)
                    {
                        var peek = new byte[4];
                        fs.Position = pos;
                        if (fs.Read(peek) < 4) break;
                        if (BitConverter.ToUInt32(peek) == FileEntryHeader.MagicHeader) break;

                        var blockLen = BitConverter.ToInt32(peek);
                        if (blockLen <= 0) break; // garbage data or EOF
                        pos += 4;

                        if (!files.TryGetValue(relPath, out var list))
                            files[relPath] = list = [];

                        list.Add(new Fragment(cvp, pos, blockLen, hdr.SizeOrTotal,
                            hdr.Flags, isFirst && list.Count == 0));

                        pos += blockLen;
                    }
                }
                catch
                {
                    /* skip corrupt blocks */
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

    public record Fragment(FileInfo CvpFile, long CvpOffset, int BlockSize, long TotalFileSize, byte Flags, bool IsFirst);
}
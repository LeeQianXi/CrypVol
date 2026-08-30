using System.Runtime.InteropServices;
using System.Text;
using CrypVol.Lib.Utility;
using Microsoft.Extensions.Logging;

namespace CrypVol.Lib.Volume;

/// <summary>扫描 .cvp 卷头，构建文件→片段映射。魔数自动识别明文(CVPH)/加密(CVPE)头。filter 非 null 时跳过不匹配的文件。</summary>
public static class VolumeScanner
{
    public static ScanResult Scan(IEnumerable<FileInfo> volumes, byte[]? cek = null,
        GlobMatcher? filter = null, ILogger? logger = null)
    {
        var files = new Dictionary<string, List<Fragment>>();
        var possiblyEncrypted = false;

        Span<byte> magicBuf = stackalloc byte[4];
        Span<byte> plainBuf = stackalloc byte[FileEntryHeader.HeaderSize];
        Span<byte> peekBuf = stackalloc byte[4];

        foreach (var cvp in volumes)
        {
            logger?.LogTrace("扫描卷: {Path}", cvp.Name);
            if (possiblyEncrypted) break;
            using var fs = File.OpenRead(cvp.FullName);
            long pos = 0;

            while (pos + 4 <= fs.Length)
            {
                fs.Position = pos;
                if (fs.Read(magicBuf) < 4) break;
                var magic = BitConverter.ToUInt32(magicBuf);

                if (!FileEntryHeader.IsValidMagic(magic))
                    break;

                var isEncrypted = FileEntryHeader.IsEncryptedMagic(magic);

                FileEntryHeader hdr;
                int headerLen;

                if (isEncrypted)
                {
                    if (cek is null)
                    {
                        possiblyEncrypted = true;
                        break;
                    }

                    var encBuf = new byte[FileEntryHeader.EncryptedHeaderSize];
                    fs.Position = pos;
                    if (fs.Read(encBuf) < FileEntryHeader.EncryptedHeaderSize) break;

                    try { hdr = FileEntryHeader.Decrypt(encBuf, cek); }
                    catch { break; }

                    headerLen = FileEntryHeader.EncryptedHeaderSize;
                }
                else
                {
                    fs.Position = pos;
                    if (fs.Read(plainBuf) < FileEntryHeader.HeaderSize) break;

                    hdr = MemoryMarshal.Read<FileEntryHeader>(plainBuf);
                    headerLen = FileEntryHeader.HeaderSize;
                }

                string relPath;
                try { relPath = ReadPath(hdr); }
                catch { break; }

                pos += headerLen;

                var includeFile = filter is null || filter.IsMatch(relPath);
                if (!includeFile)
                {
                    while (pos + 4 <= fs.Length)
                    {
                        fs.Position = pos;
                        if (fs.Read(peekBuf) < 4) break;
                        if (FileEntryHeader.IsValidMagic(BitConverter.ToUInt32(peekBuf))) break;
                        var skipLen = BitConverter.ToInt32(peekBuf);
                        if (skipLen < 0) break;
                        pos += 4 + skipLen;
                    }

                    continue;
                }

                var flags = (FileEntryHeaderFlagsEnum)hdr.Flags;
                var isFirst = !flags.HasFlag(FileEntryHeaderFlagsEnum.CrossMid)
                              && !flags.HasFlag(FileEntryHeaderFlagsEnum.CrossTail);

                while (pos + 4 <= fs.Length)
                {
                    fs.Position = pos;
                    if (fs.Read(peekBuf) < 4) break;

                    var nextMagic = BitConverter.ToUInt32(peekBuf);
                    if (FileEntryHeader.IsValidMagic(nextMagic)) break;

                    var blockLen = BitConverter.ToInt32(peekBuf);
                    if (blockLen < 0) break;
                    pos += 4;

                    if (!files.TryGetValue(relPath, out var list))
                        files[relPath] = list = [];

                    list.Add(new Fragment(cvp, pos, blockLen, hdr.SizeOrTotal,
                        hdr.Flags, isFirst && list.Count == 0, hdr.FragmentIndex));

                    pos += blockLen;
                }
            }
        }

        logger?.LogInformation("扫描完成: {FileCount} 文件, {VolCount} 卷, 加密={Encrypted}",
            files.Count, volumes.Count(), possiblyEncrypted ? "是" : "否");
        return new ScanResult
        {
            Files = files,
            PossiblyEncrypted = possiblyEncrypted
        };
    }

    private static string ReadPath(FileEntryHeader hdr)
    {
        var bytes = hdr.ToBytes();
        var start = 25;
        var end = start;
        while (end < bytes.Length && bytes[end] != 0) end++;
        return Encoding.UTF8.GetString(bytes, start, end - start);
    }

    public record Fragment(FileInfo CvpFile,
        long CvpOffset,
        int BlockSize,
        long TotalFileSize,
        byte Flags,
        bool IsFirst,
        uint FragmentIndex);

    public sealed class ScanResult
    {
        public required Dictionary<string, List<Fragment>> Files { get; init; }
        public bool PossiblyEncrypted { get; init; }
    }
}
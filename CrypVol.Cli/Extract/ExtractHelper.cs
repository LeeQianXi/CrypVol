using System.Buffers;
using System.CommandLine;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using CrypVol.Cli.Pipeline;
using CrypVol.Lib;

namespace CrypVol.Cli.Extract;

public static class ExtractHelper
{
    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        var volFiles = args.GetRequiredValue(CommandDefinition.Extract.VolFiles);
        var outputDir = args.GetValue(CommandDefinition.Extract.Output)!;
        var overwrite = args.GetValue(CommandDefinition.Extract.Overwrite);
        var threads = args.GetValue(CommandDefinition.Extract.Threads);
        threads = Math.Clamp(threads, 1, Environment.ProcessorCount);

        if (!outputDir.Exists) outputDir.Create();

        // ── 1. 发现同组所有卷 ──
        var allVolumes = DiscoverVolumes(volFiles);
        if (allVolumes.Count == 0) { Console.WriteLine("未找到 .cvp 文件"); return 1; }
        Console.WriteLine($"发现 {allVolumes.Count} 个卷");

        // ── 2. 获取 CEK ──
        var (cek, compressed) = LoadCek(args, allVolumes[0]);
        if (cek is null) { Console.WriteLine("无法获取解密密钥"); return 1; }

        // ── 3. 扫描卷 → (文件路径 → 片段列表) ──
        var fileFragments = ScanVolumes(allVolumes);
        if (fileFragments.Count == 0) { Console.WriteLine("未在卷中发现文件"); return 1; }
        Console.WriteLine($"发现 {fileFragments.Count} 个文件");

        // ── 4. 分配输出文件序号 → 创建 WorkItems ──
        var fileIndex = new Dictionary<string, int>();
        int nextIdx = 0;
        foreach (var path in fileFragments.Keys)
            fileIndex[path] = nextIdx++;

        var items = new List<WorkItem>();
        foreach (var (relPath, fragments) in fileFragments)
        {
            var volId = fileIndex[relPath];
            long fileSeq = 0;
            foreach (var f in fragments)
            {
                items.Add(new WorkItem
                {
                    RelativePath = relPath,
                    SourceFullPath = f.CvpPath,
                    VolumeIndex = volId,
                    Sequence = fileSeq,
                    SourceOffset = f.CvpOffset,
                    Length = f.BlockSize,
                    TotalFileSize = f.TotalFileSize,
                    Flags = f.Flags,
                    IsFirstFragment = f.IsFirst
                });
                fileSeq++;
            }
        }

        // ── 5. 流水线 ──
        var pipelineConfig = new PipelineConfig
        {
            ReaderConcurrency = Math.Min(items.Count, 6),
            TransformConcurrency = threads,
            RawChannelCapacity = 128,
            ProcessedChannelCapacity = 128
        };

        var transform = new ExtractTransform(cek, compressed);
        var pipeline = new Pipeline.Pipeline(pipelineConfig, transform)
        {
            ReadBlockAsync = ReadFromCvpAsync,
            WriteVolumeAsync = (ctx, ct) => WriteFileAsync(outputDir.FullName, overwrite, ctx, ct)
        };

        // 注册输出文件
        foreach (var kv in fileIndex)
        {
            var filePath = Path.Combine(outputDir.FullName, kv.Key);
            var dir = Path.GetDirectoryName(filePath);
            if (dir is not null) Directory.CreateDirectory(dir);
            pipeline.AddVolume(kv.Value, filePath, 0);
        }

        await pipeline.RunAsync(items, token);
        Console.WriteLine($"提取完成 → {outputDir.FullName}");
        return 0;
    }

    // ═══════════════════════════════════════════════════════
    //  密钥加载
    // ═══════════════════════════════════════════════════════

    private static (byte[]? cek, bool compressed) LoadCek(ParseResult args, string firstVol)
    {
        var keyFile = args.GetValue(CommandDefinition.Extract.KeyFile);
        if (keyFile is null)
        {
            var cvkName = Path.GetFileNameWithoutExtension(firstVol);
            var lastDot = cvkName.LastIndexOf('.');
            if (lastDot > 0) cvkName = cvkName[..lastDot];
            var autoCvk = Path.Combine(Path.GetDirectoryName(firstVol)!, cvkName + ".cvk");
            if (File.Exists(autoCvk)) keyFile = new FileInfo(autoCvk);
            else return (null, false);
        }

        var password = args.GetValue(CommandDefinition.Extract.Password);
        RSA? privKey = null;
        var privPath = args.GetValue(CommandDefinition.Extract.PrivkeyKey);
        if (privPath is not null)
        {
            privKey = RSA.Create();
            privKey.ImportFromPem(File.ReadAllText(privPath.FullName));
        }

        try
        {
            var (cek, _, _) = KeyEnvelope.LoadEnvelope(keyFile.FullName, password, privKey);
            return (cek, false);
        }
        finally { privKey?.Dispose(); }
    }

    // ═══════════════════════════════════════════════════════
    //  卷发现
    // ═══════════════════════════════════════════════════════

    private static List<string> DiscoverVolumes(ICollection<FileSystemInfo> inputs)
    {
        var result = new HashSet<string>();
        foreach (var input in inputs.OfType<FileInfo>())
        {
            if (!input.Name.EndsWith(".cvp", StringComparison.OrdinalIgnoreCase)) continue;
            var dir = input.DirectoryName!;
            var name = input.Name;
            var lastDot = name.LastIndexOf('.');
            var secondLastDot = name.LastIndexOf('.', lastDot - 1);
            var prefix = secondLastDot > 0 ? name[..secondLastDot] : Path.GetFileNameWithoutExtension(name);

            foreach (var f in Directory.GetFiles(dir, $"{prefix}.*.cvp"))
                result.Add(f);
        }

        return result.OrderBy(f =>
        {
            // 按卷号排序
            var name = Path.GetFileNameWithoutExtension(f);
            var parts = name.Split('.');
            return parts.Length > 1 && int.TryParse(parts[^1], out var n) ? n : 0;
        }).ToList();
    }

    // ═══════════════════════════════════════════════════════
    //  卷扫描
    // ═══════════════════════════════════════════════════════

    private record RawFragment(string CvpPath, long CvpOffset, int BlockSize, long TotalFileSize,
        byte Flags, bool IsFirst);

    private static Dictionary<string, List<RawFragment>> ScanVolumes(List<string> volumes)
    {
        var files = new Dictionary<string, List<RawFragment>>();

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
                if (hdr.Magic != FileEntryHeader.MagicHeader) { pos += 4; continue; }

                var relPath = ReadFilePath(hdr);
                var flags = (FileEntryHeaderFlagsEnum)hdr.Flags;
                pos += FileEntryHeader.HeaderSize;

                // 跨卷中间段不以文件头开始，跳过 header 判断
                if (flags.HasFlag(FileEntryHeaderFlagsEnum.CrossMid) ||
                    flags.HasFlag(FileEntryHeaderFlagsEnum.CrossTail))
                {
                    // 这些段的 header 标记但它们的数据前面没有独立 header
                    // 继续读取块
                }

                var isFirst = !flags.HasFlag(FileEntryHeaderFlagsEnum.CrossMid) &&
                              !flags.HasFlag(FileEntryHeaderFlagsEnum.CrossTail);

                // 读取该文件段的所有块（直到下一个 magic 或 EOF）
                while (pos + 4 <= fs.Length)
                {
                    var peek = new byte[4];
                    fs.Position = pos;
                    if (fs.Read(peek) < 4) break;

                    var maybeMagic = BitConverter.ToUInt32(peek);
                    if (maybeMagic == FileEntryHeader.MagicHeader) break;

                    var blockLen = BitConverter.ToInt32(peek);
                    pos += 4;

                    if (!files.ContainsKey(relPath))
                        files[relPath] = new List<RawFragment>();

                    // 用第一段的 IsFirst，后续段 IsFirst=false
                    var firstForThisFragment = isFirst && files[relPath].Count == 0;
                    files[relPath].Add(new RawFragment(cvp, pos, blockLen, hdr.SizeOrTotal,
                        hdr.Flags, firstForThisFragment));

                    pos += blockLen;
                }
            }
        }

        return files;
    }

    private static string ReadFilePath(FileEntryHeader hdr)
    {
        // FileEntryHeader 布局: 25 字节固定字段 + 231 字节 fixed buffer FilePath
        var bytes = hdr.ToBytes();
        var pathStart = 25;
        var pathEnd = pathStart;
        while (pathEnd < bytes.Length && bytes[pathEnd] != 0) pathEnd++;
        return System.Text.Encoding.UTF8.GetString(bytes, pathStart, pathEnd - pathStart);
    }

    // ═══════════════════════════════════════════════════════
    //  Stage 1: 从 .cvp 读加密数据
    // ═══════════════════════════════════════════════════════

    private static async Task<RawBlock?> ReadFromCvpAsync(WorkItem item, CancellationToken token)
    {
        var buf = ArrayPool<byte>.Shared.Rent(item.Length);
        try
        {
            await using var fs = File.OpenRead(item.SourceFullPath);
            fs.Position = item.SourceOffset;
            var read = await fs.ReadAsync(buf.AsMemory(0, item.Length), token);
            return new RawBlock { Work = item, Data = buf, DataLength = read };
        }
        catch
        {
            ArrayPool<byte>.Shared.Return(buf);
            throw;
        }
    }

    // ═══════════════════════════════════════════════════════
    //  Stage 4: 写入输出文件
    // ═══════════════════════════════════════════════════════

    private static async Task WriteFileAsync(string baseDir, bool overwrite,
        VolumeContext ctx, CancellationToken token)
    {
        var fullPath = ctx.OutputPath;
        if (!overwrite && File.Exists(fullPath))
        {
            await foreach (var _ in ctx.OutputChannel.Reader.ReadAllAsync(token)) { }
            return;
        }

        var dir = Path.GetDirectoryName(fullPath);
        if (dir is not null) Directory.CreateDirectory(dir);

        await using var fs = new FileStream(fullPath, FileMode.Create, FileAccess.Write,
            FileShare.None, 4096 * 16, FileOptions.SequentialScan);

        long pos = 0;
        await foreach (var block in ctx.OutputChannel.Reader.ReadAllAsync(token))
        {
            fs.Position = pos;
            await fs.WriteAsync(block.Data.AsMemory(0, block.OutputLength), token);
            pos += block.OutputLength;
            block.Dispose();
        }
    }
}

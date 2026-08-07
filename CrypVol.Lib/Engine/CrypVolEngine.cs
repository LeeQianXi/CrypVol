using CrypVol.Lib.Engine.Models;
using CrypVol.Lib.IO.Sinks;
using CrypVol.Lib.IO.Sources;
using CrypVol.Lib.Pipeline;
using CrypVol.Lib.Transforms;
using CrypVol.Lib.Volume;

namespace CrypVol.Lib.Engine;

/// <summary>
///     CrypVol 核心引擎。提供 Pack / Extract / Rekey 操作的统一入口，
///     支持进度回调，可同时供 CLI 和 GUI 调用。
///     纯单线程顺序处理，不使用并发原语。
/// </summary>
public sealed class CrypVolEngine
{
    /// <summary>进度回调（可选）</summary>
    public IProgress<ProgressReport>? Progress { get; set; }

    // ═══════════════════════════════════════════════════════
    //  Pack
    // ═══════════════════════════════════════════════════════

    public async Task<PackResult> PackAsync(PackOptions opts, CancellationToken token = default)
    {
        try
        {
            var prefix = opts.OutputPrefix;
            var capacity = 1L * 1024 * 1024 * opts.VolumeSizeMb;
            var (mode, cek) = opts.Credentials;
            var headerSize = mode is EncryptionMode.None ? FileEntryHeader.HeaderSize : FileEntryHeader.EncryptedHeaderSize;
            var (items, volumes) = VolumeAllocator.Allocate(
                opts.SourceFiles,
                opts.SourceFolder,
                capacity,
                headerSize,
                opts.IntegrityLevel,
                opts.EnableCompression);
            if (items.Count == 0)
                return new PackResult { Error = "无工作项" };

            var compressing = mode != EncryptionMode.None && opts.EnableCompression;
            Report("分配", 0, items.Count,
                $"共 {volumes.Count} 卷, 加密={(mode != EncryptionMode.None ? "是" : "否")}, 压缩={(compressing ? $"是 (L{opts.CompressionLevel})" : "否")}, 完整性={opts.IntegrityLevel}");

            var encryptHeaders = mode != EncryptionMode.None;
            var pipe = new SequentialPipeline(
                mode is EncryptionMode.None
                    ? new NullTransform(opts.EnableCompression, opts.CompressionLevel)
                    : new PackTransform(cek, opts.EnableCompression, opts.CompressionLevel, opts.IntegrityLevel))
            {
                ReadBlockAsync = (item, ct) => FileSource.ReadAsync(item, ct),
                WriteVolumeAsync = async (ctx, ct) =>
                {
                    Report("写入", ctx.VolumeIndex, volumes.Count, ctx.OutputPath);
                    await CvpSink.WriteAsync(ctx, encryptHeaders ? cek : null, ct);
                }
            };

            var volPaths = new List<string>();
            foreach (var (idx, _) in volumes)
            {
                var vp = Path.Combine(opts.OutputDir.FullName, $"{prefix}.{idx}.cvp");
                volPaths.Add(vp);
                pipe.AddVolume(idx, vp, 0);
            }

            await pipe.RunAsync(items, token);

            return new PackResult
            {
                Success = true,
                VolumePaths = volPaths,
                VolumeCount = volumes.Count,
                TotalBytes = opts.SourceFiles.Sum(f => f.Length)
            };
        }
        catch (Exception ex)
        {
            return new PackResult { Error = ex.Message };
        }
    }

    // ═══════════════════════════════════════════════════════
    //  Extract
    // ═══════════════════════════════════════════════════════

    public async Task<ExtractResult> ExtractAsync(ExtractOptions opts, CancellationToken token = default)
    {
        try
        {
            var (mode, cek) = opts.Credentials;
            var filter = BuildGlobMatcher(opts.IncludePattern, opts.ExcludePattern);
            var scanResult = VolumeScanner.Scan(opts.VolumeFiles, cek, filter.IsActive ? filter : null);
            if (scanResult.PossiblyEncrypted)
                return new ExtractResult { Error = "卷已加密但未提供密钥文件，请使用 --key-file 指定 .cvk 文件" };

            var fileFragments = scanResult.Files;
            var incompleteFiles = FindIncompleteFiles(fileFragments);
            if (incompleteFiles.Count > 0)
            {
                Report("不完整文件已跳过", incompleteFiles.Count, incompleteFiles.Count,
                    string.Join(", ", incompleteFiles));
                foreach (var skipped in incompleteFiles)
                    fileFragments.Remove(skipped);
            }

            if (fileFragments.Count == 0)
                return new ExtractResult { Error = "未发现文件" };

            var fileIndex = new Dictionary<string, int>();
            var fi = 0;
            foreach (var p in fileFragments.Keys) fileIndex[p] = fi++;

            var items = new List<WorkItem>();
            foreach (var (relPath, fragments) in fileFragments)
            {
                long seq = 0;
                foreach (var f in fragments)
                    items.Add(new WorkItem
                    {
                        RelativePath = relPath,
                        SourceFullPath = f.CvpFile.FullName,
                        VolumeIndex = fileIndex[relPath],
                        Sequence = seq++,
                        SourceOffset = f.CvpOffset,
                        Length = f.BlockSize,
                        TotalFileSize = f.TotalFileSize,
                        Flags = f.Flags,
                        IsFirstFragment = f.IsFirst
                    });
            }

            var integrityLevel = IntegrityLevel.None;
            var isCompressed = false;
            if (fileFragments.Count > 0)
            {
                var firstFragment = fileFragments.Values.First(f => f.Count > 0);
                integrityLevel = (IntegrityLevel)(firstFragment[0].Flags >> 3 & 3);
                isCompressed = (firstFragment[0].Flags & 0x20) != 0;
            }

            Report("提取", 0, fileFragments.Count,
                $"解密={(mode != EncryptionMode.None ? "是" : "否")}, 解压={isCompressed}, 完整性={integrityLevel}");

            var pipe = new SequentialPipeline(mode is EncryptionMode.None
                ? NullTransform.ForExtract(isCompressed)
                : new ExtractTransform(cek, isCompressed, integrityLevel))
            {
                ReadBlockAsync = (item, ct) => CvpSource.ReadAsync(item, ct),
                WriteVolumeAsync = (ctx, ct) =>
                {
                    Report("写入", 0, 0, ctx.OutputPath);
                    return FileSink.WriteAsync(opts.OutputDir.FullName, opts.Overwrite, ctx, ct);
                }
            };

            foreach (var kv in fileIndex)
            {
                var fp = Path.Combine(opts.OutputDir.FullName, kv.Key);
                var d = Path.GetDirectoryName(fp);
                if (d is not null) Directory.CreateDirectory(d);
                pipe.AddVolume(kv.Value, fp, 0);
            }

            if (!opts.OutputDir.Exists) opts.OutputDir.Create();
            await pipe.RunAsync(items, token);

            return new ExtractResult
            {
                Success = true,
                FileCount = fileFragments.Count,
                TotalBytes = fileFragments.Values.Sum(fs => fs.Sum(f => f.TotalFileSize))
            };
        }
        catch (Exception ex)
        {
            return new ExtractResult { Error = ex.Message };
        }
    }

    // ═══════════════════════════════════════════════════════
    //  Browse
    // ═══════════════════════════════════════════════════════

    public async Task<BrowseResult> BrowseAsync(BrowseOptions opts, CancellationToken token = default)
    {
        try
        {
            var (mode, cek) = opts.Credentials;
            var filter = BuildGlobMatcher(opts.IncludePattern, opts.ExcludePattern);
            var scanResult = VolumeScanner.Scan(opts.VolumeFiles, cek, filter.IsActive ? filter : null);
            if (scanResult.PossiblyEncrypted)
                return new BrowseResult { Error = "卷可能已加密但未提供密钥文件，请使用 --key-file 指定 .cvk 文件" };

            var fileFragments = scanResult.Files;
            var incompleteSet = new HashSet<string>(FindIncompleteFiles(fileFragments));
            var files = new List<BrowseFileEntry>();
            foreach (var (path, fragments) in fileFragments)
            {
                var entry = new BrowseFileEntry
                {
                    Path = path,
                    Size = fragments[0].TotalFileSize,
                    FragmentCount = fragments.Count,
                    Volumes = fragments.Select(f =>
                    {
                        var name = Path.GetFileNameWithoutExtension(f.CvpFile.Name);
                        var parts = name.Split('.');
                        return parts.Length > 1 && int.TryParse(parts[^1], out var n) ? n : 0;
                    }).Distinct().OrderBy(n => n).ToList(),
                    IsComplete = !incompleteSet.Contains(path)
                };
                files.Add(entry);
            }

            return new BrowseResult
            {
                Success = true,
                Files = files,
                VolumeCount = opts.VolumeFiles.Count
            };
        }
        catch (Exception ex)
        {
            return new BrowseResult { Error = ex.Message };
        }
    }

    // ═══════════════════════════════════════════════════════
    //  Convert (块级密钥轮换 — cek/newCek 由 CLI 预加载)
    // ═══════════════════════════════════════════════════════

    public async Task<ConvertResult> ConvertAsync(ConvertOptions opts, CancellationToken token = default)
    {
        try
        {
            var (mode, cek) = opts.OldCredentials;
            var scanResult = VolumeScanner.Scan(opts.VolumeFiles, cek);
            if (scanResult.PossiblyEncrypted)
                return new ConvertResult { Error = "卷可能已加密但未提供密钥文件，请使用 --key-file 指定 .cvk 文件" };

            var fileFragments = scanResult.Files;
            var items = new List<WorkItem>();
            var volMap = new Dictionary<int, int>();
            var newVolIdx = 0;

            foreach (var (relPath, fragments) in fileFragments)
            foreach (var f in fragments)
            {
                var oldVol = Path.GetFileNameWithoutExtension(f.CvpFile.Name).Split('.').Last();
                if (!int.TryParse(oldVol, out var ov)) ov = 0;
                if (!volMap.TryGetValue(ov, out var nv)) volMap[ov] = nv = newVolIdx++;
                items.Add(new WorkItem
                {
                    RelativePath = relPath,
                    SourceFullPath = f.CvpFile.FullName,
                    VolumeIndex = nv,
                    Sequence = items.Count(i => i.VolumeIndex == nv),
                    SourceOffset = f.CvpOffset,
                    Length = f.BlockSize,
                    TotalFileSize = f.TotalFileSize,
                    Flags = f.Flags,
                    IsFirstFragment = f.IsFirst
                });
            }

            if (items.Count == 0)
                return new ConvertResult { Error = "无数据块" };

            var integrityLevel = IntegrityLevel.None;
            var isCompressed = false;
            if (fileFragments.Count > 0)
            {
                var firstFragment = fileFragments.Values.First(f => f.Count > 0);
                integrityLevel = (IntegrityLevel)(firstFragment[0].Flags >> 3 & 3);
                isCompressed = (firstFragment[0].Flags & 0x20) != 0;
            }

            var (newMode, newCek) = opts.NewCredentials;
            var pipe = new SequentialPipeline(newMode is EncryptionMode.None
                ? new ExtractTransform(cek, isCompressed, integrityLevel)
                : new ConvertTransform(cek, newCek, integrityLevel))
            {
                ReadBlockAsync = (item, ct) => CvpSource.ReadAsync(item, ct),
                WriteVolumeAsync = (ctx, ct) =>
                    CvpSink.WriteAsync(ctx, newMode is EncryptionMode.None ? null : newCek, ct)
            };

            for (var i = 0; i < newVolIdx; i++)
                pipe.AddVolume(i, Path.Combine(opts.OutputDir.FullName, $"{opts.OutputPrefix}.{i}.cvp"), 0);
            await pipe.RunAsync(items, token);

            var volPaths = Enumerable.Range(0, newVolIdx)
                .Select(i => Path.Combine(opts.OutputDir.FullName, $"{opts.OutputPrefix}.{i}.cvp")).ToList();
            return new ConvertResult
            {
                Success = true,
                VolumePaths = volPaths,
                VolumeCount = newVolIdx
            };
        }
        catch (Exception ex)
        {
            return new ConvertResult { Error = ex.Message };
        }
    }

    // ═══════════════════════════════════════════════════════
    //  Verify
    // ═══════════════════════════════════════════════════════

    public async Task<VerifyResult> VerifyAsync(VerifyOptions opts, CancellationToken token = default)
    {
        try
        {
            var (mode, cek) = opts.Credentials;
            var filter = BuildGlobMatcher(opts.IncludePattern, opts.ExcludePattern);
            var scanResult = VolumeScanner.Scan(opts.VolumeFiles, cek, filter.IsActive ? filter : null);
            if (scanResult.PossiblyEncrypted)
                return new VerifyResult { Error = "卷可能已加密但未提供密钥文件，请使用 --key-file 指定 .cvk 文件" };

            var fileFragments = scanResult.Files;
            if (fileFragments.Count == 0)
                return new VerifyResult { Error = "未发现可识别的文件条目" };

            var totalBlocks = 0;
            var corruptedBlocks = 0;
            var corruptedFiles = 0;
            var corruptedEntries = new List<CorruptedBlock>();

            foreach (var (path, fragments) in fileFragments)
            {
                token.ThrowIfCancellationRequested();
                var fileCorrupted = false;

                foreach (var f in fragments)
                {
                    totalBlocks++;
                    var integrityLevel = (IntegrityLevel)(f.Flags >> 3 & 3);

                    if (integrityLevel < IntegrityLevel.Block || opts.Quick)
                        continue;

                    try
                    {
                        using var fs = File.OpenRead(f.CvpFile.FullName);
                        var blockBuf = new byte[f.BlockSize];
                        fs.Position = f.CvpOffset;
                        var read = fs.Read(blockBuf.AsSpan());
                        if (read < f.BlockSize) goto corrupted;

                        var dataLen = f.BlockSize - 4;
                        var expectedCrc = BitConverter.ToUInt32(blockBuf, dataLen);
                        var actualCrc = Crc32.Compute(blockBuf.AsSpan(0, dataLen));

                        if (expectedCrc == actualCrc) continue;
                    }
                    catch { }

                    corrupted:
                    corruptedBlocks++;
                    corruptedEntries.Add(new CorruptedBlock
                    {
                        FilePath = path,
                        CvpOffset = f.CvpOffset,
                        BlockSize = f.BlockSize
                    });

                    if (!fileCorrupted)
                    {
                        fileCorrupted = true;
                        corruptedFiles++;
                    }
                }
            }

            return new VerifyResult
            {
                Success = true,
                TotalFiles = fileFragments.Count,
                TotalBlocks = totalBlocks,
                CorruptedFiles = corruptedFiles,
                CorruptedBlocks = corruptedBlocks,
                CorruptedEntries = corruptedEntries
            };
        }
        catch (Exception ex)
        {
            return new VerifyResult { Error = ex.Message };
        }
    }

    // ═══════════════════════════════════════════════════════
    //  Repair
    // ═══════════════════════════════════════════════════════

    public async Task<RepairResult> RepairAsync(RepairOptions opts, CancellationToken token = default)
    {
        try
        {
            var (mode, cek) = opts.Credentials;
            var scanResult = VolumeScanner.Scan(opts.VolumeFiles, cek);
            if (scanResult.PossiblyEncrypted)
                return new RepairResult { Error = "卷可能已加密但未提供密钥文件，请使用 --key-file 指定 .cvk 文件" };

            var fileFragments = scanResult.Files;
            if (fileFragments.Count == 0)
                return new RepairResult { Error = "未发现可识别的文件条目" };

            var corrupted = new List<(FileInfo Cvp, long Offset, int Size)>();

            if (opts.VerifyReport is not null)
            {
                var lines = await File.ReadAllLinesAsync(opts.VerifyReport.FullName, token);
                foreach (var line in lines)
                {
                    var parts = line.Split('\t');
                    if (parts.Length >= 2 &&
                        long.TryParse(parts[1], out var off) &&
                        int.TryParse(parts.Length >= 3 ? parts[2] : "0", out var sz))
                    {
                        var cvp = fileFragments.Values
                            .SelectMany(f => f)
                            .FirstOrDefault(f => f.CvpOffset == off)?.CvpFile;
                        if (cvp is not null)
                            corrupted.Add((cvp, off, sz));
                    }
                }
            }
            else
            {
                var allFragments = fileFragments.SelectMany(kv => kv.Value.Select(f => (kv.Key, f))).ToList();
                foreach (var (_, f) in allFragments)
                {
                    token.ThrowIfCancellationRequested();
                    var il = (IntegrityLevel)(f.Flags >> 3 & 3);
                    if (il < IntegrityLevel.Block) continue;

                    try
                    {
                        using var fs = File.OpenRead(f.CvpFile.FullName);
                        var buf = new byte[f.BlockSize];
                        fs.Position = f.CvpOffset;
                        if (fs.Read(buf.AsSpan()) < f.BlockSize) goto corrupted;

                        var dataLen = f.BlockSize - 4;
                        var expected = BitConverter.ToUInt32(buf, dataLen);
                        var actual = Crc32.Compute(buf.AsSpan(0, dataLen));
                        if (expected == actual) continue;
                    }
                    catch { }

                    corrupted:
                    corrupted.Add((f.CvpFile, f.CvpOffset, f.BlockSize));
                }
            }

            if (corrupted.Count == 0)
                return new RepairResult { Success = true, TotalBlocks = 0, RepairedBlocks = 0 };

            var byCvp = corrupted.GroupBy(c => c.Cvp.FullName).ToList();
            var repairedVolumes = new List<string>();

            foreach (var group in byCvp)
            {
                var srcPath = group.Key;
                var dstPath = opts.OutputDir is not null
                    ? Path.Combine(opts.OutputDir.FullName, Path.GetFileName(srcPath))
                    : srcPath;

                if (opts.Backup && File.Exists(srcPath))
                    File.Copy(srcPath, srcPath + ".bak", true);

                if (dstPath != srcPath)
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(dstPath)!);
                    File.Copy(srcPath, dstPath, true);
                }

                await using var fs = new FileStream(dstPath, FileMode.Open, FileAccess.ReadWrite);
                foreach (var (_, offset, size) in group)
                {
                    var zeros = new byte[size];
                    fs.Position = offset;
                    await fs.WriteAsync(zeros, token);

                    var crc = Crc32.Compute(zeros.AsSpan(0, size - 4));
                    var crcBytes = BitConverter.GetBytes(crc);
                    fs.Position = offset + size - 4;
                    await fs.WriteAsync(crcBytes, token);
                }

                repairedVolumes.Add(dstPath);
            }

            return new RepairResult
            {
                Success = true,
                TotalBlocks = corrupted.Count,
                RepairedBlocks = corrupted.Count,
                RepairedVolumes = repairedVolumes
            };
        }
        catch (Exception ex)
        {
            return new RepairResult { Error = ex.Message };
        }
    }

    // ═══════════════════════════════════════════════════════
    //  Helpers
    // ═══════════════════════════════════════════════════════

    private void Report(string phase, int completed, int total, string? detail)
    {
        Progress?.Report(new ProgressReport
        {
            Phase = phase,
            Completed = completed,
            Total = total,
            Detail = detail
        });
    }

    internal static List<string> FindIncompleteFiles(Dictionary<string, List<VolumeScanner.Fragment>> fileFragments)
    {
        var incomplete = new List<string>();
        foreach (var (path, fragments) in fileFragments)
        {
            if (fragments.Count == 0) continue;

            if (fragments.Count == 1)
            {
                var type = (FileEntryHeaderFlagsEnum)(fragments[0].Flags & 3);
                if (type != FileEntryHeaderFlagsEnum.Full)
                    incomplete.Add(path);
                continue;
            }

            var hasCrossHead = fragments.Any(f => f.IsFirst &&
                                                  (FileEntryHeaderFlagsEnum)(f.Flags & 3) is FileEntryHeaderFlagsEnum.Full
                                                  or FileEntryHeaderFlagsEnum.CrossHead);
            var hasCrossTail = fragments.Any(f => !f.IsFirst &&
                                                  (FileEntryHeaderFlagsEnum)(f.Flags & 3) is FileEntryHeaderFlagsEnum.Full
                                                  or FileEntryHeaderFlagsEnum.CrossTail);
            if (!hasCrossHead || !hasCrossTail)
                incomplete.Add(path);
        }

        return incomplete;
    }

    private static GlobMatcher BuildGlobMatcher(string? include, string? exclude)
    {
        var m = new GlobMatcher();
        if (!string.IsNullOrWhiteSpace(include)) m.AddInclude(include);
        if (!string.IsNullOrWhiteSpace(exclude)) m.AddExclude(exclude);
        return m;
    }
}

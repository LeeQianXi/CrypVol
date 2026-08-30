using CrypVol.Lib.Engine;
using CrypVol.Lib.Engine.Models;
using CrypVol.Lib.Engine.Processors;
using CrypVol.Lib.Engine.Providers;
using CrypVol.Lib.Engine.Receivers;
using CrypVol.Lib.Helper.Models;
using CrypVol.Lib.Utility;
using CrypVol.Lib.Volume;
using Microsoft.Extensions.Logging;

namespace CrypVol.Lib.Helper;

/// <summary>
///     CrypVol 核心引擎。提供 Pack / Extract / Convert 等操作的统一入口。
///     每个阶段单线程顺序处理。
/// </summary>
public sealed class CrypVolHelper
{
    /// <summary>结构化日志（可选）</summary>
    public ILogger? Logger { get; init; }

    // ═══════════════════════════════════════════════════════
    //  Pack
    // ═══════════════════════════════════════════════════════

    public async Task<PackResult> PackAsync(PackOptions opts, CancellationToken token = default)
    {
        try
        {
            var prefix = opts.OutputPrefix;
            if (opts.SourceFiles.Count == 0)
                return new PackResult { Error = "无工作项" };

            if (opts.ChunkSizeMb is < 1 or > 64)
                return new PackResult { Error = "块大小必须在 1–64 MiB 之间" };

            var capacity = checked((long)opts.VolumeSizeMb * 1024 * 1024);
            var (mode, cek) = opts.Credentials;
            var headerSize = mode is EncryptionMode.None ? FileEntryHeader.HeaderSize : FileEntryHeader.EncryptedHeaderSize;
            var maxChunkSize = capacity - headerSize - sizeof(int);
            if (maxChunkSize <= 0)
                return new PackResult { Error = "卷容量不足以容纳文件头和数据块长度字段" };
            var chunkSize = (int)Math.Min(checked((long)opts.ChunkSizeMb * 1024 * 1024), maxChunkSize);

            var compressing = mode != EncryptionMode.None && opts.EnableCompression;
            Logger?.LogInformation(
                "Pack 开始: 流式块大小 {ChunkSize} 字节, {FileCount} 文件, {TotalBytes} 字节, 加密={Encrypted}, 压缩={Compressed}",
                chunkSize, opts.SourceFiles.Count, opts.SourceFiles.Sum(f => f.Length),
                mode != EncryptionMode.None ? "是" : "否",
                compressing ? $"是 (L{opts.CompressionLevel})" : "否");

            var encryptHeaders = mode != EncryptionMode.None;

            var receiver = new CvpFileReciver(encryptHeaders ? cek : null, opts.OutputDir.FullName, prefix);
            var provider = new SourceFileDataProvider(opts.SourceFiles, opts.SourceFolder, chunkSize, capacity,
                headerSize, opts.IntegrityLevel, opts.EnableCompression);
            var builder = ProcessingEngine.Builder().UseProvider(provider);
            if (opts.EnableCompression) builder.AddProcessor(new CompressionProcessor(opts.CompressionLevel));
            if (mode is not EncryptionMode.None) builder.AddProcessor(new EncryptionProcessor(cek, opts.IntegrityLevel));
            var pipeline = builder.UseReceiver(receiver).WithLogger(Logger).Build();
            await pipeline.StartAsync(token);

            var totalBytes = opts.SourceFiles.Sum(f => f.Length);
            var volumePaths = receiver.VolumePaths;
            Logger?.LogInformation("Pack 完成: {VolumeCount} 卷, {TotalBytes} 字节", volumePaths.Count, totalBytes);
            return new PackResult
            {
                Success = true,
                VolumePaths = volumePaths,
                VolumeCount = volumePaths.Count,
                TotalBytes = totalBytes
            };
        }
        catch (Exception ex)
        {
            Logger?.LogError(ex, "Pack 失败");
            return new PackResult
            {
                Error = ex.Message
            };
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

            var scanResult = VolumeScanner.Scan(opts.VolumeFiles, cek, filter.IsActive ? filter : null, Logger);
            Logger?.LogInformation("卷扫描完成: {FileCount} 文件, {VolumeCount} 卷, 加密={Encrypted}",
                scanResult.Files.Count, opts.VolumeFiles.Count,
                scanResult.PossiblyEncrypted ? "是" : "否");

            if (scanResult.PossiblyEncrypted)
                return new ExtractResult
                {
                    Error = "卷已加密但未提供密钥文件，请使用 --key-file 指定 .cvk 文件"
                };

            var fileFragments = scanResult.Files;
            var incompleteFiles = FindIncompleteFiles(fileFragments);
            if (incompleteFiles.Count > 0)
            {
                Logger?.LogWarning("跳过 {Count} 个不完整文件", incompleteFiles.Count);
                foreach (var skipped in incompleteFiles)
                    fileFragments.Remove(skipped);
            }

            if (fileFragments.Count == 0)
                return new ExtractResult
                {
                    Error = "未发现文件"
                };

            var fileIndex = new Dictionary<string, int>();
            var fi = 0;
            foreach (var p in fileFragments.Keys) fileIndex[p] = fi++;

            var items = new List<BlockMetadata>();
            foreach (var (relPath, fragments) in fileFragments)
            {
                long seq = 0;
                foreach (var f in fragments)
                    items.Add(new BlockMetadata
                    {
                        RelativePath = relPath,
                        SourceFullPath = f.CvpFile.FullName,
                        TargetIndex = fileIndex[relPath],
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

            Logger?.LogInformation("提取开始: {FileCount} 文件, {ItemCount} 块, 解密={Decrypt}, 解压={Decompress}",
                fileFragments.Count, items.Count,
                mode != EncryptionMode.None ? "是" : "否", isCompressed);

            var receiver = new DataFileReciver(opts.OutputDir.FullName, opts.Overwrite);

            foreach (var kv in fileIndex)
            {
                var fp = Path.Combine(opts.OutputDir.FullName, kv.Key);
                var d = Path.GetDirectoryName(fp);
                if (d is not null) Directory.CreateDirectory(d);
                receiver.AddTarget(kv.Value, fp);
            }

            if (!opts.OutputDir.Exists) opts.OutputDir.Create();
            var builder = ProcessingEngine.Builder().UseProvider(new CvpFileDataProvider(items));
            if (mode is not EncryptionMode.None) builder.AddProcessor(new DecryptionProcessor(cek, integrityLevel));
            if (isCompressed) builder.AddProcessor(new DecompressionProcessor());
            var pipeline = builder.UseReceiver(receiver).WithLogger(Logger).Build();
            await pipeline.StartAsync(token);

            Logger?.LogInformation("提取完成: {FileCount} 文件", fileFragments.Count);
            return new ExtractResult
            {
                Success = true,
                FileCount = fileFragments.Count,
                TotalBytes = fileFragments.Values.Sum(fs => fs.Sum(f => f.TotalFileSize))
            };
        }
        catch (Exception ex)
        {
            Logger?.LogError(ex, "提取失败");
            return new ExtractResult
            {
                Error = ex.Message
            };
        }
    }

    // ═══════════════════════════════════════════════════════
    //  Browse
    // ═══════════════════════════════════════════════════════

    public async Task<BrowseResult> BrowseAsync(BrowseOptions opts, CancellationToken token = default)
    {
        try
        {
            var (_, cek) = opts.Credentials;
            var filter = BuildGlobMatcher(opts.IncludePattern, opts.ExcludePattern);

            var scanResult = VolumeScanner.Scan(opts.VolumeFiles, cek, filter.IsActive ? filter : null, Logger);
            Logger?.LogInformation("卷扫描完成: {FileCount} 文件, {VolumeCount} 卷, 加密={Encrypted}",
                scanResult.Files.Count, opts.VolumeFiles.Count,
                scanResult.PossiblyEncrypted ? "是" : "否");

            if (scanResult.PossiblyEncrypted)
                return new BrowseResult
                {
                    Error = "卷可能已加密但未提供密钥文件，请使用 --key-file 指定 .cvk 文件"
                };

            var fileFragments = scanResult.Files;
            var incompleteSet = new HashSet<string>(FindIncompleteFiles(fileFragments));
            Logger?.LogInformation("浏览开始: {VolumeCount} 卷, {FileCount} 文件, {IncompleteCount} 不完整",
                opts.VolumeFiles.Count, fileFragments.Count, incompleteSet.Count);

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

            Logger?.LogInformation("浏览完成: {FileCount} 文件", files.Count);
            return new BrowseResult
            {
                Success = true,
                Files = files,
                VolumeCount = opts.VolumeFiles.Count
            };
        }
        catch (Exception ex)
        {
            Logger?.LogError(ex, "浏览失败");
            return new BrowseResult
            {
                Error = ex.Message
            };
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
            var scanResult = VolumeScanner.Scan(opts.VolumeFiles, cek, logger: Logger);
            if (scanResult.PossiblyEncrypted)
                return new ConvertResult
                {
                    Error = "卷可能已加密但未提供密钥文件，请使用 --key-file 指定 .cvk 文件"
                };

            var fileFragments = scanResult.Files;
            var items = new List<BlockMetadata>();
            var volMap = new Dictionary<int, int>();
            var newVolIdx = 0;

            foreach (var (relPath, fragments) in fileFragments)
            foreach (var f in fragments)
            {
                var oldVol = Path.GetFileNameWithoutExtension(f.CvpFile.Name).Split('.').Last();
                if (!int.TryParse(oldVol, out var ov)) ov = 0;
                if (!volMap.TryGetValue(ov, out var nv)) volMap[ov] = nv = newVolIdx++;
                items.Add(new BlockMetadata
                {
                    RelativePath = relPath,
                    SourceFullPath = f.CvpFile.FullName,
                    TargetIndex = nv,
                    Sequence = items.Count(i => i.TargetIndex == nv),
                    SourceOffset = f.CvpOffset,
                    Length = f.BlockSize,
                    TotalFileSize = f.TotalFileSize,
                    Flags = f.Flags,
                    IsFirstFragment = f.IsFirst
                });
            }

            if (items.Count == 0)
                return new ConvertResult
                {
                    Error = "无数据块"
                };

            var integrityLevel = IntegrityLevel.None;
            if (fileFragments.Count > 0)
            {
                var firstFragment = fileFragments.Values.First(f => f.Count > 0);
                integrityLevel = (IntegrityLevel)(firstFragment[0].Flags >> 3 & 3);
            }

            var (newMode, newCek) = opts.NewCredentials;
            Logger?.LogInformation("密钥轮换开始: {ItemCount} 块, {VolCount} 卷", items.Count, newVolIdx);

            var receiver = new CvpFileReciver(newMode is EncryptionMode.None ? null : newCek);

            for (var i = 0; i < newVolIdx; i++)
                receiver.AddTarget(i, Path.Combine(opts.OutputDir.FullName, $"{opts.OutputPrefix}.{i}.cvp"));

            var builder = ProcessingEngine.Builder()
                .UseProvider(new CvpFileDataProvider(items));
            if (mode is not EncryptionMode.None) builder.AddProcessor(new DecryptionProcessor(cek, integrityLevel));
            if (newMode is not EncryptionMode.None) builder.AddProcessor(new EncryptionProcessor(newCek, integrityLevel));
            var pipeline = builder.UseReceiver(receiver).WithLogger(Logger).Build();
            await pipeline.StartAsync(token);

            var volPaths = Enumerable.Range(0, newVolIdx)
                .Select(i => Path.Combine(opts.OutputDir.FullName, $"{opts.OutputPrefix}.{i}.cvp")).ToList();
            Logger?.LogInformation("密钥轮换完成: {VolCount} 卷", newVolIdx);
            return new ConvertResult
            {
                Success = true,
                VolumePaths = volPaths,
                VolumeCount = newVolIdx
            };
        }
        catch (Exception ex)
        {
            Logger?.LogError(ex, "密钥轮换失败");
            return new ConvertResult
            {
                Error = ex.Message
            };
        }
    }

    // ═══════════════════════════════════════════════════════
    //  Verify
    // ═══════════════════════════════════════════════════════

    public async Task<VerifyResult> VerifyAsync(VerifyOptions opts, CancellationToken token = default)
    {
        try
        {
            var (_, cek) = opts.Credentials;
            var filter = BuildGlobMatcher(opts.IncludePattern, opts.ExcludePattern);

            var scanResult = VolumeScanner.Scan(opts.VolumeFiles, cek, filter.IsActive ? filter : null, Logger);
            Logger?.LogInformation("卷扫描完成: {FileCount} 文件, {VolumeCount} 卷",
                scanResult.Files.Count, opts.VolumeFiles.Count);

            if (scanResult.PossiblyEncrypted)
                return new VerifyResult
                {
                    Error = "卷可能已加密但未提供密钥文件，请使用 --key-file 指定 .cvk 文件"
                };

            var fileFragments = scanResult.Files;
            if (fileFragments.Count == 0)
                return new VerifyResult
                {
                    Error = "未发现可识别的文件条目"
                };

            var totalBlocks = 0;
            var corruptedBlocks = 0;
            var corruptedFiles = 0;
            var corruptedEntries = new List<CorruptedBlock>();

            Logger?.LogInformation("校验开始: {FileCount} 文件, Quick={Quick}", fileFragments.Count, opts.Quick);

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
                        await using var fs = File.OpenRead(f.CvpFile.FullName);
                        var blockBuf = new byte[f.BlockSize];
                        fs.Position = f.CvpOffset;
                        var read = fs.Read(blockBuf.AsSpan());
                        if (read < f.BlockSize) goto corrupted;

                        var dataLen = f.BlockSize - 4;
                        var expectedCrc = BitConverter.ToUInt32(blockBuf, dataLen);
                        var actualCrc = Crc32.Compute(blockBuf.AsSpan(0, dataLen));

                        if (expectedCrc == actualCrc) continue;
                    }
                    catch
                    {
                        // ignored
                    }

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

            Logger?.LogInformation("校验完成: 总计{TotalBlocks}块, 损坏{CorruptedBlocks}块({CorruptedFiles}文件)",
                totalBlocks, corruptedBlocks, corruptedFiles);
            if (corruptedBlocks > 0)
                Logger?.LogWarning("校验发现 {CorruptedBlocks} 个损坏块在 {CorruptedFiles} 个文件中",
                    corruptedBlocks, corruptedFiles);

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
            Logger?.LogError(ex, "校验失败");
            return new VerifyResult
            {
                Error = ex.Message
            };
        }
    }

    // ═══════════════════════════════════════════════════════
    //  Repair
    // ═══════════════════════════════════════════════════════

    public async Task<RepairResult> RepairAsync(RepairOptions opts, CancellationToken token = default)
    {
        try
        {
            var (_, cek) = opts.Credentials;
            var scanResult = VolumeScanner.Scan(opts.VolumeFiles, cek, logger: Logger);
            if (scanResult.PossiblyEncrypted)
                return new RepairResult
                {
                    Error = "卷可能已加密但未提供密钥文件，请使用 --key-file 指定 .cvk 文件"
                };

            var fileFragments = scanResult.Files;
            Logger?.LogInformation("修复开始: {FileCount} 文件, 报告={HasReport}",
                fileFragments.Count, opts.VerifyReport is not null ? "是" : "扫描检测");

            if (fileFragments.Count == 0)
                return new RepairResult
                {
                    Error = "未发现可识别的文件条目"
                };

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
                        await using var fs = File.OpenRead(f.CvpFile.FullName);
                        var buf = new byte[f.BlockSize];
                        fs.Position = f.CvpOffset;
                        if (fs.Read(buf.AsSpan()) < f.BlockSize) goto corrupted1;

                        var dataLen = f.BlockSize - 4;
                        var expected = BitConverter.ToUInt32(buf, dataLen);
                        var actual = Crc32.Compute(buf.AsSpan(0, dataLen));
                        if (expected == actual) continue;
                    }
                    catch
                    {
                        // ignored
                    }

                    corrupted1:
                    corrupted.Add((f.CvpFile, f.CvpOffset, f.BlockSize));
                }
            }

            if (corrupted.Count == 0)
                return new RepairResult
                {
                    Success = true,
                    TotalBlocks = 0,
                    RepairedBlocks = 0
                };

            Logger?.LogWarning("修复 {Count} 个损坏块", corrupted.Count);
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

            Logger?.LogInformation("修复完成: {Count} 块, {VolCount} 卷", corrupted.Count, repairedVolumes.Count);
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
            Logger?.LogError(ex, "修复失败");
            return new RepairResult
            {
                Error = ex.Message
            };
        }
    }

    // ═══════════════════════════════════════════════════════
    //  Helpers
    // ═══════════════════════════════════════════════════════

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

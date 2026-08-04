using System.Text.RegularExpressions;
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
            // Allocate (encrypted headers = 284B, plain = 256B)
            var headerSize = mode is EncryptionMode.None ? FileEntryHeader.HeaderSize : FileEntryHeader.EncryptedHeaderSize;
            var (items, volumes) = VolumeAllocator.Allocate(
                opts.SourceFiles,
                opts.SourceFolder,
                capacity,
                headerSize,
                opts.IntegrityLevel);
            if (items.Count == 0)
                return new PackResult
                {
                    Error = "无工作项"
                };
            Report("分配", 0, items.Count, $"共 {volumes.Count} 卷");
            // Pipeline
            var encryptHeaders = mode != EncryptionMode.None;
            var threads = Math.Clamp(opts.Threads, 1, Environment.ProcessorCount);
            var pipe = new VolumePipeline(new PipelineConfig
            {
                ReaderConcurrency = Math.Min(items.Count, 6),
                TransformConcurrency = threads,
                RawChannelCapacity = 128,
                ProcessedChannelCapacity = 128
            }, mode is EncryptionMode.None
                ? new NullTransform()
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

            var totalBytes = opts.SourceFiles.Sum(f => f.Length);
            return new PackResult
            {
                Success = true,
                VolumePaths = volPaths,
                VolumeCount = volumes.Count,
                TotalBytes = totalBytes
            };
        }
        catch (Exception ex)
        {
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
            var scanResult = VolumeScanner.Scan(opts.VolumeFiles, cek);
            if (scanResult.PossiblyEncrypted)
                return new ExtractResult
                {
                    Error = "卷已加密但未提供密钥文件，请使用 --key-file 指定 .cvk 文件"
                };
            var fileFragments = scanResult.Files;
            var incompleteFiles = FindIncompleteFiles(fileFragments);
            if (incompleteFiles.Count > 0)
            {
                Report("不完整文件已跳过", incompleteFiles.Count, incompleteFiles.Count,
                    string.Join(", ", incompleteFiles));
                foreach (var skipped in incompleteFiles)
                    fileFragments.Remove(skipped);
            }

            // Filter by --include / --exclude
            if (!string.IsNullOrWhiteSpace(opts.IncludePattern) || !string.IsNullOrWhiteSpace(opts.ExcludePattern))
            {
                var keys = fileFragments.Keys.ToList();
                foreach (var k in keys)
                {
                    if (!string.IsNullOrWhiteSpace(opts.IncludePattern) &&
                        !SimpleGlobMatch(opts.IncludePattern, k))
                    {
                        fileFragments.Remove(k);
                        continue;
                    }

                    if (!string.IsNullOrWhiteSpace(opts.ExcludePattern) &&
                        SimpleGlobMatch(opts.ExcludePattern, k)) fileFragments.Remove(k);
                }
            }

            if (fileFragments.Count == 0)
                return new ExtractResult
                {
                    Error = "未发现文件"
                };
            // Map files to volume indices
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

            // Auto-detect integrity level from the first fragment's flags
            var integrityLevel = IntegrityLevel.None;
            if (fileFragments.Count > 0)
            {
                var firstFragment = fileFragments.Values.First(f => f.Count > 0);
                integrityLevel = (IntegrityLevel)(firstFragment[0].Flags >> 3 & 3);
            }

            Report("提取", 0, fileFragments.Count, "");

            var threads = Math.Clamp(opts.Threads, 1, Environment.ProcessorCount);
            var pipe = new VolumePipeline(new PipelineConfig
            {
                ReaderConcurrency = Math.Min(items.Count, 6),
                TransformConcurrency = threads,
                RawChannelCapacity = 128,
                ProcessedChannelCapacity = 128
            }, mode is EncryptionMode.None
                ? new NullTransform()
                : new ExtractTransform(cek, false, integrityLevel))
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
            var (mode, cek) = opts.Credentials;
            var scanResult = VolumeScanner.Scan(opts.VolumeFiles, cek);
            if (scanResult.PossiblyEncrypted)
                return new BrowseResult
                {
                    Error = "卷可能已加密但未提供密钥文件，请使用 --key-file 指定 .cvk 文件"
                };
            var fileFragments = scanResult.Files;

            // 过滤 include/exclude
            if (!string.IsNullOrWhiteSpace(opts.IncludePattern) || !string.IsNullOrWhiteSpace(opts.ExcludePattern))
            {
                var keys = fileFragments.Keys.ToList();
                foreach (var k in keys)
                {
                    if (!string.IsNullOrWhiteSpace(opts.IncludePattern) &&
                        !SimpleGlobMatch(opts.IncludePattern, k))
                    {
                        fileFragments.Remove(k);
                        continue;
                    }

                    if (!string.IsNullOrWhiteSpace(opts.ExcludePattern) &&
                        SimpleGlobMatch(opts.ExcludePattern, k))
                        fileFragments.Remove(k);
                }
            }

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
            var scanResult = VolumeScanner.Scan(opts.VolumeFiles, cek);
            if (scanResult.PossiblyEncrypted)
                return new ConvertResult
                {
                    Error = "卷可能已加密但未提供密钥文件，请使用 --key-file 指定 .cvk 文件"
                };
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
                return new ConvertResult
                {
                    Error = "无数据块"
                };

            // Auto-detect integrity level from the first fragment's flags
            var integrityLevel = IntegrityLevel.None;
            if (fileFragments.Count > 0)
            {
                var firstFragment = fileFragments.Values.First(f => f.Count > 0);
                integrityLevel = (IntegrityLevel)(firstFragment[0].Flags >> 3 & 3);
            }

            var (newMode, newCek) = opts.NewCredentials;
            var t = Math.Clamp(opts.Threads, 1, Environment.ProcessorCount);
            var pipe = new VolumePipeline(new PipelineConfig
                {
                    ReaderConcurrency = Math.Min(items.Count, 6),
                    TransformConcurrency = t,
                    RawChannelCapacity = 128,
                    ProcessedChannelCapacity = 128
                }, newMode is EncryptionMode.None
                    ? new ExtractTransform(cek, false, integrityLevel) // 解密不加密
                    : new ConvertTransform(cek, newCek, integrityLevel)) // 解密+加密
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
            var (mode, cek) = opts.Credentials;
            var scanResult = VolumeScanner.Scan(opts.VolumeFiles, cek);
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

            // Filter by --include / --exclude
            if (!string.IsNullOrWhiteSpace(opts.IncludePattern) || !string.IsNullOrWhiteSpace(opts.ExcludePattern))
            {
                var keys = fileFragments.Keys.ToList();
                foreach (var k in keys)
                {
                    if (!string.IsNullOrWhiteSpace(opts.IncludePattern) &&
                        !SimpleGlobMatch(opts.IncludePattern, k))
                    {
                        fileFragments.Remove(k);
                        continue;
                    }

                    if (!string.IsNullOrWhiteSpace(opts.ExcludePattern) &&
                        SimpleGlobMatch(opts.ExcludePattern, k))
                        fileFragments.Remove(k);
                }
            }

            if (fileFragments.Count == 0)
                return new VerifyResult
                {
                    TotalFiles = 0,
                    TotalBlocks = 0
                };

            var totalBlocks = 0;
            var corruptedBlocks = 0;
            var corruptedFiles = 0;
            var corruptedEntries = new List<CorruptedBlock>();
            var threads = Math.Clamp(opts.Threads, 1, Environment.ProcessorCount);
            var ioLimit = Math.Min(threads, opts.VolumeFiles.Count * 2);
            var semaphore = new SemaphoreSlim(ioLimit, ioLimit);
            var parallelOpts = new ParallelOptions
            {
                MaxDegreeOfParallelism = threads,
                CancellationToken = token
            };

            await Parallel.ForEachAsync(fileFragments, parallelOpts, async (kv, ct) =>
            {
                var (path, fragments) = kv;
                var fileCorrupted = false;

                foreach (var f in fragments)
                {
                    Interlocked.Increment(ref totalBlocks);
                    var integrityLevel = (IntegrityLevel)(f.Flags >> 3 & 3);

                    if (integrityLevel < IntegrityLevel.Block || opts.Quick)
                        continue;

                    try
                    {
                        await semaphore.WaitAsync(ct);
                        try
                        {
                            await using var fs = File.OpenRead(f.CvpFile.FullName);
                            var blockBuf = new byte[f.BlockSize];
                            fs.Position = f.CvpOffset;
                            var read = await fs.ReadAsync(blockBuf, ct);
                            if (read < f.BlockSize) goto corrupted;

                            var dataLen = f.BlockSize - 4;
                            var expectedCrc = BitConverter.ToUInt32(blockBuf, dataLen);
                            var actualCrc = Crc32.Compute(blockBuf.AsSpan(0, dataLen));

                            if (expectedCrc == actualCrc) continue;
                        }
                        finally { semaphore.Release(); }
                    }
                    catch { }

                    corrupted:
                    Interlocked.Increment(ref corruptedBlocks);
                    lock (corruptedEntries)
                    {
                        corruptedEntries.Add(new CorruptedBlock
                        {
                            FilePath = path,
                            CvpOffset = f.CvpOffset,
                            BlockSize = f.BlockSize
                        });
                    }

                    if (!fileCorrupted)
                    {
                        fileCorrupted = true;
                        Interlocked.Increment(ref corruptedFiles);
                    }
                }
            });

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
            var (mode, cek) = opts.Credentials;
            var scanResult = VolumeScanner.Scan(opts.VolumeFiles, cek);
            if (scanResult.PossiblyEncrypted)
                return new RepairResult
                {
                    Error = "卷可能已加密但未提供密钥文件，请使用 --key-file 指定 .cvk 文件"
                };
            var fileFragments = scanResult.Files;
            if (fileFragments.Count == 0)
                return new RepairResult
                {
                    Error = "未发现可识别的文件条目"
                };

            // Collect corrupted blocks: either from report or by scanning
            var corrupted = new List<(FileInfo Cvp, long Offset, int Size)>();

            if (opts.VerifyReport is not null)
            {
                // Read from verify report: each line is "path\toffset\tsize"
                var lines = await File.ReadAllLinesAsync(opts.VerifyReport.FullName, token);
                foreach (var line in lines)
                {
                    var parts = line.Split('\t');
                    if (parts.Length >= 2 &&
                        long.TryParse(parts[1], out var off) &&
                        int.TryParse(parts.Length >= 3 ? parts[2] : "0", out var sz))
                    {
                        // Find the CVP file for this fragment
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
                // Parallel scan to find corrupted blocks
                var threads = Math.Clamp(opts.Threads, 1, Environment.ProcessorCount);
                var ioLimit = Math.Min(threads, opts.VolumeFiles.Count * 2);
                var semaphore = new SemaphoreSlim(ioLimit, ioLimit);
                var parallelOpts = new ParallelOptions
                {
                    MaxDegreeOfParallelism = threads,
                    CancellationToken = token
                };
                var sync = new object();

                var allFragments = fileFragments.SelectMany(kv => kv.Value.Select(f => (kv.Key, f))).ToList();

                await Parallel.ForEachAsync(allFragments, parallelOpts, async (item, ct) =>
                {
                    var (_, f) = item;
                    var il = (IntegrityLevel)(f.Flags >> 3 & 3);
                    if (il < IntegrityLevel.Block) return;

                    try
                    {
                        await semaphore.WaitAsync(ct);
                        try
                        {
                            await using var fs = File.OpenRead(f.CvpFile.FullName);
                            var buf = new byte[f.BlockSize];
                            fs.Position = f.CvpOffset;
                            if (await fs.ReadAsync(buf, ct) < f.BlockSize) goto corrupted;

                            var dataLen = f.BlockSize - 4;
                            var expected = BitConverter.ToUInt32(buf, dataLen);
                            var actual = Crc32.Compute(buf.AsSpan(0, dataLen));
                            if (expected == actual) return;
                        }
                        finally { semaphore.Release(); }
                    }
                    catch { }

                    corrupted:
                    lock (sync)
                    {
                        corrupted.Add((f.CvpFile, f.CvpOffset, f.BlockSize));
                    }
                });
            }

            if (corrupted.Count == 0)
                return new RepairResult
                {
                    Success = true,
                    TotalBlocks = 0,
                    RepairedBlocks = 0
                };

            // Group by CVP file
            var byCvp = corrupted.GroupBy(c => c.Cvp.FullName).ToList();
            var repairedVolumes = new List<string>();

            foreach (var group in byCvp)
            {
                var srcPath = group.Key;
                var dstPath = opts.OutputDir is not null
                    ? Path.Combine(opts.OutputDir.FullName, Path.GetFileName(srcPath))
                    : srcPath;

                // Backup
                if (opts.Backup && File.Exists(srcPath))
                    File.Copy(srcPath, srcPath + ".bak", true);

                // Copy to output if different, then repair in-place
                if (dstPath != srcPath)
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(dstPath)!);
                    File.Copy(srcPath, dstPath, true);
                }

                // Repair: zero-fill corrupted blocks, set valid CRC32
                await using var fs = new FileStream(dstPath, FileMode.Open, FileAccess.ReadWrite);
                foreach (var (_, offset, size) in group)
                {
                    var zeros = new byte[size];
                    fs.Position = offset;
                    await fs.WriteAsync(zeros, token);

                    // Set valid CRC32 for the zero-filled block
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
            return new RepairResult
            {
                Error = ex.Message
            };
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

    private static bool SimpleGlobMatch(string pattern, string path)
    {
        if (pattern == "**" || pattern == "**/*") return true;
        var regex = "^" + Regex.Escape(pattern)
            .Replace("\\*\\*", ".*")
            .Replace("\\*", "[^/]*") + "$";
        return Regex.IsMatch(path, regex);
    }

    /// <summary>
    ///     校验每个文件的片段完整性（块大小总和是否等于 TotalFileSize、首尾类型正确）。
    ///     返回不完整的文件路径列表；空列表表示所有文件完整。
    /// </summary>
    private static List<string> FindIncompleteFiles(Dictionary<string, List<VolumeScanner.Fragment>> fileFragments)
    {
        var incomplete = new List<string>();
        foreach (var (path, fragments) in fileFragments)
        {
            if (fragments.Count == 0) continue;

            var totalSize = fragments[0].TotalFileSize;
            var sumBlockSize = fragments.Sum(f => (long)f.BlockSize);

            // 核心检查：所有数据块大小之和必须 >= 文件总大小
            if (sumBlockSize < totalSize)
            {
                incomplete.Add(path);
                continue;
            }

            // 单片段：必须为 Full
            if (fragments.Count == 1)
            {
                var type = (FileEntryHeaderFlagsEnum)(fragments[0].Flags & 3);
                if (type != FileEntryHeaderFlagsEnum.Full)
                    incomplete.Add(path);
                continue;
            }

            // 多片段：检查首尾 fragment 类型链
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
}
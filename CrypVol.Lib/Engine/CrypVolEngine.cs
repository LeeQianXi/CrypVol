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
                headerSize);
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
                : new PackTransform(cek, opts.EnableCompression, opts.CompressionLevel))
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
            var fileFragments = VolumeScanner.Scan(opts.VolumeFiles, mode, cek);
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

            Report("提取", 0, fileFragments.Count, "");

            var threads = Math.Clamp(opts.Threads, 1, Environment.ProcessorCount);
            var pipe = new VolumePipeline(new PipelineConfig
            {
                ReaderConcurrency = Math.Min(items.Count, 6),
                TransformConcurrency = threads,
                RawChannelCapacity = 128,
                ProcessedChannelCapacity = 128
            }, mode is EncryptionMode.None ? new NullTransform() : new ExtractTransform(cek, false))
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
            var fileFragments = VolumeScanner.Scan(opts.VolumeFiles, mode, cek);
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
                    }).Distinct().OrderBy(n => n).ToList()
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
            var fileFragments = VolumeScanner.Scan(opts.VolumeFiles, mode, cek);
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

            var (newMode, newCek) = opts.NewCredentials;
            var t = Math.Clamp(opts.Threads, 1, Environment.ProcessorCount);
            var pipe = new VolumePipeline(new PipelineConfig
                {
                    ReaderConcurrency = Math.Min(items.Count, 6),
                    TransformConcurrency = t,
                    RawChannelCapacity = 128,
                    ProcessedChannelCapacity = 128
                }, newMode is EncryptionMode.None
                    ? new ExtractTransform(cek, false) // 解密不加密
                    : new ConvertTransform(cek, newCek)) // 解密+加密
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
}
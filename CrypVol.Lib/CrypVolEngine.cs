using System.Security.Cryptography;
using CrypVol.Lib.Models;
using CrypVol.Lib.Pipeline;
using CrypVol.Lib.Sinks;
using CrypVol.Lib.Sources;
using CrypVol.Lib.Transforms;

namespace CrypVol.Lib;

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

    public async Task<PackResult> PackAsync(PackOptions opts, IReadOnlyList<FileInfo> files,
        string sourceDir, CancellationToken token = default)
    {
        try
        {
            if (files.Count == 0)
                return new PackResult
                {
                    Error = "无可处理文件"
                };

            var prefix = string.IsNullOrWhiteSpace(opts.OutputPrefix)
                ? new DirectoryInfo(sourceDir).Name
                : opts.OutputPrefix;

            if (!Directory.Exists(opts.OutputDir)) Directory.CreateDirectory(opts.OutputDir);

            var capacity = 1L * 1024 * 1024 * opts.VolumeSizeMb;

            // Key
            byte[] cek, salt;
            EncryptionMode mode;
            string? keyPath = null;

            if (opts.KeyFilePath is not null)
            {
                RSA? privKey = null;
                if (opts.PrivateKeyPath is not null)
                {
                    privKey = RSA.Create();
                    privKey.ImportFromPem(File.ReadAllText(opts.PrivateKeyPath));
                }

                (cek, salt, _) = KeyEnvelope.LoadEnvelope(opts.KeyFilePath, opts.KeyFilePassword, privKey);
                privKey?.Dispose();
                mode = EncryptionMode.PlainKey;
                keyPath = Path.Combine(opts.OutputDir, $"{prefix}.cvk");
                File.Copy(opts.KeyFilePath, keyPath, true);
            }
            else
            {
                cek = RandomNumberGenerator.GetBytes(32);
                salt = RandomNumberGenerator.GetBytes(32);
                mode = opts.EncryptionMode;
                if (mode == EncryptionMode.Password && string.IsNullOrWhiteSpace(opts.Password))
                    return new PackResult
                    {
                        Error = "密码模式需要 Password"
                    };

                var pubKeys = opts.PublicKeyPaths?.Select(p => new FileInfo(p));
                keyPath = mode != EncryptionMode.None ? Path.Combine(opts.OutputDir, $"{prefix}.cvk") : null;
                await CvkGenerator.CreateAsync(opts.OutputDir, prefix, mode, cek, salt,
                    opts.Password, pubKeys, token);
            }

            // Allocate
            var (items, volumes) = VolumeAllocator.Allocate(files, sourceDir, capacity);
            if (items.Count == 0)
                return new PackResult
                {
                    Error = "无工作项"
                };

            Report("分配", 0, items.Count, $"共 {volumes.Count} 卷");

            // Pipeline
            var threads = Math.Clamp(opts.Threads, 1, Environment.ProcessorCount);
            var pipe = new VolumePipeline(new PipelineConfig
            {
                ReaderConcurrency = Math.Min(items.Count, 6),
                TransformConcurrency = threads,
                RawChannelCapacity = 128,
                ProcessedChannelCapacity = 128
            }, mode == EncryptionMode.None
                ? new NullTransform()
                : new PackTransform(cek, opts.EnableCompression, opts.CompressionLevel))
            {
                ReadBlockAsync = (item, ct) => FileSource.ReadAsync(item, ct),
                WriteVolumeAsync = async (ctx, ct) =>
                {
                    Report("写入", ctx.VolumeIndex, volumes.Count, ctx.OutputPath);
                    await CvpSink.WriteAsync(ctx, ct);
                }
            };

            var volPaths = new List<string>();
            foreach (var (idx, _) in volumes)
            {
                var vp = Path.Combine(opts.OutputDir, $"{prefix}.{idx}.cvp");
                volPaths.Add(vp);
                pipe.AddVolume(idx, vp, 0);
            }

            await pipe.RunAsync(items, token);

            var totalBytes = files.Sum(f => f.Length);
            return new PackResult
            {
                Success = true,
                VolumePaths = volPaths,
                KeyFilePath = keyPath,
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
            var inputs = new List<FileSystemInfo>();
            foreach (var p in opts.VolumePaths)
                inputs.Add(Directory.Exists(p) ? new DirectoryInfo(p) : new FileInfo(p));

            var allVolumes = VolumeDiscovery.Discover(inputs);
            if (allVolumes.Count == 0)
                return new ExtractResult
                {
                    Error = "未找到 .cvp 文件"
                };

            var cvkPath = opts.KeyFilePath is not null
                ? new FileInfo(opts.KeyFilePath)
                : CvkLocator.Find(allVolumes[0]);
            byte[]? cek = null;
            var encrypted = cvkPath is not null;

            if (encrypted)
            {
                var (ok, key, err) = CvkLocator.LoadCek(cvkPath!, opts.Password,
                    opts.PrivateKeyPath is not null ? new FileInfo(opts.PrivateKeyPath) : null);
                if (!ok)
                    return new ExtractResult
                    {
                        Error = err
                    };
                cek = key;
            }

            var fileFragments = VolumeScanner.Scan(allVolumes);
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
                        SourceFullPath = f.CvpPath,
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
            }, encrypted ? new ExtractTransform(cek!, false) : new NullTransform())
            {
                ReadBlockAsync = (item, ct) => CvpSource.ReadAsync(item, ct),
                WriteVolumeAsync = (ctx, ct) =>
                {
                    Report("写入", 0, 0, ctx.OutputPath);
                    return FileSink.WriteAsync(opts.OutputDir, opts.Overwrite, ctx, ct);
                }
            };

            foreach (var kv in fileIndex)
            {
                var fp = Path.Combine(opts.OutputDir, kv.Key);
                var d = Path.GetDirectoryName(fp);
                if (d is not null) Directory.CreateDirectory(d);
                pipe.AddVolume(kv.Value, fp, 0);
            }

            if (!Directory.Exists(opts.OutputDir)) Directory.CreateDirectory(opts.OutputDir);
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
    //  Rekey
    // ═══════════════════════════════════════════════════════

    public async Task<RekeyResult> RekeyAsync(RekeyOptions opts, CancellationToken token = default)
    {
        try
        {
            if (!File.Exists(opts.SourceCvkPath))
                return new RekeyResult
                {
                    Error = "源 .cvk 不存在"
                };

            // Load old CEK
            RSA? privKey = null;
            try
            {
                if (opts.SourcePrivateKeyPath is not null)
                {
                    privKey = RSA.Create();
                    privKey.ImportFromPem(await File.ReadAllTextAsync(opts.SourcePrivateKeyPath, token));
                }

                var (cek, salt, _) = KeyEnvelope.LoadEnvelope(opts.SourceCvkPath,
                    opts.SourcePassword, privKey);

                // Backup
                if (opts.Backup)
                    File.Copy(opts.SourceCvkPath, opts.SourceCvkPath + ".bak", true);

                // Rewrap
                var output = opts.OutputPath ?? opts.SourceCvkPath;
                var mode = opts.TargetMode switch
                {
                    EncryptionMode.PlainKey => EnvelopeMode.Plain,
                    EncryptionMode.Password => EnvelopeMode.Password,
                    EncryptionMode.Asymmetric => EnvelopeMode.PublicKey,
                    _ => throw new Exception($"无效模式: {opts.TargetMode}")
                };

                Dictionary<string, RSA>? recipients = null;
                if (opts.PublicKeyPaths is { Count: > 0 })
                {
                    recipients = new Dictionary<string, RSA>();
                    foreach (var p in opts.PublicKeyPaths)
                    {
                        var rsa = RSA.Create();
                        rsa.ImportFromPem(File.ReadAllText(p));
                        recipients[Path.GetFileNameWithoutExtension(p)] = rsa;
                    }
                }

                KeyEnvelope.SaveEnvelope(output, mode, cek, salt, opts.NewPassword, recipients);
                if (recipients is not null)
                    foreach (var r in recipients.Values)
                        r.Dispose();

                return new RekeyResult
                {
                    Success = true,
                    OutputPath = output
                };
            }
            finally { privKey?.Dispose(); }
        }
        catch (Exception ex)
        {
            return new RekeyResult
            {
                Error = ex.Message
            };
        }
    }

    // ═══════════════════════════════════════════════════════
    //  Browse
    // ═══════════════════════════════════════════════════════

    public async Task<BrowseResult> BrowseAsync(IReadOnlyList<string> volumePaths,
        string? keyFilePath = null, string? password = null, CancellationToken token = default)
    {
        try
        {
            var inputs = new List<FileSystemInfo>();
            foreach (var p in volumePaths)
                inputs.Add(Directory.Exists(p) ? new DirectoryInfo(p) : new FileInfo(p));

            var allVolumes = VolumeDiscovery.Discover(inputs);
            if (allVolumes.Count == 0)
                return new BrowseResult
                {
                    Error = "未找到 .cvp 文件"
                };

            var fileFragments = VolumeScanner.Scan(allVolumes);
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
                        var name = Path.GetFileNameWithoutExtension(f.CvpPath);
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
                VolumeCount = allVolumes.Count
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
    //  Convert (块级密钥轮换)
    // ═══════════════════════════════════════════════════════

    public async Task<PackResult> ConvertAsync(IReadOnlyList<string> volumePaths,
        string outputDir, string outputPrefix,
        string? oldKeyPath, string? oldPassword,
        string? newKeyPath, EncryptionMode newMode,
        string? newPassword, IReadOnlyList<string>? newPubKeyPaths,
        int threads, CancellationToken token = default)
    {
        try
        {
            var inputs = new List<FileSystemInfo>();
            foreach (var p in volumePaths)
                inputs.Add(Directory.Exists(p) ? new DirectoryInfo(p) : new FileInfo(p));

            var allVolumes = VolumeDiscovery.Discover(inputs);
            if (allVolumes.Count == 0)
                return new PackResult
                {
                    Error = "未找到 .cvp 文件"
                };

            // Old CEK
            var oldCvkPath = oldKeyPath is not null ? new FileInfo(oldKeyPath) : CvkLocator.Find(allVolumes[0]);
            if (oldCvkPath is null)
                return new PackResult
                {
                    Error = "未找到源 .cvk"
                };

            var (ok, oldCek, err) = CvkLocator.LoadCek(oldCvkPath, oldPassword);
            if (!ok)
                return new PackResult
                {
                    Error = err
                };

            // New CEK
            byte[] newCek;
            if (newKeyPath is not null)
            {
                var (c, _, _) = KeyEnvelope.LoadEnvelope(newKeyPath, newPassword);
                newCek = c;
            }
            else
            {
                newCek = RandomNumberGenerator.GetBytes(32);
                var salt = RandomNumberGenerator.GetBytes(32);
                var pubKeys = newPubKeyPaths?.Select(p => new FileInfo(p));
                await CvkGenerator.CreateAsync(outputDir, outputPrefix, newMode, newCek, salt,
                    newPassword, pubKeys, token);
            }

            // Scan + build items (preserve original file→volume mapping)
            var fileFragments = VolumeScanner.Scan(allVolumes);
            var items = new List<WorkItem>();
            var volMap = new Dictionary<int, int>();
            var newVolIdx = 0;

            foreach (var (relPath, fragments) in fileFragments)
            foreach (var f in fragments)
            {
                var oldVol = Path.GetFileNameWithoutExtension(f.CvpPath).Split('.').Last();
                if (!int.TryParse(oldVol, out var ov)) ov = 0;
                if (!volMap.TryGetValue(ov, out var nv))
                    volMap[ov] = nv = newVolIdx++;

                items.Add(new WorkItem
                {
                    RelativePath = relPath,
                    SourceFullPath = f.CvpPath,
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
                return new PackResult
                {
                    Error = "无数据块"
                };

            threads = Math.Clamp(threads, 1, Environment.ProcessorCount);
            var pipe = new VolumePipeline(new PipelineConfig
            {
                ReaderConcurrency = Math.Min(items.Count, 6),
                TransformConcurrency = threads,
                RawChannelCapacity = 128,
                ProcessedChannelCapacity = 128
            }, new ConvertTransform(oldCek!, newCek))
            {
                ReadBlockAsync = (item, ct) => CvpSource.ReadAsync(item, ct),
                WriteVolumeAsync = (ctx, ct) => CvpSink.WriteAsync(ctx, ct)
            };

            var volPaths = new List<string>();
            for (var i = 0; i < newVolIdx; i++)
            {
                var vp = Path.Combine(outputDir, $"{outputPrefix}.{i}.cvp");
                volPaths.Add(vp);
                pipe.AddVolume(i, vp, 0);
            }

            await pipe.RunAsync(items, token);
            return new PackResult
            {
                Success = true,
                VolumePaths = volPaths,
                VolumeCount = newVolIdx
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
}
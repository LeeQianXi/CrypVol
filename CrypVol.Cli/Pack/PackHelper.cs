using System.Buffers;
using System.CommandLine;
using System.Security.Cryptography;
using CrypVol.Cli.Pipeline;
using CrypVol.Lib;
using Microsoft.Extensions.FileSystemGlobbing;
using Microsoft.Extensions.FileSystemGlobbing.Abstractions;

namespace CrypVol.Cli.Pack;

public static partial class PackHelper
{
    // ═══════════════════════════════════════════════════════
    //  Invoker — 参数解析 + 管线编排
    // ═══════════════════════════════════════════════════════

    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        var verbose = args.GetValue(CommandDefinition.Verbose);

        // 1. 解析源路径
        var inputPath = args.GetRequiredValue(CommandDefinition.Pack.InputPath);
        if (!inputPath.Exists)
        {
            Console.WriteLine(inputPath is FileInfo
                ? $"文件 \"{inputPath.Name}\" 不存在"
                : $"目录 \"{inputPath.Name}\" 不存在");
            return 1;
        }

        // 2. 收集文件列表
        var config = new PackConfig();

        if (inputPath is DirectoryInfo di)
        {
            var filter = new Matcher();
            var include = args.GetValue(CommandDefinition.Pack.Include);
            filter.AddInclude(string.IsNullOrWhiteSpace(include) ? "**/*" : include);
            var exclude = args.GetValue(CommandDefinition.Pack.Exclude);
            if (!string.IsNullOrWhiteSpace(exclude)) filter.AddExclude(exclude);
            var result = filter.Execute(new DirectoryInfoWrapper(di));
            if (!result.HasMatches)
            {
                Console.WriteLine($"目录 \"{di.Name}\" 没有可处理的文件");
                return 1;
            }

            config.SourceDir = di.FullName;
            config.Files = result.Files.Select(f => new FileInfo(Path.Combine(di.FullName, f.Path)));
        }
        else
        {
            var fi = (FileInfo)inputPath;
            config.SourceDir = fi.Directory!.FullName;
            config.Files = new[] { fi };
        }

        // 3. 输出目录
        var outputPath = args.GetRequiredValue(CommandDefinition.Pack.OutputPath);
        if (!outputPath.Exists) outputPath.Create();
        config.OutputDir = outputPath.FullName;

        var prefix = args.GetValue(CommandDefinition.Pack.OutputPrefix);
        if (string.IsNullOrWhiteSpace(prefix))
        {
            Console.WriteLine("无效的卷前缀");
            return 1;
        }

        config.OutputPrefix = prefix;

        // 4. 卷大小
        var volumeSizeMb = args.GetValue(CommandDefinition.Pack.VolumeSize);
        config.VolumeDataCapacity = 1L * 1024 * 1024 * volumeSizeMb;

        // 5. 密钥来源：二选一
        var keyFile = args.GetValue(CommandDefinition.Pack.KeyFile);
        if (keyFile is not null)
        {
            // 模式 A: 复用已有 .cvk 的 CEK
            var (cek, salt, _) = KeyEnvelope.LoadEnvelope(keyFile.FullName);
            config.Cek = cek;
            config.Salt = salt;
            config.Mode = EncryptionMode.PlainKey; // CEK 已就绪，无需额外保护
            // 复制 .cvk 到输出目录
            config.KeyOutputDir = args.GetValue(CommandDefinition.Pack.KeyOutputPath)!.FullName;
            var destCvk = Path.Combine(config.KeyOutputDir, $"{prefix}.cvk");
            File.Copy(keyFile.FullName, destCvk, overwrite: true);
        }
        else
        {
            // 模式 B: 生成新 CEK + .cvk
            config.Cek = RandomNumberGenerator.GetBytes(32);
            config.Salt = RandomNumberGenerator.GetBytes(32);
            config.Mode = args.GetValue(CommandDefinition.Pack.Mode);

            switch (config.Mode)
            {
                case EncryptionMode.Password:
                    var pwd = args.GetValue(CommandDefinition.Pack.Password);
                    if (string.IsNullOrWhiteSpace(pwd)) { Console.WriteLine("密码模式需要提供 --password"); return 1; }
                    config.Password = pwd;
                    break;
                case EncryptionMode.Asymmetric:
                    config.PublicKey = args.GetValue(CommandDefinition.Pack.PublicKey) ?? [];
                    break;
            }

            config.KeyOutputDir = args.GetValue(CommandDefinition.Pack.KeyOutputPath)!.FullName;
            await CreateCvkAsync(config, token);
        }

        // 6. 并行度和压缩
        var threads = args.GetValue(CommandDefinition.Pack.Threads);
        config.ComputeThreads = Math.Clamp(threads, 1, Environment.ProcessorCount);
        config.EnableCompression = args.GetValue(CommandDefinition.Pack.Compress);
        config.CompressionLevel = args.GetValue(CommandDefinition.Pack.CompressionLevel);

        // 7. 构建 WorkItem 列表 + 分配卷
        var (items, volumeInfos) = AllocateVolumes(config);

        if (items.Count == 0)
        {
            Console.WriteLine("没有可处理的文件");
            return 0;
        }

        Console.WriteLine($"预计生成 {volumeInfos.Count} 个数据卷");

        // 8. 创建流水线
        var pipelineConfig = new PipelineConfig
        {
            ReaderConcurrency = Math.Min(items.Count, 6),
            TransformConcurrency = config.ComputeThreads,
            WriterConcurrency = 2,
            BlockSize = 4096,
            LogInfo = verbose ? Console.WriteLine : null,
            LogVerbose = verbose ? Console.WriteLine : null
        };

        var transform = new PackTransform(config.Cek, config.EnableCompression, config.CompressionLevel);

        var pipeline = new Pipeline.Pipeline(pipelineConfig, transform)
        {
            ReadBlockAsync = (item, ct) => ReadFromFileAsync(config.SourceDir, item, ct),
            WriteVolumeAsync = (ctx, ct) => WriteToCvpAsync(ctx, ct)
        };

        // 注册卷
        foreach (var vi in volumeInfos)
        {
            var path = Path.Combine(config.OutputDir, $"{config.OutputPrefix}.{vi.Index}.cvp");
            pipeline.AddVolume(vi.Index, path, vi.Size);
        }

        // 启动
        await pipeline.RunAsync(items, token);
        Console.WriteLine($"打包完成：{volumeInfos.Count} 个卷 → {config.OutputDir}");
        return 0;
    }

    // ═══════════════════════════════════════════════════════
    //  文件 → WorkItem 分配
    // ═══════════════════════════════════════════════════════

    private static (List<WorkItem> items, List<(int Index, long Size)> volumes) AllocateVolumes(PackConfig config)
    {
        const int headerSize = 256;
        const int maxPathLen = 231 + 256;
        const long alignment = 4096;

        var items = new List<WorkItem>();
        var volumeSizes = new Dictionary<int, long>();
        var perVolSeq = new Dictionary<int, long>(); // 每个卷独立的递增序号
        var pathOrigin = config.SourceDir;
        var capacity = config.VolumeDataCapacity;

        int currentVol = 0;
        long used = 0;

        long NextSeq(int vol)
        {
            perVolSeq.TryGetValue(vol, out var s);
            perVolSeq[vol] = s + 1;
            return s;
        }

        foreach (var file in config.Files)
        {
            var relPath = Path.GetRelativePath(pathOrigin, file.FullName);
            if (relPath.Length > maxPathLen)
            {
                Console.WriteLine($"路径过长，跳过：{relPath}");
                continue;
            }

            var totalSize = file.Length;
            if (totalSize == 0)
            {
                // 空文件只占一个 header
                if (used + headerSize > capacity) { currentVol++; used = 0; }
                items.Add(new WorkItem
                {
                    RelativePath = relPath,
                    SourceFullPath = file.FullName,
                    VolumeIndex = currentVol,
                    Sequence = NextSeq(currentVol),
                    SourceOffset = 0,
                    Length = 0,
                    TotalFileSize = 0,
                    Flags = 0,
                    IsFirstFragment = true
                });
                used += headerSize;
                volumeSizes[currentVol] = used;
                continue;
            }

            long remaining = totalSize;
            long srcOffset = 0;
            var fragmentIdx = 0;

            while (remaining > 0)
            {
                if (capacity - used < headerSize) { currentVol++; used = 0; }

                var dataSpace = capacity - used - headerSize;
                var maxBlocks = dataSpace / alignment;
                if (maxBlocks == 0) { currentVol++; used = 0; continue; }

                var rawToWrite = Math.Min(remaining, maxBlocks * alignment);
                var physicalLen = (rawToWrite + alignment - 1) / alignment * alignment;

                byte flags = fragmentIdx switch
                {
                    0 when rawToWrite == remaining => 0, // Full
                    0 => 1, // CrossHead
                    _ when rawToWrite == remaining => 3, // CrossTail
                    _ => 2 // CrossMid
                };
                if (relPath.Length > 231) flags |= 4; // HasExtendedHeader

                items.Add(new WorkItem
                {
                    RelativePath = relPath,
                    SourceFullPath = file.FullName,
                    VolumeIndex = currentVol,
                    Sequence = NextSeq(currentVol), // 卷内递增序号
                    SourceOffset = srcOffset,
                    Length = (int)rawToWrite,
                    TotalFileSize = totalSize,
                    Flags = flags,
                    IsFirstFragment = true // 每个段都需独立 header
                });

                remaining -= physicalLen;
                srcOffset += physicalLen;
                fragmentIdx++;
                used += headerSize + physicalLen;
                volumeSizes[currentVol] = used;

                if (used >= capacity) { currentVol++; used = 0; }
            }
        }

        var volumes = volumeSizes
            .OrderBy(kv => kv.Key)
            .Select(kv => (kv.Key, kv.Value))
            .ToList();

        return (items, volumes);
    }

    // ═══════════════════════════════════════════════════════
    //  Stage 1: 从文件系统读取
    // ═══════════════════════════════════════════════════════

    private static async Task<RawBlock?> ReadFromFileAsync(string sourceDir, WorkItem item, CancellationToken token)
    {
        if (item.Length == 0)
        {
            // 空文件：返回空数据块（仅用于触发头部写入）
            var empty = ArrayPool<byte>.Shared.Rent(0);
            return new RawBlock { Work = item, Data = empty, DataLength = 0 };
        }

        var array = ArrayPool<byte>.Shared.Rent(item.Length);
        try
        {
            await using var fs = File.OpenRead(item.SourceFullPath);
            fs.Position = item.SourceOffset;
            var read = await fs.ReadAsync(array.AsMemory(0, item.Length), token);
            return new RawBlock { Work = item, Data = array, DataLength = read };
        }
        catch
        {
            ArrayPool<byte>.Shared.Return(array);
            throw;
        }
    }

    // ═══════════════════════════════════════════════════════
    //  Stage 4: 写入 .cvp
    // ═══════════════════════════════════════════════════════

    private static async Task WriteToCvpAsync(VolumeContext ctx, CancellationToken token)
    {
        await using var fs = new FileStream(ctx.OutputPath, FileMode.Create, FileAccess.Write,
            FileShare.None, 4096 * 16, FileOptions.SequentialScan);

        // 不预分配大小（加密后块大小不可预知），依赖顺序追加写入
        long pos = 0;

        await foreach (var block in ctx.OutputChannel.Reader.ReadAllAsync(token))
        {
            // 每个片段都写 FileEntryHeader
            if (block.Work.IsFirstFragment)
            {
                var header = new FileEntryHeader
                {
                    FileId = FileEntry.Fnv1AHash64(block.Work.RelativePath),
                    Flags = block.Work.Flags,
                    FragmentIndex = (uint)block.Work.Sequence,
                    SizeOrTotal = block.Work.TotalFileSize
                };
                header.SetFilePath(block.Work.RelativePath);
                fs.Position = pos;
                await fs.WriteAsync(header.ToBytes(), token);
                pos += FileEntryHeader.HeaderSize;
            }

            // 4 字节块长度前缀 + 数据
            var lenBytes = BitConverter.GetBytes(block.OutputLength);
            fs.Position = pos;
            await fs.WriteAsync(lenBytes, token);
            await fs.WriteAsync(block.Data.AsMemory(0, block.OutputLength), token);
            pos += 4 + block.OutputLength;
            block.Dispose();
        }
    }
}

using System.CommandLine;
using CrypVol.Lib;
using CrypVol.Lib.Crypto;
using CrypVol.Lib.Helper;
using CrypVol.Lib.Helper.Models;
using CrypVol.Lib.Utility;
using CrypVol.Lib.Volume;
using Microsoft.Extensions.Logging;

namespace CrypVol.Cli.Pack;

public static class PackHelper
{
    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        var loggerFactory = Program.LoggerFactory;
        var logger = loggerFactory.CreateLogger(nameof(PackHelper));

        var inputPath = args.GetRequiredValue(CommandDefinition.Pack.InputPath);
        if (!inputPath.Exists)
        {
            logger.LogWarning("源路径不存在");
            return 1;
        }

        var outputDir = args.GetRequiredValue(CommandDefinition.Pack.OutputPath);

        var prefix = args.GetValue(CommandDefinition.Pack.OutputPrefix);
        if (string.IsNullOrWhiteSpace(prefix))
        {
            logger.LogWarning("无效前缀");
            return 1;
        }

        if (prefix.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || prefix.Contains(Path.DirectorySeparatorChar)
                                                                   || prefix.Contains(Path.AltDirectorySeparatorChar))
        {
            logger.LogWarning("输出前缀不能包含路径分隔符或非法文件名字符");
            return 1;
        }

        if (args.GetValue(CommandDefinition.Pack.VolumeSize) == 0)
        {
            logger.LogWarning("卷切分目标必须大于 0 MiB");
            return 1;
        }

        // Globbing — enumerate files, filter with DotNet.Glob
        var sourceFolder = inputPath switch
        {
            FileInfo fi => fi.Directory!,
            DirectoryInfo di => di,
            _ => throw new InvalidOperationException()
        };
        var matcher = new GlobMatcher();
        var inc = args.GetValue(CommandDefinition.Pack.Include);
        if (!string.IsNullOrWhiteSpace(inc)) matcher.AddInclude(inc);
        var exc = args.GetValue(CommandDefinition.Pack.Exclude);
        if (!string.IsNullOrWhiteSpace(exc)) matcher.AddExclude(exc);

        var allFiles = inputPath is FileInfo inputFile
            ? [inputFile.FullName]
            : Directory.GetFiles(sourceFolder.FullName, "*", SearchOption.AllDirectories);
        var files = new List<FileInfo>();
        foreach (var f in allFiles)
        {
            var rel = Path.GetRelativePath(sourceFolder.FullName, f);
            if (matcher.IsMatch(rel))
                files.Add(new FileInfo(f));
        }

        if (files.Count == 0)
        {
            logger.LogWarning("无可处理文件");
            return 1;
        }

        var chunkSizeMb = args.GetValue(CommandDefinition.Pack.ChunkSize);
        if (chunkSizeMb is < 1 or > 64)
        {
            logger.LogWarning("块大小必须在 1–64 MiB 之间");
            return 1;
        }

        // Dry-run: 仅估算，不调用引擎
        if (args.GetValue(CommandDefinition.Pack.DryRun))
        {
            var cap = 1L * 1024 * 1024 * args.GetValue(CommandDefinition.Pack.VolumeSize);
            var chunk = Math.Min(cap, (long)chunkSizeMb * 1024 * 1024);
            var blocks = files.Sum(file => Math.Max(1, (file.Length + chunk - 1) / chunk));
            var totalBytes = files.Sum(file => file.Length);
            var volumes = Math.Max(1, (totalBytes + cap - 1) / cap);
            Console.WriteLine($"流式近似预估: {volumes} 卷, {blocks} 块, {totalBytes} 字节");
            return 0;
        }

        // Pre-load/generate CEK
        CvkCredentials? creds;
        var mode = args.GetValue(CommandDefinition.Pack.Mode);
        var keyFile = args.GetValue(CommandDefinition.Pack.KeyFile);
        if (keyFile is not null)
        {
            try
            {
                var cvk = await CvkLoader.LoadAsync(keyFile,
                    args.GetValue(CommandDefinition.Pack.Password),
                    args.GetValue(CommandDefinition.Pack.PrivkeyKey),
                    args.GetValue(CommandDefinition.Pack.PrivkeyKeyPass), token);
                creds = cvk.ToCredentials();
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "无法加载密钥文件");
                return 1;
            }
        }
        else
        {
            var password = args.GetValue(CommandDefinition.Pack.Password);
            var publicKeys = args.GetValue(CommandDefinition.Pack.PublicKey)?.ToList() ?? [];
            if (mode == EncryptionMode.Password && string.IsNullOrWhiteSpace(password))
            {
                logger.LogWarning("Password 模式需要 --password");
                return 1;
            }

            if (mode == EncryptionMode.Asymmetric && publicKeys.Count == 0)
            {
                logger.LogWarning("Asymmetric 模式需要 --public-key");
                return 1;
            }

            try
            {
                outputDir.Create();
                var cvk = CvkDocument.CreateNew(mode);
                cvk.Password = password;
                cvk.Comment = args.GetValue(CommandDefinition.Pack.Comment);
                foreach (var publicKey in publicKeys) cvk.AddPublicKey(publicKey);
                var keyDirectory = args.GetValue(CommandDefinition.Pack.KeyOutputPath) ?? outputDir;
                keyDirectory.Create();
                await cvk.WriteAsync(new FileInfo(Path.Combine(keyDirectory.FullName, $"{prefix}.cvk")), token);
                creds = cvk.ToCredentials();
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "创建密钥文件失败");
                return 1;
            }
        }

        try
        {
            outputDir.Create();
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "无法创建输出目录");
            return 1;
        }

        var engine = new CrypVolHelper
        {
            Logger = loggerFactory.CreateLogger("CrypVol")
        };
        var result = await engine.PackAsync(new PackOptions
        {
            SourceFolder = sourceFolder,
            SourceFiles = files,
            OutputDir = outputDir,
            OutputPrefix = prefix,
            VolumeSizeMb = args.GetValue(CommandDefinition.Pack.VolumeSize),
            ChunkSizeMb = chunkSizeMb,
            EnableCompression = args.GetValue(CommandDefinition.Pack.Compress) &&
                                !args.GetValue(CommandDefinition.Pack.NoCompress),
            CompressionLevel = args.GetValue(CommandDefinition.Pack.CompressionLevel),
            IntegrityLevel = args.GetValue(CommandDefinition.Pack.Integrity),
            Credentials = creds
        }, token);

        if (!result.Success)
        {
            logger.LogError("打包失败: {ResultError}", result.Error);
            return 1;
        }

        logger.LogInformation("打包完成：{VolumeCount} 个卷 → {OutputDirectory}", result.VolumeCount,
            outputDir.FullName);
        return 0;
    }
}

using System.CommandLine;
using CrypVol.Lib.Crypto;
using CrypVol.Lib.Crypto.Models;
using CrypVol.Lib.Helper;
using CrypVol.Lib.Helper.Models;
using CrypVol.Lib.Utility;

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
            await Console.Error.WriteLineAsync("源路径不存在");
            return 1;
        }

        var outputDir = args.GetRequiredValue(CommandDefinition.Pack.OutputPath);
        var mode = args.GetValue(CommandDefinition.Pack.Mode);
        var algorithm = args.GetValue(CommandDefinition.Pack.Algorithm);
        if (algorithm is CvkKeyWrapAlgorithm.EcdhP256 or CvkKeyWrapAlgorithm.EcdhP384 or CvkKeyWrapAlgorithm.EcdhP521 &&
            mode != CvkKeyProtection.PublicKey)
        {
            await Console.Error.WriteLineAsync("--algorithm Ecc 仅可与 --mode Asymmetric 一起使用。");
            return 1;
        }

        var keyFile = args.GetValue(CommandDefinition.Pack.KeyFile);
        var publicKeys = args.GetValue(CommandDefinition.Pack.PublicKey)?.ToList() ?? [];

        if (keyFile is null && mode == CvkKeyProtection.PublicKey && publicKeys.Count == 0)
        {
            await Console.Error.WriteLineAsync("参数错误：公钥模式必须至少提供一个 --public-key；也可以改用 PlainKey 或 Password 模式。");
            return 1;
        }

        var prefix = args.GetValue(CommandDefinition.Pack.OutputPrefix);
        if (string.IsNullOrWhiteSpace(prefix))
        {
            await Console.Error.WriteLineAsync("无效前缀");
            return 1;
        }

        if (prefix.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || prefix.Contains(Path.DirectorySeparatorChar)
                                                                   || prefix.Contains(Path.AltDirectorySeparatorChar))
        {
            await Console.Error.WriteLineAsync("输出前缀不能包含路径分隔符或非法文件名字符");
            return 1;
        }

        if (args.GetValue(CommandDefinition.Pack.VolumeSize) == 0)
        {
            await Console.Error.WriteLineAsync("卷切分目标必须大于 0 MiB");
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
            await Console.Error.WriteLineAsync("无可处理文件");
            return 1;
        }

        var chunkSizeMb = args.GetValue(CommandDefinition.Pack.ChunkSize);
        if (chunkSizeMb is < 1 or > 64)
        {
            await Console.Error.WriteLineAsync("块大小必须在 1–64 MiB 之间");
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
        if (keyFile is not null)
        {
            try
            {
                var cvk = await CvkOperations.LoadAsync(keyFile,
                    args.GetValue(CommandDefinition.Pack.Password),
                    args.GetValue(CommandDefinition.Pack.PrivkeyKey),
                    args.GetValue(CommandDefinition.Pack.PrivkeyKeyPass), token, logger);
                creds = CvkOperations.ToCredentials(cvk);
            }
            catch (Exception ex)
            {
                await Console.Error.WriteLineAsync($"无法加载密钥文件: {ex.Message}");
                return 1;
            }
        }
        else
        {
            var password = args.GetValue(CommandDefinition.Pack.Password);
            if (mode == CvkKeyProtection.Password && string.IsNullOrWhiteSpace(password))
            {
                await Console.Error.WriteLineAsync("Password 模式需要 --password");
                return 1;
            }

            try
            {
                outputDir.Create();
                var cvk = CvkOperations.CreateNew(mode, algorithm);
                cvk.Comment = args.GetValue(CommandDefinition.Pack.Comment);
                foreach (var publicKey in publicKeys) CvkOperations.AddPublicKey(cvk, publicKey);
                var keyDirectory = args.GetValue(CommandDefinition.Pack.KeyOutputPath) ?? outputDir;
                keyDirectory.Create();
                await CvkOperations.WriteAsync(cvk, new FileInfo(Path.Combine(keyDirectory.FullName, $"{prefix}.cvk")),
                    password, token);
                creds = CvkOperations.ToCredentials(cvk);
            }
            catch (Exception ex)
            {
                await Console.Error.WriteLineAsync($"创建密钥文件失败: {ex.Message}");
                return 1;
            }
        }

        try
        {
            outputDir.Create();
        }
        catch (Exception ex)
        {
            await Console.Error.WriteLineAsync($"无法创建输出目录: {ex.Message}");
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
            EnableCompression = !args.GetValue(CommandDefinition.Pack.NoCompress),
            CompressionLevel = args.GetValue(CommandDefinition.Pack.CompressionLevel),
            IntegrityLevel = args.GetValue(CommandDefinition.Pack.Integrity),
            Credentials = creds
        }, token);

        if (!result.Success)
        {
            await Console.Error.WriteLineAsync($"打包失败: {result.Error}");
            return 1;
        }

        Console.WriteLine($"打包完成：{result.VolumeCount} 个卷 → {outputDir.FullName}");
        return 0;
    }
}
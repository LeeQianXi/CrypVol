using System.CommandLine;
using CrypVol.Lib;
using CrypVol.Lib.Crypto;
using CrypVol.Lib.Engine;
using CrypVol.Lib.Engine.Models;
using CrypVol.Lib.Volume;

namespace CrypVol.Cli.Pack;

public static class PackHelper
{
    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        var loggerFactory = Program.LoggerFactory;

        var inputPath = args.GetRequiredValue(CommandDefinition.Pack.InputPath);
        if (!inputPath.Exists)
        {
            Console.WriteLine("源路径不存在");
            return 1;
        }

        var outputDir = args.GetRequiredValue(CommandDefinition.Pack.OutputPath);
        if (!outputDir.Exists)
            outputDir.Create();

        var prefix = args.GetValue(CommandDefinition.Pack.OutputPrefix);
        if (string.IsNullOrWhiteSpace(prefix))
        {
            Console.WriteLine("无效前缀");
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

        var allFiles = Directory.GetFiles(sourceFolder.FullName, "*", SearchOption.AllDirectories);
        var files = new List<FileInfo>();
        foreach (var f in allFiles)
        {
            var rel = Path.GetRelativePath(sourceFolder.FullName, f);
            if (matcher.IsMatch(rel))
                files.Add(new FileInfo(f));
        }

        if (files.Count == 0)
        {
            Console.WriteLine("无可处理文件");
            return 1;
        }

        // Dry-run: 仅估算，不调用引擎
        if (args.GetValue(CommandDefinition.Pack.DryRun))
        {
            var cap = 1L * 1024 * 1024 * args.GetValue(CommandDefinition.Pack.VolumeSize);
            VolumeAllocator.Logger = loggerFactory.CreateLogger("VolumeAllocator");
            var (items, vols) = VolumeAllocator.Allocate(files, sourceFolder, cap);
            Console.WriteLine($"预估: {vols.Count} 卷, {items.Count} 块, {files.Sum(f => f.Length)} 字节");
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
                var reader = new CvkReader(
                    keyFile,
                    args.GetValue(CommandDefinition.Pack.Password),
                    args.GetValue(CommandDefinition.Pack.PrivkeyKey),
                    args.GetValue(CommandDefinition.Pack.PrivkeyKeyPass)
                )
                {
                    Logger = loggerFactory.CreateLogger("CvkReader")
                };
                creds = await reader.LoadKeyAsync(token);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return 1;
            }
        }
        else
        {
            var writer = new CvkWriter(
                mode,
                args.GetValue(CommandDefinition.Pack.Password),
                args.GetValue(CommandDefinition.Pack.PublicKey),
                args.GetValue(CommandDefinition.Pack.Comment)
            )
            {
                Logger = loggerFactory.CreateLogger("CvkWriter")
            };
            creds = await writer.WriteCvkAsync(
                args.GetValue(CommandDefinition.Pack.KeyOutputPath) ?? outputDir,
                prefix, token);
        }

        var engine = new CrypVolEngine
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
            EnableCompression = args.GetValue(CommandDefinition.Pack.Compress),
            CompressionLevel = args.GetValue(CommandDefinition.Pack.CompressionLevel),
            KeyOutputDir = args.GetValue(CommandDefinition.Pack.KeyOutputPath)!,
            IntegrityLevel = args.GetValue(CommandDefinition.Pack.Integrity),
            Credentials = creds
        }, token);

        if (!result.Success)
        {
            Console.WriteLine($"错误: {result.Error}");
            return 1;
        }

        Console.WriteLine($"打包完成：{result.VolumeCount} 个卷 → {outputDir.FullName}");
        return 0;
    }
}

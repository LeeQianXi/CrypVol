using System.CommandLine;
using CrypVol.Lib;
using CrypVol.Lib.Models;
using Microsoft.Extensions.FileSystemGlobbing;
using Microsoft.Extensions.FileSystemGlobbing.Abstractions;

namespace CrypVol.Cli.Pack;

public static class PackHelper
{
    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        var inputPath = args.GetRequiredValue(CommandDefinition.Pack.InputPath);
        if (!inputPath.Exists)
        {
            Console.WriteLine("源路径不存在");
            return 1;
        }

        var sourceDir = inputPath switch
        {
            FileInfo fi => fi.Directory!.FullName,
            DirectoryInfo di => di.FullName,
            _ => throw new InvalidOperationException()
        };

        // Globbing (CLI-specific, stays here)
        List<FileInfo> files;
        if (inputPath is DirectoryInfo dirInfo)
        {
            var filter = new Matcher();
            var inc = args.GetValue(CommandDefinition.Pack.Include);
            filter.AddInclude(string.IsNullOrWhiteSpace(inc) ? "**/*" : inc);
            var exc = args.GetValue(CommandDefinition.Pack.Exclude);
            if (!string.IsNullOrWhiteSpace(exc)) filter.AddExclude(exc);
            var globResult = filter.Execute(new DirectoryInfoWrapper(dirInfo));
            if (!globResult.HasMatches)
            {
                Console.WriteLine("无可处理文件");
                return 1;
            }

            files = globResult.Files.Select(f => new FileInfo(Path.Combine(dirInfo.FullName, f.Path))).ToList();
        }
        else { files = [(FileInfo)inputPath]; }

        var outputDir = args.GetRequiredValue(CommandDefinition.Pack.OutputPath);
        var prefix = args.GetValue(CommandDefinition.Pack.OutputPrefix);
        if (string.IsNullOrWhiteSpace(prefix))
        {
            Console.WriteLine("无效前缀");
            return 1;
        }

        var engine = new CrypVolEngine();
        if (args.GetValue(CommandDefinition.Verbose))
            engine.Progress = new ConsoleProgress();

        var result = await engine.PackAsync(new PackOptions
        {
            SourcePath = inputPath.FullName,
            OutputDir = outputDir.FullName,
            OutputPrefix = prefix,
            VolumeSizeMb = args.GetValue(CommandDefinition.Pack.VolumeSize),
            EncryptionMode = args.GetValue(CommandDefinition.Pack.Mode),
            Password = args.GetValue(CommandDefinition.Pack.Password),
            PublicKeyPaths = args.GetValue(CommandDefinition.Pack.PublicKey)?.Select(f => f.FullName).ToList(),
            KeyFilePath = args.GetValue(CommandDefinition.Pack.KeyFile)?.FullName,
            KeyFilePassword = args.GetValue(CommandDefinition.Pack.Password),
            EnableCompression = args.GetValue(CommandDefinition.Pack.Compress),
            CompressionLevel = args.GetValue(CommandDefinition.Pack.CompressionLevel),
            Threads = args.GetValue(CommandDefinition.Pack.Threads)
        }, files, sourceDir, token);

        if (!result.Success)
        {
            Console.WriteLine($"错误: {result.Error}");
            return 1;
        }

        Console.WriteLine($"打包完成：{result.VolumeCount} 个卷 → {outputDir.FullName}");
        return 0;
    }
}
using System.CommandLine;
using System.Text;
using System.Text.Json;
using CrypVol.Lib;
using CrypVol.Lib.Crypto;
using CrypVol.Lib.Engine;
using CrypVol.Lib.Engine.Models;
using CrypVol.Lib.Volume;

namespace CrypVol.Cli.Browse;

public static class BrowseHelper
{
    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        var rawInput = args.GetRequiredValue(CommandDefinition.Browse.VolFiles);
        var fmt = args.GetValue(CommandDefinition.Browse.OutputFormat);
        var longFormat = args.GetValue(CommandDefinition.Browse.LongFormat);
        var outputFile = args.GetValue(CommandDefinition.Browse.Output);

        var loggerFactory = Program.LoggerFactory;

        // 1. 解析卷文件 + 密钥加载
        VolumeDiscovery.Logger = loggerFactory.CreateLogger("VolumeDiscovery");
        var volFiles = VolumeDiscovery.Discover(rawInput).ToList().AsReadOnly();
        if (volFiles.Count is 0)
        {
            Console.Error.WriteLine("无可处理文件");
            return 1;
        }

        CvkCredentials? creds;
        var keyFile = args.GetValue(CommandDefinition.Browse.KeyFile);
        if (keyFile is null)
        {
            keyFile = VolumeDiscovery.DiscoverKeyFile(volFiles);
            if (keyFile is not null)
                Console.WriteLine($"自动发现密钥文件: {keyFile.FullName}");
        }

        if (keyFile is not null)
            try
            {
                var reader = new CvkReader(
                    keyFile,
                    args.GetValue(CommandDefinition.Browse.Password),
                    args.GetValue(CommandDefinition.Browse.PrivkeyKey),
                    args.GetValue(CommandDefinition.Browse.PrivkeyKeyPass)
                )
                {
                    Logger = loggerFactory.CreateLogger("CvkReader")
                };
                creds = await reader.LoadKeyAsync(token);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.Message);
                return 1;
            }
        else
            creds = new CvkCredentials(EncryptionMode.None, null!);

        // 2. Engine
        var engine = new CrypVolEngine
        {
            Logger = loggerFactory.CreateLogger("CrypVol")
        };
        var result = await engine.BrowseAsync(new BrowseOptions
        {
            VolumeFiles = volFiles,
            Credentials = creds,
            IncludePattern = args.GetValue(CommandDefinition.Browse.Include),
            ExcludePattern = args.GetValue(CommandDefinition.Browse.Exclude)
        }, token);
        if (!result.Success)
        {
            Console.Error.WriteLine($"错误: {result.Error}");
            return 1;
        }

        // 3. 格式化输出
        var output = Format(result.Files, result.VolumeCount, fmt, longFormat);

        if (outputFile is not null)
            await File.WriteAllTextAsync(outputFile.FullName, output, token);
        else
            Console.Write(output);

        return 0;
    }

    private static string Format(List<BrowseFileEntry> files, int volumeCount, OutputFormat format, bool longFormat)
    {
        return format switch
        {
            OutputFormat.Json => FormatJson(files, volumeCount, longFormat),
            OutputFormat.Csv => FormatCsv(files, longFormat),
            OutputFormat.Table => FormatTable(files, volumeCount, longFormat),
            _ => FormatList(files, volumeCount, longFormat)
        };
    }

    private static string FormatList(List<BrowseFileEntry> files, int volumeCount, bool longFormat)
    {
        var sb = new StringBuilder();
        var incomplete = files.Where(f => !f.IsComplete).Select(f => f.Path).ToList();
        if (incomplete.Count > 0)
            sb.AppendLine($"警告: 以下文件不完整: {string.Join(", ", incomplete)}");

        sb.AppendLine($"共 {files.Count} 个文件 ({volumeCount} 个卷):");
        foreach (var f in files)
        {
            var status = f.IsComplete ? "" : " [不完整]";
            if (longFormat)
                sb.AppendLine($"  {Fmt(f.Size),10}  {f.FragmentCount}段  卷[{string.Join(",", f.Volumes)}]  {f.Path}{status}");
            else
                sb.AppendLine($"  {f.Path}{status}");
        }

        return sb.ToString();
    }

    private static string FormatTable(List<BrowseFileEntry> files, int volumeCount, bool longFormat)
    {
        var sb = new StringBuilder();
        var incomplete = files.Where(f => !f.IsComplete).Select(f => f.Path).ToList();
        if (incomplete.Count > 0)
            sb.AppendLine($"警告: 以下文件不完整: {string.Join(", ", incomplete)}");

        sb.AppendLine($"共 {files.Count} 个文件 ({volumeCount} 个卷):");
        sb.AppendLine();

        if (longFormat)
        {
            sb.AppendLine($"{"大小",-10} {"片段",-6} {"跨卷",-16} {"状态",-8} 路径");
            sb.AppendLine(new string('-', 80));
            foreach (var f in files)
            {
                var size = Fmt(f.Size);
                var vols = string.Join(",", f.Volumes);
                var cross = f.FragmentCount > 1 ? $"是 ({string.Join("->", f.Volumes)})" : "-";
                var status = f.IsComplete ? "" : "不完整";
                sb.AppendLine($"{size,-10} {f.FragmentCount,-6} {cross,-16} {status,-8} {f.Path}");
            }
        }
        else
        {
            sb.AppendLine($"{"大小",-10} {"片段",-6} {"状态",-8} 路径");
            sb.AppendLine(new string('-', 60));
            foreach (var f in files)
            {
                var size = Fmt(f.Size);
                var status = f.IsComplete ? "" : "不完整";
                sb.AppendLine($"{size,-10} {f.FragmentCount,-6} {status,-8} {f.Path}");
            }
        }

        return sb.ToString();
    }

    private static string FormatJson(List<BrowseFileEntry> files, int volumeCount, bool longFormat)
    {
        var jsonFiles = files.Select(f => new
        {
            f.Path,
            f.Size,
            SizeFormatted = Fmt(f.Size),
            f.FragmentCount,
            f.Volumes,
            CrossVolume = f.FragmentCount > 1,
            VolumeSpan = f.Volumes.Count > 0 ? $"{f.Volumes.Min()}->{f.Volumes.Max()}" : "",
            f.IsComplete
        });
        var obj = new
        {
            VolumeCount = volumeCount,
            FileCount = files.Count,
            Files = jsonFiles
        };
        return JsonSerializer.Serialize(obj, new JsonSerializerOptions { WriteIndented = true });
    }

    private static string FormatCsv(List<BrowseFileEntry> files, bool longFormat)
    {
        var sb = new StringBuilder();
        if (longFormat)
        {
            sb.AppendLine("Path,Size,FragmentCount,Volumes,CrossVolume,VolumeSpan,IsComplete");
            foreach (var f in files)
                sb.AppendLine(
                    $"\"{f.Path}\",{f.Size},{f.FragmentCount},\"{string.Join(";", f.Volumes)}\",{f.FragmentCount > 1},\"{f.Volumes.Min()}->{f.Volumes.Max()}\",{f.IsComplete}");
        }
        else
        {
            sb.AppendLine("Path,Size,FragmentCount,Volumes,IsComplete");
            foreach (var f in files)
                sb.AppendLine(
                    $"\"{f.Path}\",{f.Size},{f.FragmentCount},\"{string.Join(";", f.Volumes)}\",{f.IsComplete}");
        }

        return sb.ToString();
    }

    private static string Fmt(long b)
    {
        return b switch
        {
            < 1024 => $"{b}B", < 1048576 => $"{b / 1024.0:F1}K",
            < 1073741824 => $"{b / 1048576.0:F1}M", _ => $"{b / 1073741824.0:F2}G"
        };
    }
}

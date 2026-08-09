using Microsoft.Extensions.Logging;

namespace CrypVol.Lib.Volume;

/// <summary>发现同组所有 .cvp 卷文件</summary>
public static class VolumeDiscovery
{
    public static List<FileInfo> Discover(ICollection<FileSystemInfo> inputs, ILogger? logger = null)
    {
        var result = new HashSet<FileInfo>();

        foreach (var input in inputs)
            if (input is DirectoryInfo di)
            {
                foreach (var f in Directory.GetFiles(di.FullName, "*.cvp", SearchOption.TopDirectoryOnly))
                    result.Add(new FileInfo(f));
            }
            else if (input is FileInfo fi && fi.Name.EndsWith(".cvp", StringComparison.OrdinalIgnoreCase))
            {
                var dir = fi.DirectoryName!;
                var prefix = GetPrefix(fi);
                foreach (var f in Directory.GetFiles(dir, $"{prefix}.*.cvp"))
                    result.Add(new FileInfo(f));
            }

        var list = result.OrderBy(f =>
        {
            var name = Path.GetFileNameWithoutExtension(f.Name);
            var parts = name.Split('.');
            return parts.Length > 1 && int.TryParse(parts[^1], out var n) ? n : 0;
        }).ToList();

        logger?.LogDebug("发现 {Count} 个卷", list.Count);
        return list;
    }

    private static string GetPrefix(FileInfo fi)
    {
        var name = fi.Name;
        var lastDot = name.LastIndexOf('.');
        var secondLastDot = name.LastIndexOf('.', lastDot - 1);
        return secondLastDot > 0 ? name[..secondLastDot] : Path.GetFileNameWithoutExtension(name);
    }

    public static FileInfo? DiscoverKeyFile(IReadOnlyList<FileInfo> volFiles, ILogger? logger = null)
    {
        var first = volFiles.FirstOrDefault(f => f.Name.EndsWith(".cvp", StringComparison.OrdinalIgnoreCase));
        if (first is null) return null;
        var cvk = new FileInfo(Path.Combine(first.DirectoryName!, $"{GetPrefix(first)}.cvk"));
        if (cvk.Exists)
        {
            logger?.LogDebug("自动发现密钥: {Path}", cvk.FullName);
            return cvk;
        }

        return null;
    }
}

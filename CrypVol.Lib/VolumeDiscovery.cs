namespace CrypVol.Lib;

/// <summary>发现同组所有 .cvp 卷文件</summary>
public static class VolumeDiscovery
{
    public static List<FileInfo> Discover(ICollection<FileSystemInfo> inputs)
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
                var name = fi.Name;
                var lastDot = name.LastIndexOf('.');
                var secondLastDot = name.LastIndexOf('.', lastDot - 1);
                var prefix = secondLastDot > 0 ? name[..secondLastDot] : Path.GetFileNameWithoutExtension(name);
                foreach (var f in Directory.GetFiles(dir, $"{prefix}.*.cvp"))
                    result.Add(new FileInfo(f));
            }

        return result.OrderBy(f =>
        {
            var name = Path.GetFileNameWithoutExtension(f.Name);
            var parts = name.Split('.');
            return parts.Length > 1 && int.TryParse(parts[^1], out var n) ? n : 0;
        }).ToList();
    }
}
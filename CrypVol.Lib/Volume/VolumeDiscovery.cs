namespace CrypVol.Lib.Volume;

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
                var prefix = GetPrefix(fi);
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

    /// <summary>从 .cvp 文件名推导卷组前缀（archive.1.cvp → archive）</summary>
    private static string GetPrefix(FileInfo fi)
    {
        var name = fi.Name;
        var lastDot = name.LastIndexOf('.');
        var secondLastDot = name.LastIndexOf('.', lastDot - 1);
        return secondLastDot > 0 ? name[..secondLastDot] : Path.GetFileNameWithoutExtension(name);
    }

    /// <summary>
    /// 在卷文件所在目录自动发现同前缀的 .cvk 密钥文件（archive.1.cvp → archive.cvk）。
    /// 多个卷组并存时优先使用第一个卷组的前缀；未找到返回 null。
    /// </summary>
    public static FileInfo? DiscoverKeyFile(IReadOnlyList<FileInfo> volFiles)
    {
        var first = volFiles.FirstOrDefault(f => f.Name.EndsWith(".cvp", StringComparison.OrdinalIgnoreCase));
        if (first is null) return null;
        var cvk = new FileInfo(Path.Combine(first.DirectoryName!, $"{GetPrefix(first)}.cvk"));
        return cvk.Exists ? cvk : null;
    }
}
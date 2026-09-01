namespace CrypVol.Lib.Crypto;

/// <summary>发现当前用户 SSH 目录中的私钥候选文件。</summary>
public static class SshPrivateKeyDiscovery
{
    /// <summary>枚举当前用户 <c>~/.ssh</c> 目录中的私钥候选文件。</summary>
    /// <returns>按文件名排序的候选私钥文件。</returns>
    public static IEnumerable<FileInfo> DiscoverUserPrivateKeys()
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrWhiteSpace(userProfile)) return [];
        return DiscoverPrivateKeys(new DirectoryInfo(Path.Combine(userProfile, ".ssh")));
    }

    /// <summary>枚举指定 SSH 目录中的私钥候选文件。</summary>
    /// <param name="sshDirectory">SSH 配置目录。</param>
    /// <returns>按文件名排序的候选私钥文件。</returns>
    public static IEnumerable<FileInfo> DiscoverPrivateKeys(DirectoryInfo sshDirectory)
    {
        ArgumentNullException.ThrowIfNull(sshDirectory);
        if (!sshDirectory.Exists) return [];

        try
        {
            var fileNames = sshDirectory.EnumerateFiles("*", SearchOption.TopDirectoryOnly)
                .Select(file => file.Name)
                .ToHashSet(StringComparer.Ordinal);
            return fileNames
                .Where(fileName => IsPairedPrivateKey(fileName, fileNames))
                .Select(fileName => new FileInfo(Path.Combine(sshDirectory.FullName, fileName)))
                .OrderBy(file => file.Name, StringComparer.Ordinal)
                .ToArray();
        }
        catch (UnauthorizedAccessException)
        {
            return [];
        }
        catch (IOException)
        {
            return [];
        }
    }

    private static bool IsPairedPrivateKey(string fileName, IReadOnlySet<string> fileNames)
    {
        return !fileName.EndsWith(".pub", StringComparison.OrdinalIgnoreCase)
               && fileNames.Contains($"{fileName}.pub");
    }
}
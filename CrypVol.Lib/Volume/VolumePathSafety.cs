namespace CrypVol.Lib.Volume;

/// <summary>验证归档路径并将输出路径限制在指定根目录内。</summary>
public static class VolumePathSafety
{
    /// <summary>验证归档中使用的相对文件路径。</summary>
    /// <param name="relativePath">来自归档头或调用方的相对路径。</param>
    /// <exception cref="InvalidDataException">路径不是安全的相对文件路径时抛出。</exception>
    public static void ValidateRelativePath(string relativePath)
    {
        if (string.IsNullOrWhiteSpace(relativePath))
            throw new InvalidDataException("归档条目路径不能为空。");
        if (Path.IsPathRooted(relativePath) || IsWindowsRootedPath(relativePath))
            throw new InvalidDataException($"归档条目路径不能是绝对路径: {relativePath}");

        var segments = relativePath.Replace('\\', '/').Split('/');
        if (segments.Any(segment => string.IsNullOrEmpty(segment) || segment is "." or ".."))
            throw new InvalidDataException($"归档条目路径包含不安全的目录段: {relativePath}");
    }

    /// <summary>解析输出路径，并确认其仍位于指定输出根目录中。</summary>
    /// <param name="outputRoot">允许写入的输出根目录。</param>
    /// <param name="candidatePath">待解析的绝对或相对候选路径。</param>
    /// <returns>经过规范化且位于输出根目录内的完整路径。</returns>
    /// <exception cref="InvalidDataException">候选路径越出输出根目录时抛出。</exception>
    public static string ResolveUnderRoot(string outputRoot, string candidatePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(outputRoot);
        ArgumentException.ThrowIfNullOrWhiteSpace(candidatePath);

        var root = Path.GetFullPath(outputRoot);
        var fullPath = Path.GetFullPath(Path.IsPathFullyQualified(candidatePath)
            ? candidatePath
            : Path.Combine(root, candidatePath));
        var relativePath = Path.GetRelativePath(root, fullPath);
        ValidateRelativePath(relativePath);
        return fullPath;
    }

    private static bool IsWindowsRootedPath(string path)
    {
        return path.StartsWith("\\\\", StringComparison.Ordinal) ||
               path.Length >= 3 && char.IsAsciiLetter(path[0]) && path[1] == ':' &&
               (path[2] == '/' || path[2] == '\\');
    }
}
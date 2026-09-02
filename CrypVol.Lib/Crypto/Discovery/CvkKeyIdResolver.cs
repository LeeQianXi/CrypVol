using System.Text.RegularExpressions;

namespace CrypVol.Lib.Crypto.Discovery;

/// <summary>按公钥格式生成稳定的 CVK 接收者标识。</summary>
public static partial class CvkKeyIdResolver
{
    /// <summary>从公钥文件解析接收者标识。</summary>
    /// <param name="publicKeyFile">RSA PEM 或 OpenSSH 公钥文件。</param>
    /// <returns>OpenSSH 公钥注释中的邮箱地址，或去掉扩展名的文件名。</returns>
    public static string Resolve(FileInfo publicKeyFile)
    {
        ArgumentNullException.ThrowIfNull(publicKeyFile);
        var fallback = Path.GetFileNameWithoutExtension(publicKeyFile.Name);
        var keyText = File.ReadAllText(publicKeyFile.FullName);
        if (!keyText.TrimStart().StartsWith("ssh-rsa ", StringComparison.Ordinal)) return fallback;

        var fields = keyText.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        return fields.Skip(2).FirstOrDefault(IsEmailAddress) ?? fallback;
    }

    private static bool IsEmailAddress(string value)
    {
        return EmailAddressPattern().IsMatch(value);
    }

    [GeneratedRegex("^[^\\s@]+@[^\\s@]+$")]
    private static partial Regex EmailAddressPattern();
}
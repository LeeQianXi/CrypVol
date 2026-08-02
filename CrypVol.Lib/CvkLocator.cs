using System.Security.Cryptography;

namespace CrypVol.Lib;

/// <summary>查找 .cvk 密钥文件</summary>
public static class CvkLocator
{
    /// <summary>在第一个 .cvp 同目录下自动搜索 .cvk</summary>
    public static FileInfo? Find(string firstVolPath)
    {
        var cvkName = Path.GetFileNameWithoutExtension(firstVolPath);
        var lastDot = cvkName.LastIndexOf('.');
        if (lastDot > 0) cvkName = cvkName[..lastDot];
        var autoCvk = Path.Combine(Path.GetDirectoryName(firstVolPath)!, cvkName + ".cvk");
        return File.Exists(autoCvk) ? new FileInfo(autoCvk) : null;
    }

    /// <summary>解密 CEK（含凭据校验）</summary>
    public static (bool ok, byte[]? cek, string? error) LoadCek(
        FileInfo keyFile, string? password = null, FileInfo? privkeyPath = null)
    {
        EnvelopeMode mode;
        try { mode = KeyEnvelope.ReadMode(keyFile.FullName); }
        catch (Exception ex) { return (false, null, $"无法读取密钥文件: {ex.Message}"); }

        if (mode == EnvelopeMode.Password && string.IsNullOrWhiteSpace(password))
            return (false, null, "密钥受密码保护，请提供 --password");
        if (mode == EnvelopeMode.PublicKey && privkeyPath is null)
            return (false, null, "密钥受公钥保护，请提供 --privkey-key");

        RSA? privKey = null;
        try
        {
            if (privkeyPath is not null)
            {
                privKey = RSA.Create();
                privKey.ImportFromPem(File.ReadAllText(privkeyPath.FullName));
            }

            var (cek, _, _) = KeyEnvelope.LoadEnvelope(keyFile.FullName, password, privKey);
            return (true, cek, null);
        }
        catch (Exception ex) { return (false, null, $"密钥解密失败: {ex.Message}"); }
        finally { privKey?.Dispose(); }
    }
}
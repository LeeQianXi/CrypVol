using System.CommandLine;
using CrypVol.Lib.Crypto;
using CrypVol.Lib.Crypto.Models;

namespace CrypVol.Cli.Rekey;

/// <summary>将现有 CVK 重新封装到另一种保护模式。</summary>
public static class RekeyHelper
{
    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        var source = args.GetRequiredValue(CommandDefinition.Rekey.CvkFile);
        var mode = args.GetValue(CommandDefinition.Rekey.ToMode)
                   ?? throw new ArgumentException("必须指定 --to-mode（Plain、Password 或 PublicKey）。");
        var oldPassword = args.GetValue(CommandDefinition.Rekey.Password);
        var newPassword = args.GetValue(CommandDefinition.Rekey.NewPassword);
        var privateKey = args.GetValue(CommandDefinition.Rekey.PrivkeyKey);
        var privateKeyPassword = args.GetValue(CommandDefinition.Rekey.PrivkeyKeyPass);
        var publicKeys = args.GetValue(CommandDefinition.Rekey.PublicKey)?.ToList() ?? [];
        var output = args.GetValue(CommandDefinition.Rekey.Output) ?? source;
        try
        {
            var algorithm = args.GetValue(CommandDefinition.Rekey.Algorithm) ?? DefaultAlgorithm(mode);
            var route = CvkEncapsulationRoute.Resolve(mode, algorithm);

            if (route.RequiresPassword && string.IsNullOrWhiteSpace(newPassword))
                throw new ArgumentException("Password 封装级别需要 --new-password。", nameof(newPassword));
            if (!route.RequiresPassword && !string.IsNullOrWhiteSpace(newPassword))
                throw new ArgumentException("只有 Password 封装级别可以使用 --new-password。", nameof(newPassword));
            if (route.RequiresRecipients && publicKeys.Count == 0)
                throw new ArgumentException("PublicKey 封装级别至少需要一个 --public-key。", nameof(publicKeys));
            if (!route.RequiresRecipients && publicKeys.Count > 0)
                throw new ArgumentException("只有 PublicKey 封装级别可以使用 --public-key。", nameof(publicKeys));

            // 解封源文档时必须传入非对称私钥；Password 和 Plain 路由会忽略该参数。
            var document = await CvkOperations.LoadAsync(source, oldPassword, privateKey,
                privateKeyPassword, token);
            document.KeyProtection = route.Level;
            document.KeyWrapAlgorithm = route.Algorithm;
            if (args.GetValue(CommandDefinition.Rekey.Label) is { } label) document.Label = label;
            if (args.GetValue(CommandDefinition.Rekey.Description) is { } description) document.Description = description;
            if (args.GetValue(CommandDefinition.Rekey.Comment) is { } comment) document.Comment = comment;
            document.RecipientKeys.Clear();
            foreach (var key in publicKeys)
                CvkOperations.AddPublicKey(document, key);

            if (args.GetValue(CommandDefinition.Rekey.Backup))
            {
                var backup = new FileInfo(source.FullName + ".bak");
                if (backup.Exists)
                    throw new IOException($"备份文件已存在：{backup.FullName}。");
                File.Copy(source.FullName, backup.FullName);
            }

            await CvkOperations.WriteAsync(document, output, newPassword, token);
            Console.WriteLine($"密钥已重新封装 → {output.FullName}");
            return 0;
        }
        catch (Exception ex)
        {
            await Console.Error.WriteLineAsync($"无法重新封装 CVK: {ex.Message}");
            return 1;
        }
    }

    private static CvkKeyWrapAlgorithm DefaultAlgorithm(CvkKeyProtection mode)
    {
        return mode switch
        {
            CvkKeyProtection.Plain => CvkKeyWrapAlgorithm.None,
            CvkKeyProtection.Password => CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256,
            CvkKeyProtection.PublicKey => CvkKeyWrapAlgorithm.RsaOaepSha256,
            _ => throw new ArgumentOutOfRangeException(nameof(mode), mode, "未知的 CVK 封装级别。")
        };
    }
}
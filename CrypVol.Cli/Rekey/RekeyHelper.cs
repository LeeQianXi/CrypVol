using System.CommandLine;
using System.Security.Cryptography;
using CrypVol.Lib;

namespace CrypVol.Cli.Rekey;

public static class RekeyHelper
{
    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        var cvkFile = args.GetRequiredValue(CommandDefinition.Rekey.CvkFile);
        var toMode = args.GetRequiredValue(CommandDefinition.Rekey.ToMode);

        // ── 解密原 .cvk ──
        var password = args.GetValue(CommandDefinition.Rekey.Password);
        RSA? privKey = null;
        var privPath = args.GetValue(CommandDefinition.Rekey.PrivkeyKey);
        if (privPath is not null)
        {
            privKey = RSA.Create();
            privKey.ImportFromPem(await File.ReadAllTextAsync(privPath.FullName, token));
        }

        byte[] cek, salt;
        try
        {
            (cek, salt, _) = KeyEnvelope.LoadEnvelope(cvkFile.FullName, password, privKey);
        }
        finally { privKey?.Dispose(); }

        // ── 备份（可选） ──
        if (args.GetValue(CommandDefinition.Rekey.Backup))
        {
            var bak = cvkFile.FullName + ".bak";
            File.Copy(cvkFile.FullName, bak, overwrite: true);
            Console.WriteLine($"已备份: {bak}");
        }

        // ── 重新封装 ──
        var output = args.GetValue(CommandDefinition.Rekey.Output);
        var outputPath = output?.FullName ?? cvkFile.FullName;

        var mode = toMode switch
        {
            EncryptionMode.PlainKey => EnvelopeMode.Plain,
            EncryptionMode.Password => EnvelopeMode.Password,
            EncryptionMode.Asymmetric => EnvelopeMode.PublicKey,
            _ => throw new Exception($"无效的目标模式: {toMode}")
        };

        var newPassword = args.GetValue(CommandDefinition.Rekey.NewPassword);
        var pubKeyFiles = args.GetValue(CommandDefinition.Rekey.PublicKey);
        Dictionary<string, RSA>? recipients = null;
        if (pubKeyFiles is not null)
        {
            recipients = new Dictionary<string, RSA>();
            foreach (var f in pubKeyFiles)
            {
                var rsa = RSA.Create();
                rsa.ImportFromPem(File.ReadAllText(f.FullName));
                recipients[Path.GetFileNameWithoutExtension(f.Name)] = rsa;
            }
        }

        // 使用原 CEK/Salt 重新封装
        KeyEnvelope.SaveEnvelope(outputPath, mode, cek, salt, newPassword, recipients);
        Console.WriteLine($"密钥已重新封装 → {outputPath}");

        if (recipients is not null)
            foreach (var r in recipients.Values) r.Dispose();

        await Task.CompletedTask;
        return 0;
    }
}

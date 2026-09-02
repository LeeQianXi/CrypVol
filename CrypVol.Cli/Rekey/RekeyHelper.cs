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
        var mode = args.GetValue(CommandDefinition.Rekey.ToMode);
        var password = args.GetValue(CommandDefinition.Rekey.NewPassword);
        var output = args.GetValue(CommandDefinition.Rekey.Output) ?? source;
        try
        {
            if (mode == CvkKeyProtection.Password && string.IsNullOrWhiteSpace(password)) throw new ArgumentException("Password 模式需要 --new-password。");
            var document = await CvkOperations.LoadAsync(source, args.GetValue(CommandDefinition.Rekey.Password), token);
            document.KeyProtection = mode;
            document.KeyWrapAlgorithm = mode switch
            {
                CvkKeyProtection.Plain => CvkKeyWrapAlgorithm.None,
                CvkKeyProtection.Password => CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256,
                _ => args.GetValue(CommandDefinition.Rekey.Algorithm) ?? CvkKeyWrapAlgorithm.RsaOaepSha256
            };
            if (mode != CvkKeyProtection.PublicKey) document.RecipientKeys.Clear();
            foreach (var key in args.GetValue(CommandDefinition.Rekey.PublicKey) ?? []) CvkOperations.AddPublicKey(document, key);
            await CvkOperations.WriteAsync(document, output, password, token);
            Console.WriteLine($"密钥已重新封装 → {output.FullName}");
            return 0;
        }
        catch (Exception ex)
        {
            await Console.Error.WriteLineAsync($"无法重新封装 CVK: {ex.Message}");
            return 1;
        }
    }
}

using System.CommandLine;
using CrypVol.Lib.Crypto;

namespace CrypVol.Cli.Rekey;

public static class RekeyHelper
{
    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        var cvkFile = args.GetRequiredValue(CommandDefinition.Rekey.CvkFile);
        var toMode = args.GetValue(CommandDefinition.Rekey.ToMode);

        // 1. 加载源 CEK
        CvkCredentials creds;
        try
        {
            creds = await new CvkReader(
                    cvkFile,
                    args.GetValue(CommandDefinition.Rekey.Password),
                    args.GetValue(CommandDefinition.Rekey.PrivkeyKey),
                    args.GetValue(CommandDefinition.Rekey.PrivkeyKeyPass))
                .LoadKeyAsync(token);
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
            return 1;
        }

        // 2. 备份
        if (args.GetValue(CommandDefinition.Rekey.Backup))
            File.Copy(cvkFile.FullName, cvkFile.FullName + ".bak", true);

        // 3. 重新封装
        var output = args.GetValue(CommandDefinition.Rekey.Output);
        var outDir = output?.Directory ?? cvkFile.Directory!;
        var prefix = Path.GetFileNameWithoutExtension(output?.Name ?? cvkFile.Name);
        var writer = new CvkWriter(
            creds.Cek,
            toMode,
            args.GetValue(CommandDefinition.Rekey.NewPassword),
            args.GetValue(CommandDefinition.Rekey.PublicKey));
        await writer.WriteCvkAsync(outDir, prefix, token);

        Console.WriteLine($"密钥已重新封装 → {Path.Combine(outDir.FullName, prefix + ".cvk")}");
        return 0;
    }
}
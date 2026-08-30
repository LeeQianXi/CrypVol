using System.CommandLine;
using CrypVol.Lib.Crypto;

namespace CrypVol.Cli.Rekey;

public static class RekeyHelper
{
    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        var cvkFile = args.GetRequiredValue(CommandDefinition.Rekey.CvkFile);
        var toMode = args.GetValue(CommandDefinition.Rekey.ToMode);
        var loggerFactory = Program.LoggerFactory;

        // 1. 加载源 CEK
        CvkCredentials creds;
        try
        {
            var cvk = await CvkLoader.LoadAsync(cvkFile,
                args.GetValue(CommandDefinition.Rekey.Password),
                args.GetValue(CommandDefinition.Rekey.PrivkeyKey),
                args.GetValue(CommandDefinition.Rekey.PrivkeyKeyPass), token);
            creds = cvk.ToCredentials();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }

        // 2. 备份
        if (args.GetValue(CommandDefinition.Rekey.Backup))
            File.Copy(cvkFile.FullName, cvkFile.FullName + ".bak", true);

        // 3. 重新封装
        var output = args.GetValue(CommandDefinition.Rekey.Output);
        var outDir = output?.Directory ?? cvkFile.Directory!;
        var prefix = Path.GetFileNameWithoutExtension(output?.Name ?? cvkFile.Name);
        var outputCvk = new CvkDocument(creds.Cek, toMode)
        {
            Password = args.GetValue(CommandDefinition.Rekey.NewPassword)
        };
        foreach (var publicKey in args.GetValue(CommandDefinition.Rekey.PublicKey) ?? [])
            outputCvk.AddPublicKey(publicKey);
        await outputCvk.WriteAsync(new FileInfo(Path.Combine(outDir.FullName, $"{prefix}.cvk")), token);

        Console.WriteLine($"密钥已重新封装 → {Path.Combine(outDir.FullName, prefix + ".cvk")}");
        return 0;
    }
}

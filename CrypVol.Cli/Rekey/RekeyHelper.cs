using System.CommandLine;
using CrypVol.Lib.Crypto;

namespace CrypVol.Cli.Rekey;

public static class RekeyHelper
{
    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        var cvkFile = args.GetRequiredValue(CommandDefinition.Rekey.CvkFile);
        var toMode = args.GetValue(CommandDefinition.Rekey.ToMode);
        var newPassword = args.GetValue(CommandDefinition.Rekey.NewPassword);
        var publicKeys = args.GetValue(CommandDefinition.Rekey.PublicKey)?.ToList() ?? [];
        var logger = Program.LoggerFactory.CreateLogger(nameof(RekeyHelper));

        // 1. 加载完整文档，保留注释和已有的公钥接收者槽位。
        CvkDocument document;
        try
        {
            document = await CvkLoader.LoadAsync(cvkFile,
                args.GetValue(CommandDefinition.Rekey.Password),
                args.GetValue(CommandDefinition.Rekey.PrivkeyKey),
                args.GetValue(CommandDefinition.Rekey.PrivkeyKeyPass), token, logger);
        }
        catch (Exception ex)
        {
            await Console.Error.WriteLineAsync($"无法加载 CVK: {ex.Message}");
            return 1;
        }

        // 2. 在任何写入前完成参数校验并构建内容，避免无效参数造成备份或覆写。
        if (toMode is EncryptionMode.None || !Enum.IsDefined(toMode))
        {
            await Console.Error.WriteLineAsync("rekey 的目标模式必须是 PlainKey、Password 或 Asymmetric。");
            return 1;
        }

        if (toMode == EncryptionMode.Password && string.IsNullOrWhiteSpace(newPassword))
        {
            await Console.Error.WriteLineAsync("Password 模式需要 --new-password。");
            return 1;
        }

        if (toMode != EncryptionMode.Password && !string.IsNullOrWhiteSpace(newPassword))
        {
            await Console.Error.WriteLineAsync("--new-password 仅可与 --to-mode Password 一起使用。");
            return 1;
        }

        if (toMode != EncryptionMode.Asymmetric && publicKeys.Count > 0)
        {
            await Console.Error.WriteLineAsync("--public-key 仅可与 --to-mode Asymmetric 一起使用。");
            return 1;
        }

        var output = args.GetValue(CommandDefinition.Rekey.Output);
        var outputFile = output ?? cvkFile;
        var sameAsSource = string.Equals(Path.GetFullPath(outputFile.FullName), Path.GetFullPath(cvkFile.FullName),
            OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
        if (!sameAsSource && outputFile.Exists)
        {
            await Console.Error.WriteLineAsync($"输出文件已存在：{outputFile.FullName}");
            return 1;
        }

        document.EncryptionMode = toMode;
        switch (toMode)
        {
            case EncryptionMode.PlainKey:
                document.Password = null;
                document.ClearPublicKeys();
                break;
            case EncryptionMode.Password:
                document.Password = newPassword;
                document.ClearPublicKeys();
                break;
            case EncryptionMode.Asymmetric:
                document.Password = null;
                foreach (var publicKey in publicKeys) document.AddPublicKey(publicKey);
                if (document.PublicKeyRecipients.Count == 0 && document.NewPublicKeyFiles.Count == 0)
                {
                    await Console.Error.WriteLineAsync("Asymmetric 模式至少需要一个现有或通过 --public-key 指定的接收者。");
                    return 1;
                }

                break;
        }

        string contents;
        try
        {
            contents = document.BuildBase64();
        }
        catch (Exception ex)
        {
            await Console.Error.WriteLineAsync($"无法构建 CVK: {ex.Message}");
            return 1;
        }

        // 3. 在全部预检通过后备份，并通过同目录临时文件替换目标，避免半写入的 CVK。
        var backupFile = new FileInfo(cvkFile.FullName + ".bak");
        if (args.GetValue(CommandDefinition.Rekey.Backup))
        {
            if (backupFile.Exists)
            {
                await Console.Error.WriteLineAsync($"备份文件已存在，拒绝覆盖：{backupFile.FullName}");
                return 1;
            }

            try
            {
                File.Copy(cvkFile.FullName, backupFile.FullName);
            }
            catch (Exception ex)
            {
                await Console.Error.WriteLineAsync($"无法创建备份: {ex.Message}");
                return 1;
            }
        }

        var outputDirectory = outputFile.Directory;
        if (outputDirectory is null)
        {
            await Console.Error.WriteLineAsync("输出文件路径无效。");
            return 1;
        }

        var temporaryPath = Path.Combine(outputDirectory.FullName, $".{outputFile.Name}.{Guid.NewGuid():N}.tmp");
        try
        {
            outputDirectory.Create();
            await File.WriteAllTextAsync(temporaryPath, contents, token);
            File.Move(temporaryPath, outputFile.FullName, true);
        }
        catch (Exception ex)
        {
            await Console.Error.WriteLineAsync($"无法写入 CVK: {ex.Message}");
            return 1;
        }
        finally
        {
            if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
        }

        Console.WriteLine($"密钥已重新封装 → {outputFile.FullName}");
        return 0;
    }
}
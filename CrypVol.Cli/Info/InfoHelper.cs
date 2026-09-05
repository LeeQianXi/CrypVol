using System.CommandLine;
using System.Security.Cryptography;
using CrypVol.Lib.Crypto;
using CrypVol.Lib.Crypto.Models;
using CrypVol.Lib.Crypto.Reading;
using CrypVol.Lib.Crypto.Writing;

namespace CrypVol.Cli.Info;

public static class InfoHelper
{
    /// <summary>执行 info 命令。</summary>
    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        var keyFile = args.GetRequiredValue(CommandDefinition.Info.KeyFile);
        var password = args.GetValue(CommandDefinition.Info.Password);
        var explicitPrivateKey = args.GetValue(CommandDefinition.Info.PrivkeyKey);
        var privateKeyPassword = args.GetValue(CommandDefinition.Info.PrivkeyKeyPass);
        var logger = Program.LoggerFactory.CreateLogger(nameof(InfoHelper));

        CvkParsedFile parsed;
        try
        {
            // 先独立解析三段，使完整性或解封失败时仍能输出 Header 信息。
            var raw = await File.ReadAllBytesAsync(keyFile.FullName, token);
            parsed = CvkParser.Parse(raw);
            PrintHeader(keyFile, parsed.Header);
        }
        catch (OperationCanceledException)
        {
            await Console.Error.WriteLineAsync("操作已取消");
            return 1;
        }
        catch (Exception ex)
        {
            Console.WriteLine("状态: CVK 格式无效");
            Console.WriteLine($"原因: {ex.Message}");
            return 0;
        }

        var integrity = new Sha256IntegrityCalculator().Compute(parsed.HeaderJson, parsed.KeyBody);
        var integrityValid = integrity.Length == parsed.Integrity.Length &&
                             CryptographicOperations.FixedTimeEquals(integrity.Span, parsed.Integrity.Span);
        Console.WriteLine(integrityValid ? "完整性: 已验证" : "完整性: 失败（文件可能被篡改或损坏）");
        if (!integrityValid)
        {
            Console.WriteLine("状态: CVK 可解析，但未通过完整性校验，未执行解封");
            return 0;
        }

        if (parsed.Header.KeyProtection == CvkKeyProtection.Password && string.IsNullOrWhiteSpace(password))
        {
            Console.WriteLine("状态: CVK 完整性通过，但需要提供 --password 才能解封");
            return 0;
        }

        try
        {
            CvkDocument document;
            document = await CvkOperations.LoadAsync(keyFile, password, explicitPrivateKey, privateKeyPassword, token,
                logger);
            Console.WriteLine("状态: 已解封并验证");
            PrintDocument(document);
        }
        catch (OperationCanceledException)
        {
            await Console.Error.WriteLineAsync("操作已取消");
            return 1;
        }
        catch (Exception ex)
        {
            Console.WriteLine("状态: CVK 完整性通过，但未解封");
            Console.WriteLine($"解封原因: {ex.Message}");
        }

        return 0;
    }

    /// <summary>输出文件头中的公开信息。</summary>
    private static void PrintHeader(FileInfo file, CvkHeader header)
    {
        Console.WriteLine($"文件: {file.Name}");
        Console.WriteLine($"版本: {header.Version}");
        Console.WriteLine($"封装级别: {ModeLabel(header.KeyProtection)} ({header.KeyProtection})");
        Console.WriteLine($"密钥封装算法: {header.KeyWrapAlgorithm}");
        PrintMetadata(header.Label, header.Description, header.Comment, header.CreatedAt, header.Generator);
    }

    /// <summary>输出解封后的私密信息。</summary>
    private static void PrintDocument(CvkDocument document)
    {
        Console.WriteLine($"CEK 指纹: {Fingerprint(document.Cek)}");
        if (document.KeyProtection != CvkKeyProtection.PublicKey) return;

        Console.WriteLine($"公钥接收者: {document.RecipientKeys.Count}");
        foreach (var recipient in document.RecipientKeys)
            Console.WriteLine($"  - {recipient.KeyId} ({recipient.Algorithm})");
    }

    /// <summary>输出 CVK 的可读元数据。</summary>
    private static void PrintMetadata(string? label, string? description, string? comment,
        DateTimeOffset? createdAt, string? generator)
    {
        if (!string.IsNullOrWhiteSpace(label)) Console.WriteLine($"标签: {label}");
        if (!string.IsNullOrWhiteSpace(description)) Console.WriteLine($"描述: {description}");
        if (!string.IsNullOrWhiteSpace(comment)) Console.WriteLine($"注释: {comment}");
        if (createdAt is not null) Console.WriteLine($"创建时间: {createdAt:O}");
        if (!string.IsNullOrWhiteSpace(generator)) Console.WriteLine($"生成器: {generator}");
    }

    private static string Fingerprint(ReadOnlyMemory<byte> cek)
    {
        var fingerprint = System.Convert.ToHexString(SHA256.HashData(cek.Span));
        return fingerprint[..16] + "...";
    }

    private static string ModeLabel(CvkKeyProtection m)
    {
        return m switch
        {
            CvkKeyProtection.Plain => "明文封装",
            CvkKeyProtection.Password => "密码封装",
            CvkKeyProtection.PublicKey => "公钥封装",
            _ => "未知封装级别"
        };
    }
}
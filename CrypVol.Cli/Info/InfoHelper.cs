using System.CommandLine;
using CrypVol.Lib.Crypto.Cryptography;
using CrypVol.Lib.Crypto.Keys;
using CrypVol.Lib.Crypto.Models;
using CrypVol.Lib.Crypto.Reading;
using CrypVol.Lib.Crypto.Writing;

namespace CrypVol.Cli.Info;

public static class InfoHelper
{
    public static async Task<int> Invoker(ParseResult args, CancellationToken token)
    {
        var keyFile = args.GetRequiredValue(CommandDefinition.Info.KeyFile);
        var logger = Program.LoggerFactory.CreateLogger(nameof(InfoHelper));

        try
        {
            var parsed = CvkParser.Parse(await File.ReadAllBytesAsync(keyFile.FullName, token));
            Console.WriteLine($"文件: {keyFile.Name}");
            Console.WriteLine($"保护模式: {ModeLabel(parsed.Header.KeyProtection)} ({parsed.Header.KeyProtection})");
            Console.WriteLine($"封装算法: {parsed.Header.KeyWrapAlgorithm}");

            var password = args.GetValue(CommandDefinition.Info.Password);
            var registry = string.IsNullOrEmpty(password)
                ? CvkPayloadCryptorRegistry.CreateDefault()
                : CvkPayloadCryptorRegistry.CreateDefault(password);
            var cryptor = registry.Resolve(parsed.Header);
            var reader = new CvkReader(new Sha256IntegrityCalculator(),
                new CvkPayloadUnprotectorAdapter(cryptor));
            var document = await reader.ReadDocumentAsync(keyFile, token);

            Console.WriteLine("状态: 已解封并验证");
            Console.WriteLine($"保护模式: {ModeLabel(document.KeyProtection)} ({document.KeyProtection})");
            Console.WriteLine($"封装算法: {document.KeyWrapAlgorithm}");
            Console.WriteLine($"CEK 指纹: {System.Convert.ToHexString(document.Cek)[..8]}...");
            if (!string.IsNullOrWhiteSpace(document.Comment))
                Console.WriteLine($"注释: {document.Comment}");
            if (!string.IsNullOrWhiteSpace(document.Label)) Console.WriteLine($"标签: {document.Label}");
            if (!string.IsNullOrWhiteSpace(document.Description)) Console.WriteLine($"描述: {document.Description}");
            if (document.CreatedAt is not null) Console.WriteLine($"创建时间: {document.CreatedAt:O}");
            if (!string.IsNullOrWhiteSpace(document.Generator)) Console.WriteLine($"生成器: {document.Generator}");

            if (document.KeyProtection == CvkKeyProtection.PublicKey)
            {
                Console.WriteLine($"公钥接收者: {document.RecipientKeys.Count}");
                foreach (var recipient in document.RecipientKeys)
                    Console.WriteLine($"  - {recipient.KeyId}");
            }
        }
        catch (Exception ex)
        {
            await Console.Error.WriteLineAsync($"无法解封 CVK: {ex.Message}");
            return 1;
        }

        return 0;
    }

    private static string ModeLabel(CvkKeyProtection m)
    {
        return m switch
        {
            CvkKeyProtection.Plain => "明文",
            CvkKeyProtection.Password => "密码保护",
            CvkKeyProtection.PublicKey => "公钥保护",
            _ => "未知"
        };
    }
}

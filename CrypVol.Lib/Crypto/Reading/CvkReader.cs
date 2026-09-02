using System.Security.Cryptography;
using CrypVol.Lib.Crypto.Writing;

namespace CrypVol.Lib.Crypto.Reading;

/// <summary>读取、校验并按需解封 CVK 文件。</summary>
public sealed class CvkReader
{
    private readonly ICvkIntegrityCalculator _integrityCalculator;
    private readonly ICvkPayloadUnprotector? _payloadUnprotector;

    /// <summary>创建 CVK 读取器。</summary>
    public CvkReader(ICvkIntegrityCalculator integrityCalculator,
        ICvkPayloadUnprotector? payloadUnprotector = null)
    {
        _integrityCalculator = integrityCalculator ?? throw new ArgumentNullException(nameof(integrityCalculator));
        _payloadUnprotector = payloadUnprotector;
    }

    /// <summary>读取并解析文件，返回尚未解封的 CVK 段。</summary>
    public async Task<CvkParsedFile> ReadAsync(FileInfo file, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(file);
        if (!file.Exists) throw new FileNotFoundException("CVK 文件不存在。", file.FullName);
        await using var stream = file.OpenRead();
        using var memory = new MemoryStream();
        await stream.CopyToAsync(memory, cancellationToken);
        var parsed = CvkParser.Parse(memory.ToArray());
        var expected = _integrityCalculator.Compute(parsed.HeaderJson, parsed.KeyBody);
        if (expected.Length != parsed.Integrity.Length ||
            !CryptographicOperations.FixedTimeEquals(expected.Span, parsed.Integrity.Span))
            throw new CryptographicException("CVK 完整性校验失败。");
        return parsed;
    }

    /// <summary>读取、校验并解封为内存中的 Document。</summary>
    public async Task<CvkDocument> ReadDocumentAsync(FileInfo file, CancellationToken cancellationToken = default)
    {
        if (_payloadUnprotector is null) throw new InvalidOperationException("未配置 Payload 解封策略。");
        var parsed = await ReadAsync(file, cancellationToken);
        var payload = await _payloadUnprotector.UnprotectAsync(parsed.Header, parsed.KeyBody, cancellationToken);
        var document = new CvkDocument
        {
            Cek = payload.Cek.ToArray(),
            KeyProtection = parsed.Header.KeyProtection,
            KeyWrapAlgorithm = parsed.Header.KeyWrapAlgorithm,
            Version = parsed.Header.Version,
            Label = parsed.Header.Label,
            Description = parsed.Header.Description,
            Comment = parsed.Header.Comment,
            CreatedAt = parsed.Header.CreatedAt,
            Generator = parsed.Header.Generator
        };
        foreach (var recipient in payload.RecipientKeys) document.RecipientKeys.Add(recipient);
        return document;
    }
}
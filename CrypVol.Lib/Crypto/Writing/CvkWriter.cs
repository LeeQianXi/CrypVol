using System.Buffers.Binary;
using System.Text.Json;
using System.Text.Json.Serialization;
using CrypVol.Lib.Crypto.Models;
using CrypVol.Lib.Utility;

namespace CrypVol.Lib.Crypto.Writing;

/// <summary>将可变的 <see cref="CvkDocument" /> 写入 CVK 三段式文件。</summary>
/// <remarks>
///     <para>写入顺序为 Header JSON、受保护的密钥体、完整性段。</para>
///     <para>Document 不负责任何隐式拼装；Header 和 Payload 在本类中显式构造。</para>
/// </remarks>
public sealed class CvkWriter
{
    private const int PrefixSize = 16;
    private static readonly byte[] Magic = [.. "CVK1"u8];
    private readonly ICvkIntegrityCalculator _integrityCalculator;
    private readonly JsonSerializerOptions _jsonOptions;
    private readonly ICvkPayloadProtector _payloadProtector;

    /// <summary>创建 CVK 写入器。</summary>
    public CvkWriter(ICvkPayloadProtector payloadProtector,
        ICvkIntegrityCalculator? integrityCalculator = null,
        JsonSerializerOptions? jsonOptions = null)
    {
        _payloadProtector = payloadProtector ?? throw new ArgumentNullException(nameof(payloadProtector));
        _integrityCalculator = integrityCalculator ?? new Sha256IntegrityCalculator();
        _jsonOptions = jsonOptions ?? CreateJsonOptions();
    }

    /// <summary>将 Document 原子写入目标文件。</summary>
    public async Task WriteAsync(CvkDocument document, FileInfo file,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(file);
        Validate(document);

        var header = new CvkHeader(document.Version, document.KeyProtection,
            document.KeyWrapAlgorithm, document.Label, document.Description,
            document.Comment, document.CreatedAt, document.Generator);
        var payload = new CvkPayload(document.Cek.ToArray(), document.RecipientKeys.ToArray());
        var headerJson = JsonSerializer.SerializeToUtf8Bytes(header, _jsonOptions);
        var keyBody = await _payloadProtector.ProtectAsync(header, payload, cancellationToken);
        var integrity = _integrityCalculator.Compute(headerJson, keyBody);

        var output = new byte[PrefixSize + headerJson.Length + keyBody.Length + integrity.Length];
        Magic.CopyTo(output, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(4), (uint)headerJson.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(8), (uint)keyBody.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(12), (uint)integrity.Length);
        var offset = PrefixSize;
        headerJson.CopyTo(output, offset);
        offset += headerJson.Length;
        keyBody.Span.CopyTo(output.AsSpan(offset));
        offset += keyBody.Length;
        integrity.Span.CopyTo(output.AsSpan(offset));
        await AtomicFile.WriteBytesAsync(file.FullName, output, cancellationToken);
    }

    private static JsonSerializerOptions CreateJsonOptions()
    {
        return new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            WriteIndented = false
        };
    }

    private static void Validate(CvkDocument document)
    {
        if (document.Cek is null || document.Cek.Length == 0)
            throw new InvalidDataException("CVK 必须包含 CEK。");
        if (document.Version == 0)
            throw new InvalidDataException("CVK 版本必须大于 0。");
        if (document.KeyProtection == CvkKeyProtection.Plain && document.KeyWrapAlgorithm != CvkKeyWrapAlgorithm.None)
            throw new InvalidDataException("Plain 模式必须使用 None 封装算法。");
        switch (document)
        {
            case
            {
                KeyProtection: CvkKeyProtection.Password,
                KeyWrapAlgorithm: not (CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256 or CvkKeyWrapAlgorithm.PasswordArgon2Id)
            }:
                throw new InvalidDataException("Password 模式必须使用密码派生算法。");
            case { KeyProtection: CvkKeyProtection.PublicKey, RecipientKeys.Count: 0 }:
                throw new InvalidDataException("PublicKey 模式至少需要一个接收者公钥。");
        }
    }
}
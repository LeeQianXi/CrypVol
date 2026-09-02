using CrypVol.Lib.Crypto.Models;

namespace CrypVol.Lib.Crypto.Reading;

/// <summary>已解析但尚未解封的 CVK 文件。</summary>
public sealed record CvkParsedFile(
    CvkHeader Header,
    ReadOnlyMemory<byte> HeaderJson,
    ReadOnlyMemory<byte> KeyBody,
    ReadOnlyMemory<byte> Integrity);
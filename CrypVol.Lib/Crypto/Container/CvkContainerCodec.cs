using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;

namespace CrypVol.Lib.Crypto.Container;

/// <summary>CVK v3 容器编解码器，负责三段式布局与完整性校验，不参与密钥解封。</summary>
internal static class CvkContainerCodec
{
    /// <summary>将明文元数据和密钥体封装为带校验体的 Base64 CVK。</summary>
    public static string Encode(CvkMetadataPayload metadata, ReadOnlySpan<byte> keyBody)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        if (keyBody.Length <= 0 || keyBody.Length > CvkFormat.MaxSectionLength)
            throw new InvalidOperationException("CVK 密钥体长度无效。");
        if (metadata.KeyBodyLength != keyBody.Length)
            throw new InvalidOperationException("CVK 元数据与密钥体长度不一致。");

        var metadataBytes = JsonSerializer.SerializeToUtf8Bytes(metadata, CvkJson.Options);
        if (metadataBytes.Length > CvkFormat.MaxSectionLength)
            throw new InvalidOperationException("CVK 元数据过大。");
        var total = checked(CvkFormat.HeaderSize + metadataBytes.Length + keyBody.Length + CvkFormat.IntegritySize);
        var data = new byte[total];
        CvkFormat.Magic.CopyTo(data, 0);
        data[4] = CvkFormat.Version;
        data[5] = CvkFormat.Flags;
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(6, 4), (uint)metadataBytes.Length);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(10, 4), (uint)keyBody.Length);
        metadataBytes.CopyTo(data, CvkFormat.HeaderSize);
        keyBody.CopyTo(data.AsSpan(CvkFormat.HeaderSize + metadataBytes.Length));
        var integrityOffset = total - CvkFormat.IntegritySize;
        SHA256.HashData(data.AsSpan(0, integrityOffset), data.AsSpan(integrityOffset));
        return Convert.ToBase64String(data);
    }

    /// <summary>解码并验证 CVK 容器，返回未解封的密钥体。</summary>
    public static CvkContainer Decode(string base64)
    {
        byte[] data;
        try { data = Convert.FromBase64String(base64); }
        catch (FormatException ex) { throw new InvalidDataException("CVK 不是有效的 Base64 容器。", ex); }
        if (data.Length < CvkFormat.HeaderSize + CvkFormat.IntegritySize)
            throw new InvalidDataException("CVK 容器过短。");
        if (!data.AsSpan(0, 4).SequenceEqual(CvkFormat.Magic) || data[4] != CvkFormat.Version || data[5] != CvkFormat.Flags)
            throw new InvalidDataException("CVK 容器标识或版本无效。");
        var metadataLength = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(6, 4));
        var keyBodyLength = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(10, 4));
        if (metadataLength > CvkFormat.MaxSectionLength || keyBodyLength is 0 or > CvkFormat.MaxSectionLength)
            throw new InvalidDataException("CVK 分段长度超出限制。");
        var total = checked((long)CvkFormat.HeaderSize + metadataLength + keyBodyLength + CvkFormat.IntegritySize);
        if (total != data.Length) throw new InvalidDataException("CVK 分段长度与文件大小不一致。");
        var integrityOffset = data.Length - CvkFormat.IntegritySize;
        var expected = SHA256.HashData(data.AsSpan(0, integrityOffset));
        if (!CryptographicOperations.FixedTimeEquals(expected, data.AsSpan(integrityOffset)))
            throw new CryptographicException("CVK 校验体不匹配，文件可能已损坏或被篡改。");
        var metadata = JsonSerializer.Deserialize<CvkMetadataPayload>(
            data.AsSpan(CvkFormat.HeaderSize, (int)metadataLength), CvkJson.Options)
            ?? throw new InvalidDataException("CVK 明文元数据为空。");
        var keyBody = data.AsSpan(CvkFormat.HeaderSize + (int)metadataLength, (int)keyBodyLength).ToArray();
        return new CvkContainer(metadata, keyBody, data.AsSpan(integrityOffset).ToArray());
    }
}

/// <summary>已经验证完整性的 CVK 容器分段。</summary>
internal sealed record CvkContainer(CvkMetadataPayload Metadata, byte[] KeyBody, byte[] Integrity);

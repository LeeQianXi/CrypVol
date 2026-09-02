using System.Buffers.Binary;
using System.Text;
using CrypVol.Lib.Crypto.Models;

namespace CrypVol.Lib.Crypto.Protectors;

/// <summary>公钥密钥体的接收者目录编解码；RSA/ECC 仅负责各自的密文生成与解封。</summary>
internal static class PublicKeyKeyBodyCodec
{
    public const ushort MaxRecipientCiphertextLength = 4096;

    /// <summary>写入统一的接收者目录。</summary>
    public static void WriteRecipients(BinaryWriter writer, IReadOnlyCollection<CvkPublicKeyRecipient> recipients)
    {
        if (recipients.Count == 0 || recipients.Count > ushort.MaxValue)
            throw new InvalidOperationException("接收者数量必须在 1–65535 之间。");
        writer.Write(BinaryPrimitives.ReverseEndianness((ushort)recipients.Count));
        foreach (var recipient in recipients)
        {
            var id = Encoding.UTF8.GetBytes(recipient.KeyId);
            if (id.Length is 0 or > byte.MaxValue) throw new InvalidOperationException("接收者标识长度无效。");
            if (recipient.EncryptedDek.Length is 0 or > MaxRecipientCiphertextLength)
                throw new InvalidOperationException("接收者 DEK 密文长度无效。");
            writer.Write((byte)id.Length); writer.Write(id);
            writer.Write(BinaryPrimitives.ReverseEndianness((ushort)recipient.EncryptedDek.Length));
            writer.Write(recipient.EncryptedDek);
        }
    }

    /// <summary>读取并严格校验接收者目录。</summary>
    public static List<CvkPublicKeyRecipient> ReadRecipients(BinaryReader reader, long end, string label)
    {
        var count = BinaryPrimitives.ReverseEndianness(ReadUInt16(reader, end, $"{label}接收者数量"));
        if (count == 0) throw new InvalidDataException($"{label} CVK 至少需要一个接收者。");
        var result = new List<CvkPublicKeyRecipient>(count);
        for (var i = 0; i < count; i++)
        {
            var idLength = ReadByte(reader, end, "接收者标识长度");
            if (idLength == 0) throw new InvalidDataException("接收者标识不能为空。");
            var keyId = Encoding.UTF8.GetString(ReadExact(reader, idLength, end, "接收者标识"));
            var length = BinaryPrimitives.ReverseEndianness(ReadUInt16(reader, end, "DEK 密文长度"));
            if (length == 0 || length > MaxRecipientCiphertextLength)
                throw new InvalidDataException("DEK 密文长度无效。");
            result.Add(new CvkPublicKeyRecipient(keyId, ReadExact(reader, length, end, "DEK 密文")));
        }
        return result;
    }

    private static byte[] ReadExact(BinaryReader reader, int count, long end, string field)
    {
        if (reader.BaseStream.Position > end - count) throw new InvalidDataException($"CVK {field}超出边界。");
        var value = reader.ReadBytes(count);
        if (value.Length != count) throw new InvalidDataException($"CVK {field}长度不足。");
        return value;
    }

    private static byte ReadByte(BinaryReader reader, long end, string field) => ReadExact(reader, 1, end, field)[0];
    private static ushort ReadUInt16(BinaryReader reader, long end, string field) =>
        BinaryPrimitives.ReadUInt16LittleEndian(ReadExact(reader, 2, end, field));
}

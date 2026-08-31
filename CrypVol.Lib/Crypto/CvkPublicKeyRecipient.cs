namespace CrypVol.Lib.Crypto;

/// <summary>CVK 公钥模式中的接收者槽位；可在没有原始公钥文件时保留或移除。</summary>
public sealed class CvkPublicKeyRecipient
{
    internal CvkPublicKeyRecipient(string keyId, byte[] encryptedDek)
    {
        KeyId = keyId;
        EncryptedDek = encryptedDek;
    }

    /// <summary>接收者标识。</summary>
    public string KeyId { get; }

    /// <summary>由该接收者公钥包裹的 DEK。</summary>
    public byte[] EncryptedDek { get; }
}

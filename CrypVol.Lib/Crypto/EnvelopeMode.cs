namespace CrypVol.Lib.Crypto;

public enum EnvelopeMode : byte
{
    Plain = 0x00,
    Password = 0x01,
    PublicKey = 0x02,
    EccPublicKey = 0x03
}

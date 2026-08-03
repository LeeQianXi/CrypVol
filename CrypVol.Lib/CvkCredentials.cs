namespace CrypVol.Lib;

public sealed record CvkCredentials(EncryptionMode EncryptionMode, byte[] Cek);
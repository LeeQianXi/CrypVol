namespace CrypVol.Lib.Crypto;

/// <summary>进入处理引擎的轻量加密凭据，仅携带运行所需的模式与 CEK。</summary>
/// <param name="EncryptionMode">内容加密模式。</param>
/// <param name="Cek">内容加密密钥。</param>
public sealed record CvkCredentials(EncryptionMode EncryptionMode, byte[] Cek);
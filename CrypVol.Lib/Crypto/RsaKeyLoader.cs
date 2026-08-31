using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;
using Renci.SshNet;
using Renci.SshNet.Common;
using SshRsaKey = Renci.SshNet.Security.RsaKey;

namespace CrypVol.Lib.Crypto;

/// <summary>加载 CVK 公钥模式所需的 RSA 密钥，兼容 PEM 与 OpenSSH 文本格式。</summary>
public static class RsaKeyLoader
{
    /// <summary>加载 RSA 公钥。</summary>
    /// <param name="keyText">PEM 或 <c>ssh-rsa</c> 单行公钥内容。</param>
    /// <returns>可用于 RSA-OAEP 加密的公钥实例。</returns>
    public static RSA LoadPublicKey(string keyText)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyText);
        if (TryLoadPemPublicKey(keyText, out var rsa)) return rsa;

        var fields = keyText.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (fields.Length < 2 || !string.Equals(fields[0], "ssh-rsa", StringComparison.Ordinal))
            throw new CryptographicException("不支持的公钥格式。请提供 RSA PEM 或 OpenSSH ssh-rsa 公钥。");

        try
        {
            var parameters = OpenSshPublicKeyUtilities.ParsePublicKey(Convert.FromBase64String(fields[1]));
            if (parameters is not RsaKeyParameters rsaParameters || rsaParameters.IsPrivate)
                throw new CryptographicException("公钥不是 RSA 密钥。");
            return CreateRsa(rsaParameters);
        }
        catch (FormatException exception)
        {
            throw new CryptographicException("OpenSSH 公钥的 Base64 内容无效。", exception);
        }
    }

    /// <summary>加载 RSA 私钥。</summary>
    /// <param name="keyText">PEM、OpenSSH、ssh.com 或 PuTTY 私钥内容。</param>
    /// <param name="password">加密私钥的密码。</param>
    /// <returns>可用于 RSA-OAEP 解密的私钥实例。</returns>
    public static RSA LoadPrivateKey(string keyText, string? password = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyText);
        if (TryLoadPemPrivateKey(keyText, password, out var rsa)) return rsa;
        if (string.IsNullOrEmpty(password) && TryLoadUnencryptedOpenSshPrivateKey(keyText, out rsa)) return rsa;

        try
        {
            using var stream = new MemoryStream(Encoding.UTF8.GetBytes(keyText), writable: false);
            using var privateKeyFile = new PrivateKeyFile(stream, password);
            if (privateKeyFile.Key is not SshRsaKey sshRsaKey)
                throw new CryptographicException("私钥不是 RSA 密钥。");
            return CreateRsa(sshRsaKey);
        }
        catch (SshException exception)
        {
            throw new CryptographicException("私钥格式无效，或 --key-pass 不正确。", exception);
        }
        catch (NotSupportedException exception)
        {
            throw new CryptographicException("不支持的私钥格式或算法。仅支持 RSA 私钥。", exception);
        }
        catch (ArgumentException exception)
        {
            throw new CryptographicException("私钥格式无效，或 --key-pass 不正确。", exception);
        }
    }

    private static bool TryLoadPemPublicKey(string keyText, out RSA rsa)
    {
        rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(keyText);
            return true;
        }
        catch (ArgumentException)
        {
            rsa.Dispose();
            rsa = null!;
            return false;
        }
    }

    private static bool TryLoadPemPrivateKey(string keyText, string? password, out RSA rsa)
    {
        rsa = RSA.Create();
        try
        {
            if (string.IsNullOrEmpty(password)) rsa.ImportFromPem(keyText);
            else rsa.ImportFromEncryptedPem(keyText, password);
            return true;
        }
        catch (ArgumentException)
        {
            rsa.Dispose();
            rsa = null!;
            return false;
        }
        catch (CryptographicException)
        {
            rsa.Dispose();
            rsa = null!;
            return false;
        }
    }

    private static bool TryLoadUnencryptedOpenSshPrivateKey(string keyText, out RSA rsa)
    {
        rsa = null!;
        if (!keyText.Contains("-----BEGIN OPENSSH PRIVATE KEY-----", StringComparison.Ordinal)) return false;

        try
        {
            using var reader = new StringReader(keyText);
            var pem = new PemReader(reader).ReadPemObject();
            if (pem is null) return false;
            var parameters = OpenSshPrivateKeyUtilities.ParsePrivateKeyBlob(pem.Content);
            if (parameters is not RsaPrivateCrtKeyParameters rsaParameters) return false;
            rsa = CreateRsa(rsaParameters);
            return true;
        }
        catch (IOException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    private static RSA CreateRsa(RsaKeyParameters parameters)
    {
        var rsa = RSA.Create();
        rsa.ImportParameters(DotNetUtilities.ToRSAParameters(parameters));
        return rsa;
    }

    private static RSA CreateRsa(RsaPrivateCrtKeyParameters parameters)
    {
        var rsa = RSA.Create();
        rsa.ImportParameters(DotNetUtilities.ToRSAParameters(parameters));
        return rsa;
    }

    private static RSA CreateRsa(SshRsaKey key)
    {
        var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters
        {
            Modulus = ToUnsignedBigEndian(key.Modulus),
            Exponent = ToUnsignedBigEndian(key.Exponent),
            D = ToUnsignedBigEndian(key.D),
            P = ToUnsignedBigEndian(key.P),
            Q = ToUnsignedBigEndian(key.Q),
            DP = ToUnsignedBigEndian(key.DP),
            DQ = ToUnsignedBigEndian(key.DQ),
            InverseQ = ToUnsignedBigEndian(key.InverseQ)
        });
        return rsa;
    }

    private static byte[] ToUnsignedBigEndian(System.Numerics.BigInteger value)
    {
        return value.ToByteArray(isUnsigned: true, isBigEndian: true);
    }
}

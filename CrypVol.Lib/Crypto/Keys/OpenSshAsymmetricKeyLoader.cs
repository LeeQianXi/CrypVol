using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using CrypVol.Lib.Utility;
using Renci.SshNet;
using Renci.SshNet.Security;

namespace CrypVol.Lib.Crypto.Keys;

/// <summary>只解析 OpenSSH authorized_keys 公钥文件和 OpenSSH 私钥封装。</summary>
public sealed class OpenSshAsymmetricKeyLoader : StaticSingleton<OpenSshAsymmetricKeyLoader>, IAsymmetricKeyLoader
{
    /// <inheritdoc />
    public bool LoadPublicKey(FileInfo file, out AsymmetricPublicKeyMaterial key, string? keyId = null)
    {
        ArgumentNullException.ThrowIfNull(file);
        if (!file.Exists) throw new FileNotFoundException("密钥文件不存在。", file.FullName);
        key = null!;
        try
        {
            var line = File.ReadLines(file.FullName).Select(static x => x.Trim())
                .FirstOrDefault(static x => x.Length > 0 && !x.StartsWith('#'));
            if (line is null) return false;
            var fields = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length < 2 || !string.Equals(fields[0], "ssh-rsa", StringComparison.Ordinal)) return false;
            var blob = Convert.FromBase64String(fields[1]);
            var offset = 0;
            if (!ReadField(blob, ref offset).SequenceEqual("ssh-rsa"u8)) return false;
            var exponent = NormalizeMpint(ReadField(blob, ref offset));
            var modulus = NormalizeMpint(ReadField(blob, ref offset));
            if (offset != blob.Length || exponent.Length == 0 || modulus.Length == 0) return false;
            var rsa = RSA.Create();
            rsa.ImportParameters(new RSAParameters
            {
                Exponent = exponent,
                Modulus = modulus
            });
            var resolvedId = !string.IsNullOrWhiteSpace(keyId) ? keyId!
                : fields.Length >= 3 ? string.Join(' ', fields[2..]) : Path.GetFileNameWithoutExtension(file.Name);
            key = new AsymmetricPublicKeyMaterial(resolvedId, "RSA", rsa);
            return true;
        }
        catch (FileNotFoundException) { throw; }
        catch (Exception)
        {
            key = null!;
            return false;
        }
    }

    /// <inheritdoc />
    public bool LoadPrivateKey(FileInfo file, out AsymmetricPrivateKeyMaterial key, string? password = null,
        string? keyId = null)
    {
        ArgumentNullException.ThrowIfNull(file);
        if (!file.Exists) throw new FileNotFoundException("密钥文件不存在。", file.FullName);
        key = null!;
        if (!File.ReadLines(file.FullName).Any(static line => line.Contains("OPENSSH PRIVATE KEY", StringComparison.Ordinal)))
            return false;
        try
        {
            using var source = password is null
                ? new PrivateKeyFile(file.FullName)
                : new PrivateKeyFile(file.FullName, password);
            if (source.Key is not RsaKey rsaKey) return false;
            var rsa = RSA.Create();
            rsa.ImportParameters(new RSAParameters
            {
                Modulus = ToUnsignedBigEndian(rsaKey.Modulus),
                Exponent = ToUnsignedBigEndian(rsaKey.Exponent),
                D = ToUnsignedBigEndian(rsaKey.D),
                P = ToUnsignedBigEndian(rsaKey.P),
                Q = ToUnsignedBigEndian(rsaKey.Q),
                DP = ToUnsignedBigEndian(rsaKey.DP),
                DQ = ToUnsignedBigEndian(rsaKey.DQ),
                InverseQ = ToUnsignedBigEndian(rsaKey.InverseQ)
            });
            key = new AsymmetricPrivateKeyMaterial(
                string.IsNullOrWhiteSpace(keyId) ? Path.GetFileNameWithoutExtension(file.Name) : keyId!, "RSA", rsa);
            return true;
        }
        catch (Exception)
        {
            key = null!;
            return false;
        }
    }

    private static ReadOnlySpan<byte> ReadField(ReadOnlySpan<byte> blob, ref int offset)
    {
        if (offset > blob.Length - 4) throw new FormatException();
        var length = BinaryPrimitives.ReadUInt32BigEndian(blob[offset..]);
        offset += 4;
        if (length > int.MaxValue || offset > blob.Length - (int)length) throw new FormatException();
        var value = blob.Slice(offset, (int)length);
        offset += (int)length;
        return value;
    }

    private static byte[] NormalizeMpint(ReadOnlySpan<byte> value)
    {
        while (value.Length > 1 && value[0] == 0) value = value[1..];
        return value.ToArray();
    }

    private static byte[] ToUnsignedBigEndian(BigInteger value)
    {
        return value.ToByteArray(true, true);
    }
}
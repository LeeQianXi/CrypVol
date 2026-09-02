using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CrypVol.Lib.Crypto.Keys;
using Xunit;

namespace CrypVol.Tests;

/// <summary>覆盖 CVK 使用的公私钥文件加载、格式拒绝和密码校验。</summary>
public sealed class CvkKeyLoaderTests
{
    [Fact]
    public void KeyLoaders_RejectNullFile()
    {
        Assert.Throws<ArgumentNullException>(() => AsymmetricKeyFileLoader.LoadPublicKey(null!));
        Assert.Throws<ArgumentNullException>(() => AsymmetricKeyFileLoader.LoadPrivateKey(null!));
    }

    [Fact]
    public void RsaPublicKey_LoadsWithFilenameKeyId()
    {
        using var rsa = RSA.Create(2048);
        var file = Temp("receiver.pub");
        try
        {
            File.WriteAllText(file.FullName, rsa.ExportSubjectPublicKeyInfoPem());
            using var material = AsymmetricKeyFileLoader.LoadPublicKey(file);
            Assert.Equal(Path.GetFileNameWithoutExtension(file.Name), material.KeyId);
            Assert.Equal("RSA", material.Algorithm);
            Assert.NotEmpty(material.PublicKeyBytes);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public void PublicKey_CustomKeyIdOverridesFilename()
    {
        using var rsa = RSA.Create(2048);
        var file = Temp("receiver.pub");
        try
        {
            File.WriteAllText(file.FullName, rsa.ExportSubjectPublicKeyInfoPem());
            using var material = AsymmetricKeyFileLoader.LoadPublicKey(file, "custom-id");
            Assert.Equal("custom-id", material.KeyId);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public void BlankCustomKeyId_FallsBackToFilename()
    {
        using var rsa = RSA.Create(2048);
        var file = Temp("fallback.pub");
        try
        {
            File.WriteAllText(file.FullName, rsa.ExportSubjectPublicKeyInfoPem());
            using var material = AsymmetricKeyFileLoader.LoadPublicKey(file, "   ");
            Assert.Equal("fallback", material.KeyId);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public void InvalidAndMissingKeyFiles_AreRejected()
    {
        var file = Temp("invalid.pem");
        try
        {
            File.WriteAllText(file.FullName, "not a key");
            Assert.Throws<AsymmetricKeyFileFormatException>(() => AsymmetricKeyFileLoader.LoadPublicKey(file));
            Assert.Throws<AsymmetricKeyFileFormatException>(() => AsymmetricKeyFileLoader.LoadPrivateKey(file));
        }
        finally { if (file.Exists) file.Delete(); }
        Assert.Throws<FileNotFoundException>(() => AsymmetricKeyFileLoader.LoadPublicKey(new FileInfo(file.FullName)));
    }

    [Fact]
    public void EmptyWhitespaceAndBinaryKeyFiles_AreRejected()
    {
        foreach (var content in new[] { Array.Empty<byte>(), System.Text.Encoding.UTF8.GetBytes("   \n\t"), new byte[] { 0xFF, 0xFE, 0x00 } })
        {
            var file = Temp("invalid-content.pem");
            try
            {
                File.WriteAllBytes(file.FullName, content);
                Assert.ThrowsAny<Exception>(() => AsymmetricKeyFileLoader.LoadPublicKey(file));
                Assert.ThrowsAny<Exception>(() => AsymmetricKeyFileLoader.LoadPrivateKey(file));
            }
            finally { if (file.Exists) file.Delete(); }
        }
    }

    [Fact]
    public void PublicLoader_RejectsPrivateKey()
    {
        using var rsa = RSA.Create(2048);
        var file = Temp("private.pem");
        try
        {
            File.WriteAllText(file.FullName, rsa.ExportPkcs8PrivateKeyPem());
            Assert.Throws<AsymmetricKeyFileFormatException>(() => AsymmetricKeyFileLoader.LoadPublicKey(file));
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public void EncryptedPrivateKey_RequiresCorrectPassword()
    {
        using var rsa = RSA.Create(2048);
        var file = Temp("private.pem");
        try
        {
            var pbe = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100_000);
            File.WriteAllText(file.FullName, rsa.ExportEncryptedPkcs8PrivateKeyPem("secret", pbe));
            using var material = AsymmetricKeyFileLoader.LoadPrivateKey(file, "secret");
            Assert.Equal("RSA", material.Algorithm);
            Assert.Throws<AsymmetricKeyFileFormatException>(() => AsymmetricKeyFileLoader.LoadPrivateKey(file));
            Assert.Throws<AsymmetricKeyFileFormatException>(() => AsymmetricKeyFileLoader.LoadPrivateKey(file, "wrong"));
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public void RsaPkcs1PrivateKey_Loads()
    {
        using var rsa = RSA.Create(2048);
        var file = Temp("rsa-pkcs1.pem");
        try
        {
            File.WriteAllText(file.FullName, rsa.ExportRSAPrivateKeyPem());
            using var material = AsymmetricKeyFileLoader.LoadPrivateKey(file);
            Assert.Equal("RSA", material.Algorithm);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public void EcdsaPublicAndPrivateKeys_Load()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicFile = Temp("ecdsa.pub");
        var privateFile = Temp("ecdsa.pem");
        try
        {
            File.WriteAllText(publicFile.FullName, ecdsa.ExportSubjectPublicKeyInfoPem());
            File.WriteAllText(privateFile.FullName, ecdsa.ExportECPrivateKeyPem());
            using var publicMaterial = AsymmetricKeyFileLoader.LoadPublicKey(publicFile);
            using var privateMaterial = AsymmetricKeyFileLoader.LoadPrivateKey(privateFile);
            Assert.Equal("ECDSA", publicMaterial.Algorithm);
            Assert.Equal("ECDSA", privateMaterial.Algorithm);
        }
        finally { if (publicFile.Exists) publicFile.Delete(); if (privateFile.Exists) privateFile.Delete(); }
    }

    [Fact]
    public void EcdhPrivateKey_IsRecognizedAsEcdh()
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var file = Temp("ecdh.pem");
        try
        {
            File.WriteAllText(file.FullName, ecdh.ExportPkcs8PrivateKeyPem());
            using var material = AsymmetricKeyFileLoader.LoadPrivateKey(file);
            Assert.Equal("ECDH", material.Algorithm);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public void EcdhPublicKey_LoadsAsEcdh()
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var file = Temp("ecdh.pub");
        try
        {
            File.WriteAllText(file.FullName, ecdh.ExportSubjectPublicKeyInfoPem());
            using var material = AsymmetricKeyFileLoader.LoadPublicKey(file);
            Assert.Equal("ECDH", material.Algorithm);
            Assert.NotEmpty(material.PublicKeyBytes);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public void EncryptedEcPrivateKey_LoadsWithPassword()
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var file = Temp("ecdh-encrypted.pem");
        try
        {
            var pbe = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100_000);
            File.WriteAllText(file.FullName, ecdh.ExportEncryptedPkcs8PrivateKeyPem("secret", pbe));
            using var material = AsymmetricKeyFileLoader.LoadPrivateKey(file, "secret");
            Assert.Equal("ECDH", material.Algorithm);
            Assert.Throws<AsymmetricKeyFileFormatException>(() => AsymmetricKeyFileLoader.LoadPrivateKey(file, "wrong"));
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public void RsaCertificatePublicKey_Loads()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=CVK-Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(5));
        var file = Temp("certificate.pem");
        try
        {
            File.WriteAllText(file.FullName, certificate.ExportCertificatePem());
            using var material = AsymmetricKeyFileLoader.LoadPublicKey(file);
            Assert.Equal("RSA", material.Algorithm);
            Assert.NotEmpty(material.PublicKeyBytes);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public void EcdsaCertificatePublicKey_Loads()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=CVK-ECDSA", ecdsa, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(5));
        var file = Temp("ecdsa-certificate.pem");
        try
        {
            File.WriteAllText(file.FullName, certificate.ExportCertificatePem());
            using var material = AsymmetricKeyFileLoader.LoadPublicKey(file);
            Assert.Equal("ECDSA", material.Algorithm);
            Assert.NotEmpty(material.PublicKeyBytes);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    private static FileInfo Temp(string name) => new(Path.Combine(Path.GetTempPath(), $"cvk-{Guid.NewGuid():N}-{name}"));
}

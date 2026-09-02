using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CrypVol.Lib.Crypto.Keys;
using Xunit;

namespace CrypVol.Tests;

/// <summary>覆盖 CVK 使用的公私钥文件加载、格式拒绝和密码校验。</summary>
public sealed class CvkKeyLoaderTests
{
    [Fact]
    public void KeyLoaders_RejectNullFile()
    {
        Assert.Throws<ArgumentNullException>(() => AsymmetricKeyLoaderManager.Instance.LoadPublicKey(null!, out _));
        Assert.Throws<ArgumentNullException>(() => AsymmetricKeyLoaderManager.Instance.LoadPrivateKey(null!, out _));
    }

    [Fact]
    public void PrivateKeyMaterial_DisposeReleasesKeyButPreservesMetadata()
    {
        using var rsa = RSA.Create(2048);
        var file = Temp("dispose.pem");
        try
        {
            File.WriteAllText(file.FullName, rsa.ExportPkcs8PrivateKeyPem());
            Assert.True(AsymmetricKeyLoaderManager.Instance.LoadPrivateKey(file, out var material, keyId: "dispose-test"));
            var publicBytes = material.PublicKeyBytes.ToArray();
            material.Dispose();
            material.Dispose();

            Assert.Equal("dispose-test", material.KeyId);
            Assert.Equal("RSA", material.Algorithm);
            Assert.Equal(publicBytes, material.PublicKeyBytes);
            Assert.Throws<ObjectDisposedException>(() => ((RSA)material.Key).ExportParameters(false));
        }
        finally
        {
            if (file.Exists) file.Delete();
        }
    }

    [Fact]
    public void PublicKeyMaterial_DisposeReleasesKeyButPreservesMetadata()
    {
        using var rsa = RSA.Create(2048);
        var file = Temp("dispose.pub");
        try
        {
            File.WriteAllText(file.FullName, rsa.ExportSubjectPublicKeyInfoPem());
            Assert.True(AsymmetricKeyLoaderManager.Instance.LoadPublicKey(file, out var material, "public-dispose-test"));
            var publicBytes = material.PublicKeyBytes.ToArray();
            material.Dispose();
            material.Dispose();

            Assert.Equal("public-dispose-test", material.KeyId);
            Assert.Equal("RSA", material.Algorithm);
            Assert.Equal(publicBytes, material.PublicKeyBytes);
            Assert.Throws<ObjectDisposedException>(() => ((RSA)material.Key).ExportParameters(false));
        }
        finally
        {
            if (file.Exists) file.Delete();
        }
    }

    [Fact]
    public void PublicAndPrivateLoaders_ProduceIdenticalPublicKeyBytes()
    {
        using var rsa = RSA.Create(2048);
        var publicFile = Temp("same-key.pub");
        var privateFile = Temp("same-key.pem");
        try
        {
            File.WriteAllText(publicFile.FullName, rsa.ExportSubjectPublicKeyInfoPem());
            File.WriteAllText(privateFile.FullName, rsa.ExportPkcs8PrivateKeyPem());
            Assert.True(AsymmetricKeyLoaderManager.Instance.LoadPublicKey(publicFile, out var publicMaterial, "same"));
            Assert.True(AsymmetricKeyLoaderManager.Instance.LoadPrivateKey(privateFile, out var privateMaterial,
                keyId: "same"));
            using (publicMaterial)
            using (privateMaterial)
            {
                Assert.Equal(publicMaterial.Algorithm, privateMaterial.Algorithm);
                Assert.Equal(publicMaterial.PublicKeyBytes, privateMaterial.PublicKeyBytes);
            }
        }
        finally
        {
            if (publicFile.Exists) publicFile.Delete();
            if (privateFile.Exists) privateFile.Delete();
        }
    }

    [Fact]
    public void EcdhPublicAndPrivateLoaders_ProduceIdenticalPublicKeyBytes()
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var publicFile = Temp("same-ecdh.pub");
        var privateFile = Temp("same-ecdh.pem");
        try
        {
            File.WriteAllText(publicFile.FullName, ecdh.ExportSubjectPublicKeyInfoPem());
            File.WriteAllText(privateFile.FullName, ecdh.ExportPkcs8PrivateKeyPem());
            Assert.True(AsymmetricKeyLoaderManager.Instance.LoadPublicKey(publicFile, out var publicMaterial, "same-ecdh"));
            Assert.True(AsymmetricKeyLoaderManager.Instance.LoadPrivateKey(privateFile, out var privateMaterial,
                keyId: "same-ecdh"));
            using (publicMaterial)
            using (privateMaterial)
            {
                Assert.Equal("ECDH", publicMaterial.Algorithm);
                Assert.Equal("ECDH", privateMaterial.Algorithm);
                Assert.Equal(publicMaterial.PublicKeyBytes, privateMaterial.PublicKeyBytes);
            }
        }
        finally
        {
            if (publicFile.Exists) publicFile.Delete();
            if (privateFile.Exists) privateFile.Delete();
        }
    }

    [Fact]
    public void RsaPublicKey_LoadsWithFilenameKeyId()
    {
        using var rsa = RSA.Create(2048);
        var file = Temp("receiver.pub");
        try
        {
            File.WriteAllText(file.FullName, rsa.ExportSubjectPublicKeyInfoPem());
            Assert.True(AsymmetricKeyLoaderManager.Instance.LoadPublicKey(file, out var material));
            using var materialLease = material;
            Assert.Equal(Path.GetFileNameWithoutExtension(file.Name), material.KeyId);
            Assert.Equal("RSA", material.Algorithm);
            Assert.NotEmpty(material.PublicKeyBytes);
        }
        finally
        {
            if (file.Exists) file.Delete();
        }
    }

    [Fact]
    public void PublicKey_KeyIdPreservesEarlierFilenameExtensions()
    {
        using var rsa = RSA.Create(2048);
        var file = Temp("team.prod.pub");
        try
        {
            File.WriteAllText(file.FullName, rsa.ExportSubjectPublicKeyInfoPem());
            Assert.True(AsymmetricKeyLoaderManager.Instance.LoadPublicKey(file, out var material));
            using var materialLease = material;
            Assert.Equal(Path.GetFileNameWithoutExtension(file.Name), material.KeyId);
        }
        finally
        {
            if (file.Exists) file.Delete();
        }
    }

    [Fact]
    public void RsaPublicKey_WithUtf8Bom_Loads()
    {
        using var rsa = RSA.Create(2048);
        var file = Temp("receiver-bom.pub");
        try
        {
            var pem = Encoding.UTF8.GetBytes(rsa.ExportSubjectPublicKeyInfoPem());
            File.WriteAllBytes(file.FullName, [.. Encoding.UTF8.GetPreamble(), .. pem]);
            Assert.True(AsymmetricKeyLoaderManager.Instance.LoadPublicKey(file, out var material));
            using var materialLease = material;
            Assert.Equal("RSA", material.Algorithm);
            Assert.NotEmpty(material.PublicKeyBytes);
        }
        finally
        {
            if (file.Exists) file.Delete();
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void RsaPublicKey_PemLineEndingVariants_Load(bool crlf)
    {
        using var rsa = RSA.Create(2048);
        var file = Temp(crlf ? "receiver-crlf.pub" : "receiver-no-final-newline.pub");
        try
        {
            var pem = rsa.ExportSubjectPublicKeyInfoPem();
            pem = crlf ? pem.Replace("\n", "\r\n", StringComparison.Ordinal) : pem.TrimEnd('\r', '\n');
            File.WriteAllText(file.FullName, pem);
            Assert.True(AsymmetricKeyLoaderManager.Instance.LoadPublicKey(file, out var material));
            using var materialLease = material;
            Assert.Equal("RSA", material.Algorithm);
        }
        finally
        {
            if (file.Exists) file.Delete();
        }
    }

    [Fact]
    public void PublicKey_CustomKeyIdOverridesFilename()
    {
        using var rsa = RSA.Create(2048);
        var file = Temp("receiver.pub");
        try
        {
            File.WriteAllText(file.FullName, rsa.ExportSubjectPublicKeyInfoPem());
            Assert.True(AsymmetricKeyLoaderManager.Instance.LoadPublicKey(file, out var material, "custom-id"));
            using var materialLease = material;
            Assert.Equal("custom-id", material.KeyId);
        }
        finally
        {
            if (file.Exists) file.Delete();
        }
    }

    [Fact]
    public void BlankCustomKeyId_FallsBackToFilename()
    {
        using var rsa = RSA.Create(2048);
        var file = Temp("fallback.pub");
        try
        {
            File.WriteAllText(file.FullName, rsa.ExportSubjectPublicKeyInfoPem());
            Assert.True(AsymmetricKeyLoaderManager.Instance.LoadPublicKey(file, out var material, "   "));
            using var materialLease = material;
            Assert.Equal(Path.GetFileNameWithoutExtension(file.Name), material.KeyId);
        }
        finally
        {
            if (file.Exists) file.Delete();
        }
    }

    [Fact]
    public void PrivateKey_BlankCustomKeyId_FallsBackToFilename()
    {
        using var rsa = RSA.Create(2048);
        var file = Temp("private-fallback.pem");
        try
        {
            var pem = Encoding.UTF8.GetBytes(rsa.ExportPkcs8PrivateKeyPem());
            File.WriteAllBytes(file.FullName, [.. Encoding.UTF8.GetPreamble(), .. pem]);
            Assert.True(AsymmetricKeyLoaderManager.Instance.LoadPrivateKey(file, out var material, keyId: "\t"));
            using var materialLease = material;
            Assert.Equal(Path.GetFileNameWithoutExtension(file.Name), material.KeyId);
        }
        finally
        {
            if (file.Exists) file.Delete();
        }
    }

    [Fact]
    public void PrivateKey_KeyIdPreservesEarlierFilenameExtensions()
    {
        using var rsa = RSA.Create(2048);
        var file = Temp("team.prod.pem");
        try
        {
            File.WriteAllText(file.FullName, rsa.ExportPkcs8PrivateKeyPem());
            Assert.True(AsymmetricKeyLoaderManager.Instance.LoadPrivateKey(file, out var material));
            using var materialLease = material;
            Assert.Equal(Path.GetFileNameWithoutExtension(file.Name), material.KeyId);
        }
        finally
        {
            if (file.Exists) file.Delete();
        }
    }

    [Fact]
    public void InvalidAndMissingKeyFiles_AreRejected()
    {
        var file = Temp("invalid.pem");
        try
        {
            File.WriteAllText(file.FullName, "not a key");
            Assert.False(AsymmetricKeyLoaderManager.Instance.LoadPublicKey(file, out _));
            Assert.False(AsymmetricKeyLoaderManager.Instance.LoadPrivateKey(file, out _));
        }
        finally
        {
            if (file.Exists) file.Delete();
        }

        Assert.Throws<FileNotFoundException>(() =>
            AsymmetricKeyLoaderManager.Instance.LoadPublicKey(new FileInfo(file.FullName), out _));
    }

    [Fact]
    public void EmptyWhitespaceAndBinaryKeyFiles_AreRejected()
    {
        foreach (var content in new[]
                 {
                     Array.Empty<byte>(),
                     Encoding.UTF8.GetBytes("   \n\t"),
                     new byte[]
                     {
                         0xFF, 0xFE, 0x00
                     }
                 })
        {
            var file = Temp("invalid-content.pem");
            try
            {
                File.WriteAllBytes(file.FullName, content);
                Assert.False(AsymmetricKeyLoaderManager.Instance.LoadPublicKey(file, out _));
                Assert.False(AsymmetricKeyLoaderManager.Instance.LoadPrivateKey(file, out _));
            }
            finally
            {
                if (file.Exists) file.Delete();
            }
        }
    }

    [Fact]
    public void KeyLoaders_RejectDirectoryPath()
    {
        var directory = new DirectoryInfo(Path.Combine(Path.GetTempPath(), $"cvk-key-directory-{Guid.NewGuid():N}"));
        directory.Create();
        try
        {
            Assert.ThrowsAny<Exception>(() =>
                AsymmetricKeyLoaderManager.Instance.LoadPublicKey(new FileInfo(directory.FullName), out _));
            Assert.ThrowsAny<Exception>(() =>
                AsymmetricKeyLoaderManager.Instance.LoadPrivateKey(new FileInfo(directory.FullName), out _));
        }
        finally { directory.Delete(); }
    }

    [Fact]
    public void PublicLoader_RejectsPrivateKey()
    {
        using var rsa = RSA.Create(2048);
        var file = Temp("private.pem");
        try
        {
            File.WriteAllText(file.FullName, rsa.ExportPkcs8PrivateKeyPem());
            Assert.False(AsymmetricKeyLoaderManager.Instance.LoadPublicKey(file, out _));
        }
        finally
        {
            if (file.Exists) file.Delete();
        }
    }

    [Fact]
    public void PublicLoader_RejectsMixedPrivateAndPublicPemBlocks()
    {
        using var rsa = RSA.Create(2048);
        var file = Temp("mixed.pem");
        try
        {
            var mixed = rsa.ExportPkcs8PrivateKeyPem() + rsa.ExportSubjectPublicKeyInfoPem();
            File.WriteAllText(file.FullName, mixed);
            Assert.False(AsymmetricKeyLoaderManager.Instance.LoadPublicKey(file, out _));
        }
        finally
        {
            if (file.Exists) file.Delete();
        }
    }

    [Fact]
    public void PrivateLoader_RejectsPublicKey()
    {
        using var rsa = RSA.Create(2048);
        var file = Temp("public-only.pem");
        try
        {
            File.WriteAllText(file.FullName, rsa.ExportSubjectPublicKeyInfoPem());
            Assert.False(AsymmetricKeyLoaderManager.Instance.LoadPrivateKey(file, out _));
        }
        finally
        {
            if (file.Exists) file.Delete();
        }
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
            Assert.True(AsymmetricKeyLoaderManager.Instance.LoadPrivateKey(file, out var material, "secret"));
            using var materialLease = material;
            Assert.Equal("RSA", material.Algorithm);
            Assert.False(AsymmetricKeyLoaderManager.Instance.LoadPrivateKey(file, out _));
            Assert.False(AsymmetricKeyLoaderManager.Instance.LoadPrivateKey(file, out _, "wrong"));
        }
        finally
        {
            if (file.Exists) file.Delete();
        }
    }

    [Fact]
    public void PrivateKey_WithUtf8Bom_Loads()
    {
        using var rsa = RSA.Create(2048);
        var file = Temp("private-bom.pem");
        try
        {
            var pem = Encoding.UTF8.GetBytes(rsa.ExportPkcs8PrivateKeyPem());
            File.WriteAllBytes(file.FullName, [.. Encoding.UTF8.GetPreamble(), .. pem]);
            Assert.True(AsymmetricKeyLoaderManager.Instance.LoadPrivateKey(file, out var material));
            using var materialLease = material;
            Assert.Equal("RSA", material.Algorithm);
            Assert.NotEmpty(material.PublicKeyBytes);
        }
        finally
        {
            if (file.Exists) file.Delete();
        }
    }

    [Fact]
    public void EncryptedPrivateKey_WithUtf8Bom_LoadsWithPassword()
    {
        using var rsa = RSA.Create(2048);
        var file = Temp("encrypted-private-bom.pem");
        try
        {
            var pbe = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100_000);
            var pem = Encoding.UTF8.GetBytes(rsa.ExportEncryptedPkcs8PrivateKeyPem("secret", pbe));
            File.WriteAllBytes(file.FullName, [.. Encoding.UTF8.GetPreamble(), .. pem]);
            Assert.True(AsymmetricKeyLoaderManager.Instance.LoadPrivateKey(file, out var material, "secret"));
            using var materialLease = material;
            Assert.Equal("RSA", material.Algorithm);
        }
        finally
        {
            if (file.Exists) file.Delete();
        }
    }

    [Fact]
    public void UnencryptedPrivateKey_RejectsUnexpectedPassword()
    {
        using var rsa = RSA.Create(2048);
        var file = Temp("unencrypted-private.pem");
        try
        {
            File.WriteAllText(file.FullName, rsa.ExportPkcs8PrivateKeyPem());
            Assert.False(AsymmetricKeyLoaderManager.Instance.LoadPrivateKey(file, out _, "unexpected-password"));
        }
        finally
        {
            if (file.Exists) file.Delete();
        }
    }

    [Fact]
    public void RsaPkcs1PrivateKey_Loads()
    {
        using var rsa = RSA.Create(2048);
        var file = Temp("rsa-pkcs1.pem");
        try
        {
            File.WriteAllText(file.FullName, rsa.ExportRSAPrivateKeyPem());
            Assert.True(AsymmetricKeyLoaderManager.Instance.LoadPrivateKey(file, out var material));
            using var materialLease = material;
            Assert.Equal("RSA", material.Algorithm);
        }
        finally
        {
            if (file.Exists) file.Delete();
        }
    }

    [Fact]
    public void RsaPkcs1PublicKey_Loads()
    {
        using var rsa = RSA.Create(2048);
        var file = Temp("rsa-pkcs1.pub");
        try
        {
            File.WriteAllText(file.FullName, rsa.ExportRSAPublicKeyPem());
            Assert.True(AsymmetricKeyLoaderManager.Instance.LoadPublicKey(file, out var material));
            using var materialLease = material;
            Assert.Equal("RSA", material.Algorithm);
            Assert.NotEmpty(material.PublicKeyBytes);
        }
        finally
        {
            if (file.Exists) file.Delete();
        }
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
            Assert.True(AsymmetricKeyLoaderManager.Instance.LoadPublicKey(publicFile, out var publicMaterial));
            using var publicMaterialLease = publicMaterial;
            Assert.True(AsymmetricKeyLoaderManager.Instance.LoadPrivateKey(privateFile, out var privateMaterial));
            using var privateMaterialLease = privateMaterial;
            Assert.Equal("ECDSA", publicMaterial.Algorithm);
            Assert.Equal("ECDSA", privateMaterial.Algorithm);
        }
        finally
        {
            if (publicFile.Exists) publicFile.Delete();
            if (privateFile.Exists) privateFile.Delete();
        }
    }

    [Theory]
    [InlineData("nistP384")]
    [InlineData("nistP521")]
    public void EcdsaOtherCurves_Load(string curveName)
    {
        var curve = curveName == "nistP384" ? ECCurve.NamedCurves.nistP384 : ECCurve.NamedCurves.nistP521;
        using var ecdsa = ECDsa.Create(curve);
        var publicFile = Temp($"ecdsa-{curveName}.pub");
        var privateFile = Temp($"ecdsa-{curveName}.pem");
        try
        {
            File.WriteAllText(publicFile.FullName, ecdsa.ExportSubjectPublicKeyInfoPem());
            File.WriteAllText(privateFile.FullName, ecdsa.ExportECPrivateKeyPem());
            Assert.True(AsymmetricKeyLoaderManager.Instance.LoadPublicKey(publicFile, out var publicMaterial));
            using var publicMaterialLease = publicMaterial;
            Assert.True(AsymmetricKeyLoaderManager.Instance.LoadPrivateKey(privateFile, out var privateMaterial));
            using var privateMaterialLease = privateMaterial;
            Assert.Equal("ECDSA", publicMaterial.Algorithm);
            Assert.Equal("ECDSA", privateMaterial.Algorithm);
            Assert.Equal(publicMaterial.PublicKeyBytes, privateMaterial.PublicKeyBytes);
        }
        finally
        {
            if (publicFile.Exists) publicFile.Delete();
            if (privateFile.Exists) privateFile.Delete();
        }
    }

    [Fact]
    public void EcdhPrivateKey_IsRecognizedAsEcdh()
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var file = Temp("ecdh.pem");
        try
        {
            File.WriteAllText(file.FullName, ecdh.ExportPkcs8PrivateKeyPem());
            Assert.True(AsymmetricKeyLoaderManager.Instance.LoadPrivateKey(file, out var material));
            using var materialLease = material;
            Assert.Equal("ECDH", material.Algorithm);
        }
        finally
        {
            if (file.Exists) file.Delete();
        }
    }

    [Fact]
    public void EcdhPublicKey_LoadsAsEcdh()
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var file = Temp("ecdh.pub");
        try
        {
            File.WriteAllText(file.FullName, ecdh.ExportSubjectPublicKeyInfoPem());
            Assert.True(AsymmetricKeyLoaderManager.Instance.LoadPublicKey(file, out var material));
            using var materialLease = material;
            Assert.Equal("ECDH", material.Algorithm);
            Assert.NotEmpty(material.PublicKeyBytes);
        }
        finally
        {
            if (file.Exists) file.Delete();
        }
    }

    [Theory]
    [InlineData("nistP384")]
    [InlineData("nistP521")]
    public void EcdhOtherCurves_LoadAsEcdh(string curveName)
    {
        var curve = curveName == "nistP384" ? ECCurve.NamedCurves.nistP384 : ECCurve.NamedCurves.nistP521;
        using var ecdh = ECDiffieHellman.Create(curve);
        var publicFile = Temp($"ecdh-{curveName}.pub");
        var privateFile = Temp($"ecdh-{curveName}.pem");
        try
        {
            File.WriteAllText(publicFile.FullName, ecdh.ExportSubjectPublicKeyInfoPem());
            File.WriteAllText(privateFile.FullName, ecdh.ExportPkcs8PrivateKeyPem());
            Assert.True(AsymmetricKeyLoaderManager.Instance.LoadPublicKey(publicFile, out var publicMaterial));
            using var publicMaterialLease = publicMaterial;
            Assert.True(AsymmetricKeyLoaderManager.Instance.LoadPrivateKey(privateFile, out var privateMaterial));
            using var privateMaterialLease = privateMaterial;
            Assert.Equal("ECDH", publicMaterial.Algorithm);
            Assert.Equal("ECDH", privateMaterial.Algorithm);
        }
        finally
        {
            if (publicFile.Exists) publicFile.Delete();
            if (privateFile.Exists) privateFile.Delete();
        }
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
            Assert.True(AsymmetricKeyLoaderManager.Instance.LoadPrivateKey(file, out var material, "secret"));
            using var materialLease = material;
            Assert.Equal("ECDH", material.Algorithm);
            Assert.False(AsymmetricKeyLoaderManager.Instance.LoadPrivateKey(file, out _, "wrong"));
        }
        finally
        {
            if (file.Exists) file.Delete();
        }
    }

    [Fact]
    public void EncryptedEcdsaPrivateKey_LoadsWithPassword()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var file = Temp("ecdsa-encrypted.pem");
        try
        {
            var pbe = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100_000);
            File.WriteAllText(file.FullName, ecdsa.ExportEncryptedPkcs8PrivateKeyPem("secret", pbe));
            Assert.True(AsymmetricKeyLoaderManager.Instance.LoadPrivateKey(file, out var material, "secret"));
            using var materialLease = material;
            Assert.Equal("ECDSA", material.Algorithm);
            Assert.False(AsymmetricKeyLoaderManager.Instance.LoadPrivateKey(file, out _, "wrong"));
        }
        finally
        {
            if (file.Exists) file.Delete();
        }
    }

    [Fact]
    public void RsaCertificatePublicKey_Loads()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=CVK-Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate =
            request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(5));
        var file = Temp("certificate.pem");
        try
        {
            File.WriteAllText(file.FullName, certificate.ExportCertificatePem());
            Assert.True(AsymmetricKeyLoaderManager.Instance.LoadPublicKey(file, out var material));
            using var materialLease = material;
            Assert.Equal("RSA", material.Algorithm);
            Assert.NotEmpty(material.PublicKeyBytes);
        }
        finally
        {
            if (file.Exists) file.Delete();
        }
    }

    [Fact]
    public void OpenSshRsaPublicKey_LoadsAuthorizedKeysFormat()
    {
        using var rsa = RSA.Create(2048);
        var file = Temp("authorized_keys");
        try
        {
            File.WriteAllText(file.FullName,
                $"ssh-rsa {Convert.ToBase64String(BuildOpenSshRsaBlob(rsa.ExportParameters(false)))} user@example.com\n");
            Assert.True(AsymmetricKeyLoaderManager.Instance.LoadPublicKey(file, out var material));
            using var materialLease = material;
            Assert.Equal("RSA", material.Algorithm);
            Assert.NotEmpty(material.PublicKeyBytes);
        }
        finally
        {
            if (file.Exists) file.Delete();
        }
    }

    [Fact]
    public void OpenSshCommentEmail_IsUsedAsKeyId()
    {
        using var rsa = RSA.Create(2048);
        var file = Temp("authorized_keys");
        try
        {
            var blob = Convert.ToBase64String(BuildOpenSshRsaBlob(rsa.ExportParameters(false)));
            File.WriteAllText(file.FullName, $"ssh-rsa {blob} alice@example.com\n");
            Assert.True(AsymmetricKeyLoaderManager.Instance.LoadPublicKey(file, out var material));
            using var materialLease = material;
            Assert.Equal("alice@example.com", material.KeyId);
        }
        finally
        {
            if (file.Exists) file.Delete();
        }
    }

    [Fact]
    public void OpenSshWithoutComment_FallsBackToFilenameKeyId()
    {
        using var rsa = RSA.Create(2048);
        var file = Temp("id_rsa.pub");
        try
        {
            var blob = Convert.ToBase64String(BuildOpenSshRsaBlob(rsa.ExportParameters(false)));
            File.WriteAllText(file.FullName, $"ssh-rsa {blob}\n");
            Assert.True(AsymmetricKeyLoaderManager.Instance.LoadPublicKey(file, out var material));
            using var materialLease = material;
            Assert.Equal(Path.GetFileNameWithoutExtension(file.Name), material.KeyId);
        }
        finally
        {
            if (file.Exists) file.Delete();
        }
    }

    [Fact]
    public void OpenSshExplicitKeyId_OverridesCommentEmail()
    {
        using var rsa = RSA.Create(2048);
        var file = Temp("authorized_keys");
        try
        {
            var blob = Convert.ToBase64String(BuildOpenSshRsaBlob(rsa.ExportParameters(false)));
            File.WriteAllText(file.FullName, $"ssh-rsa {blob} alice@example.com\n");
            Assert.True(AsymmetricKeyLoaderManager.Instance.LoadPublicKey(file, out var material, "explicit-id"));
            using var materialLease = material;
            Assert.Equal("explicit-id", material.KeyId);
        }
        finally
        {
            if (file.Exists) file.Delete();
        }
    }

    [Fact]
    public void OpenSshLineWhitespace_IsIgnored()
    {
        using var rsa = RSA.Create(2048);
        var file = Temp("authorized_keys");
        try
        {
            var blob = Convert.ToBase64String(BuildOpenSshRsaBlob(rsa.ExportParameters(false)));
            File.WriteAllText(file.FullName, $"  \tssh-rsa   {blob}   alice@example.com  \t\n");
            Assert.True(AsymmetricKeyLoaderManager.Instance.LoadPublicKey(file, out var material));
            using var materialLease = material;
            Assert.Equal("alice@example.com", material.KeyId);
            Assert.Equal(rsa.ExportSubjectPublicKeyInfo(), material.PublicKeyBytes);
        }
        finally
        {
            if (file.Exists) file.Delete();
        }
    }

    [Theory]
    [InlineData("ssh-rsa !!!not-base64!!!")]
    [InlineData("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGV4YW1wbGU=")]
    [InlineData("ssh-rsa")]
    [InlineData("")]
    public void OpenSshMalformedOrUnsupported_IsRejected(string content)
    {
        var file = Temp("authorized_keys");
        try
        {
            File.WriteAllText(file.FullName, content + "\n");
            Assert.False(AsymmetricKeyLoaderManager.Instance.LoadPublicKey(file, out _));
        }
        finally
        {
            if (file.Exists) file.Delete();
        }
    }

    [Fact]
    public void EcdsaCertificatePublicKey_Loads()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=CVK-ECDSA", ecdsa, HashAlgorithmName.SHA256);
        using var certificate =
            request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(5));
        var file = Temp("ecdsa-certificate.pem");
        try
        {
            File.WriteAllText(file.FullName, certificate.ExportCertificatePem());
            Assert.True(AsymmetricKeyLoaderManager.Instance.LoadPublicKey(file, out var material));
            using var materialLease = material;
            Assert.Equal("ECDSA", material.Algorithm);
            Assert.NotEmpty(material.PublicKeyBytes);
        }
        finally
        {
            if (file.Exists) file.Delete();
        }
    }

    private static FileInfo Temp(string name)
    {
        return new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-{Guid.NewGuid():N}-{name}"));
    }

    private static byte[] BuildOpenSshRsaBlob(RSAParameters parameters)
    {
        using var stream = new MemoryStream();
        WriteField(stream, "ssh-rsa"u8.ToArray());
        WriteField(stream, ToMpint(parameters.Exponent!));
        WriteField(stream, ToMpint(parameters.Modulus!));
        return stream.ToArray();
    }

    private static void WriteField(Stream stream, ReadOnlySpan<byte> value)
    {
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, (uint)value.Length);
        stream.Write(length);
        stream.Write(value);
    }

    private static byte[] ToMpint(byte[] value)
    {
        var first = Array.FindIndex(value, b => b != 0);
        if (first < 0) return [0];
        var trimmed = value[first..];
        return (trimmed[0] & 0x80) != 0 ? [0, .. trimmed] : trimmed;
    }
}
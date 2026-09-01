using System.Security.Cryptography;
using CrypVol.Lib.Crypto;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Security;
using Xunit;

namespace CrypVol.Tests;

/// <summary>验证可编辑 CVK 内容模型及其既有 KEY0 格式封装。</summary>
public sealed class CvkDocumentTests
{
    [Fact]
    public async Task PlainDocument_LoadsCekAndComment()
    {
        var file = CreateFile();
        try
        {
            var source = CvkDocument.CreateNew(EncryptionMode.PlainKey);
            source.Comment = "注释";
            await source.WriteAsync(file);

            var loaded = await CvkLoader.LoadAsync(file);

            Assert.Equal(source.Cek, loaded.Cek);
            Assert.Equal("注释", loaded.Comment);
            Assert.Equal(EncryptionMode.PlainKey, loaded.EncryptionMode);
        }
        finally { Delete(file); }
    }

    [Fact]
    public async Task ChangePasswordAndPayload_BuildsLoadableDocument()
    {
        var file = CreateFile();
        try
        {
            var document = CvkDocument.CreateNew(EncryptionMode.PlainKey);
            document.Cek = RandomNumberGenerator.GetBytes(32);
            document.EncryptionMode = EncryptionMode.Password;
            document.Password = "new-password";
            await document.WriteAsync(file);

            var loaded = await CvkLoader.LoadAsync(file, "new-password");

            Assert.Equal(document.Cek, loaded.Cek);
            Assert.Equal(EncryptionMode.Password, loaded.EncryptionMode);
            Assert.Equal(EnvelopeMode.Password, CvkLoader.ReadMode(file.FullName));
        }
        finally { Delete(file); }
    }

    [Fact]
    public void PublicKeyRecipients_CanBeAddedAndRemoved()
    {
        var document = CvkDocument.CreateNew(EncryptionMode.Asymmetric);
        var first = new FileInfo(Path.Combine(Path.GetTempPath(), "first.pem"));
        var second = new FileInfo(Path.Combine(Path.GetTempPath(), "second.pem"));

        document.AddPublicKey(first);
        document.AddPublicKey(first);
        document.AddPublicKey(second);

        Assert.Equal(2, document.NewPublicKeyFiles.Count);
        Assert.True(document.RemovePublicKey(first));
        Assert.Single(document.NewPublicKeyFiles);
        document.ClearPublicKeys();
        Assert.Empty(document.NewPublicKeyFiles);
    }

    [Fact]
    public async Task SshPrivateKeyDiscovery_OnlyReturnsPairedPrivateKeys()
    {
        var directory = new DirectoryInfo(Path.Combine(Path.GetTempPath(), $"cvk-ssh-{Guid.NewGuid()}"));
        directory.Create();
        try
        {
            await File.WriteAllTextAsync(Path.Combine(directory.FullName, "id_rsa"), "private");
            await File.WriteAllTextAsync(Path.Combine(directory.FullName, "id_rsa.pub"), "public");
            await File.WriteAllTextAsync(Path.Combine(directory.FullName, "unpaired"), "private");
            await File.WriteAllTextAsync(Path.Combine(directory.FullName, "known_hosts"), "host");
            await File.WriteAllTextAsync(Path.Combine(directory.FullName, "config"), "config");

            var candidates = SshPrivateKeyDiscovery.DiscoverPrivateKeys(directory).ToArray();

            var candidate = Assert.Single(candidates);
            Assert.Equal("id_rsa", candidate.Name);
        }
        finally
        {
            try { directory.Delete(true); }
            catch { }
        }
    }

    [Fact]
    public async Task LoadedPublicKeyRecipients_ArePreservedWithoutTheirPemFiles()
    {
        var directory = new DirectoryInfo(Path.Combine(Path.GetTempPath(), $"cvk-recipients-{Guid.NewGuid()}"));
        directory.Create();
        try
        {
            var firstPublic = new FileInfo(Path.Combine(directory.FullName, "first.pem"));
            var firstPrivate = new FileInfo(Path.Combine(directory.FullName, "first-private.pem"));
            var secondPublic = new FileInfo(Path.Combine(directory.FullName, "second.pem"));
            using (var first = RSA.Create(2048))
            using (var second = RSA.Create(2048))
            {
                await File.WriteAllTextAsync(firstPublic.FullName, first.ExportRSAPublicKeyPem());
                await File.WriteAllTextAsync(firstPrivate.FullName, first.ExportRSAPrivateKeyPem());
                await File.WriteAllTextAsync(secondPublic.FullName, second.ExportRSAPublicKeyPem());
            }

            var source = CvkDocument.CreateNew(EncryptionMode.Asymmetric);
            source.AddPublicKey(firstPublic);
            var original = new FileInfo(Path.Combine(directory.FullName, "original.cvk"));
            await source.WriteAsync(original);

            var loaded = await CvkLoader.LoadAsync(original, privateKeyFile: firstPrivate);
            Assert.Single(loaded.PublicKeyRecipients);
            File.Delete(firstPublic.FullName);

            loaded.AddPublicKey(secondPublic);
            var expanded = new FileInfo(Path.Combine(directory.FullName, "expanded.cvk"));
            await loaded.WriteAsync(expanded);
            var reloaded = await CvkLoader.LoadAsync(expanded, privateKeyFile: firstPrivate);
            Assert.Equal(2, reloaded.PublicKeyRecipients.Count);

            Assert.True(reloaded.RemovePublicKey("second"));
            var reduced = new FileInfo(Path.Combine(directory.FullName, "reduced.cvk"));
            await reloaded.WriteAsync(reduced);
            var final = await CvkLoader.LoadAsync(reduced, privateKeyFile: firstPrivate);
            Assert.Single(final.PublicKeyRecipients);
            Assert.Equal("first", final.PublicKeyRecipients[0].KeyId);
        }
        finally
        {
            try { directory.Delete(true); }
            catch { }
        }
    }

    [Fact]
    public async Task OpenSshRsaKeyPair_CanCreateAndLoadAsymmetricDocument()
    {
        var directory = new DirectoryInfo(Path.Combine(Path.GetTempPath(), $"cvk-openssh-{Guid.NewGuid()}"));
        directory.Create();
        try
        {
            var publicKey = new FileInfo(Path.Combine(directory.FullName, "id_rsa.pub"));
            var privateKey = new FileInfo(Path.Combine(directory.FullName, "id_rsa"));
            using (var rsa = RSA.Create(2048))
            {
                var pair = DotNetUtilities.GetRsaKeyPair(rsa);
                var publicBlob = OpenSshPublicKeyUtilities.EncodePublicKey(pair.Public);
                var privateBlob = OpenSshPrivateKeyUtilities.EncodePrivateKey(pair.Private);
                await File.WriteAllTextAsync(publicKey.FullName,
                    $"ssh-rsa {Convert.ToBase64String(publicBlob)} alice@example.com");
                await File.WriteAllTextAsync(privateKey.FullName,
                    $"-----BEGIN OPENSSH PRIVATE KEY-----\n{Convert.ToBase64String(privateBlob)}\n-----END OPENSSH PRIVATE KEY-----\n");
            }

            var original = CvkDocument.CreateNew(EncryptionMode.Asymmetric);
            original.AddPublicKey(publicKey);
            var file = new FileInfo(Path.Combine(directory.FullName, "key.cvk"));
            await original.WriteAsync(file);

            var loaded = await CvkLoader.LoadAsync(file, privateKeyFile: privateKey);

            Assert.Equal(original.Cek, loaded.Cek);
            Assert.Equal("alice@example.com", Assert.Single(loaded.PublicKeyRecipients).KeyId);
        }
        finally
        {
            try { directory.Delete(true); }
            catch { }
        }
    }

    /// <summary>移除 SSH 公钥文件时应使用邮箱注释生成的实际 KeyId。</summary>
    [Fact]
    public async Task RemovePublicKey_SshEmailKeyId_UsesResolvedKeyId()
    {
        var directory = new DirectoryInfo(Path.Combine(Path.GetTempPath(), $"cvk-remove-{Guid.NewGuid()}"));
        directory.Create();
        try
        {
            var publicKey = new FileInfo(Path.Combine(directory.FullName, "id_rsa.pub"));
            var privateKey = new FileInfo(Path.Combine(directory.FullName, "id_rsa.pem"));
            using (var rsa = RSA.Create(2048))
            {
                var pair = DotNetUtilities.GetRsaKeyPair(rsa);
                await File.WriteAllTextAsync(publicKey.FullName,
                    $"ssh-rsa {Convert.ToBase64String(OpenSshPublicKeyUtilities.EncodePublicKey(pair.Public))} alice@example.com\n");
                await File.WriteAllTextAsync(privateKey.FullName, rsa.ExportRSAPrivateKeyPem());
            }

            var document = CvkDocument.CreateNew(EncryptionMode.Asymmetric);
            document.AddPublicKey(publicKey);
            var file = new FileInfo(Path.Combine(directory.FullName, "key.cvk"));
            await document.WriteAsync(file);
            var loaded = await CvkLoader.LoadAsync(file, privateKeyFile: privateKey);
            Assert.True(loaded.RemovePublicKey(publicKey));
            Assert.Empty(loaded.PublicKeyRecipients);
        }
        finally
        {
            try { directory.Delete(true); }
            catch { }
        }
    }

    /// <summary>P-256 ECDH 公钥封装应能构建并使用对应私钥解封。</summary>
    [Fact]
    public async Task EccP256Document_LoadsWithPrivateKey()
    {
        var directory = new DirectoryInfo(Path.Combine(Path.GetTempPath(), $"cvk-ecc-{Guid.NewGuid()}"));
        directory.Create();
        try
        {
            var publicKey = new FileInfo(Path.Combine(directory.FullName, "device.pem"));
            var privateKey = new FileInfo(Path.Combine(directory.FullName, "device-private.pem"));
            using (var key = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256))
            {
                await File.WriteAllTextAsync(publicKey.FullName, key.ExportSubjectPublicKeyInfoPem());
                await File.WriteAllTextAsync(privateKey.FullName, key.ExportECPrivateKeyPem());
            }

            var source = CvkDocument.CreateNew(EncryptionMode.Ecc);
            source.AddPublicKey(publicKey);
            var file = new FileInfo(Path.Combine(directory.FullName, "ecc.cvk"));
            await source.WriteAsync(file);

            var loaded = await CvkLoader.LoadAsync(file, privateKeyFile: privateKey);
            Assert.Equal(source.Cek, loaded.Cek);
            Assert.Equal(EncryptionMode.Ecc, loaded.EncryptionMode);
            Assert.Equal(EnvelopeMode.EccPublicKey, CvkLoader.ReadMode(file.FullName));
            Assert.Equal("device", Assert.Single(loaded.PublicKeyRecipients).KeyId);
        }
        finally
        {
            try { directory.Delete(true); }
            catch { }
        }
    }

    private static FileInfo CreateFile()
    {
        return new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-document-{Guid.NewGuid()}.cvk"));
    }

    private static void Delete(FileInfo file)
    {
        try { file.Delete(); }
        catch { }
    }
}

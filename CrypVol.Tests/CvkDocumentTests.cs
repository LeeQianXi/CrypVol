using System.Security.Cryptography;
using CrypVol.Lib;
using CrypVol.Lib.Crypto;
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
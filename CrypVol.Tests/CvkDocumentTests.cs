using System.Security.Cryptography;
using CrypVol.Lib.Crypto;
using CrypVol.Lib.Crypto.Cryptography;
using CrypVol.Lib.Crypto.Models;
using CrypVol.Lib.Crypto.Keys;
using CrypVol.Lib.Crypto.Reading;
using CrypVol.Lib.Crypto.Writing;
using Xunit;

namespace CrypVol.Tests;

/// <summary>覆盖 CVK 文档创建、原子写入、解析、完整性校验和元数据往返。</summary>
public sealed class CvkDocumentTests
{
    [Fact]
    public async Task Operations_RejectNullArguments()
    {
        var file = TempFile();
        await Assert.ThrowsAnyAsync<Exception>(() => CvkOperations.WriteAsync(null!, file));
        await Assert.ThrowsAnyAsync<Exception>(() => CvkOperations.WriteAsync(CvkOperations.CreateNew(CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.None), null!));
        await Assert.ThrowsAnyAsync<Exception>(() => CvkOperations.LoadAsync(null!));
        Assert.ThrowsAny<Exception>(() => CvkOperations.ToCredentials(null!));
        Assert.ThrowsAny<Exception>(() => CvkOperations.AddPublicKey(null!, file));
    }

    [Fact]
    public void CreateNew_RejectsUndefinedRoutes()
    {
        Assert.ThrowsAny<Exception>(() => CvkOperations.CreateNew((CvkKeyProtection)99, CvkKeyWrapAlgorithm.None));
        Assert.ThrowsAny<Exception>(() => CvkOperations.CreateNew(CvkKeyProtection.Plain, (CvkKeyWrapAlgorithm)99));
    }

    [Fact]
    public async Task PlainDocument_RoundTrips()
    {
        var file = TempFile();
        try
        {
            var source = CvkOperations.CreateNew(CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.None);
            source.Comment = "unit-test";
            await CvkOperations.WriteAsync(source, file);
            var loaded = await CvkOperations.LoadAsync(file);
            Assert.Equal(source.Cek, loaded.Cek);
            Assert.Equal(source.Comment, loaded.Comment);
            Assert.Equal(CvkKeyProtection.Plain, loaded.KeyProtection);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task Metadata_WithUnicodeAndEscapes_RoundTrips()
    {
        var file = TempFile();
        try
        {
            var source = CvkOperations.CreateNew(CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.None);
            source.Label = "卷🔐\n标签";
            source.Description = "描述\t含引号\"";
            source.Comment = string.Empty;
            await CvkOperations.WriteAsync(source, file);
            var loaded = await CvkOperations.LoadAsync(file);
            Assert.Equal(source.Label, loaded.Label);
            Assert.Equal(source.Description, loaded.Description);
            Assert.Equal(source.Comment, loaded.Comment);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task Reader_ReadAsyncReturnsVerifiedParsedSegments()
    {
        var file = TempFile();
        try
        {
            var source = CvkOperations.CreateNew(CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.None);
            await CvkOperations.WriteAsync(source, file);
            var parsed = await new CvkReader(new Sha256IntegrityCalculator()).ReadAsync(file);
            Assert.Equal(CvkKeyProtection.Plain, parsed.Header.KeyProtection);
            Assert.NotEmpty(parsed.HeaderJson.ToArray());
            Assert.NotEmpty(parsed.KeyBody.ToArray());
            Assert.Equal(32, parsed.Integrity.Length);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task Header_UsesStableJsonRouteNames()
    {
        var file = TempFile();
        try
        {
            await CvkOperations.WriteAsync(CvkOperations.CreateNew(CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.None), file);
            var parsed = await new CvkReader(new Sha256IntegrityCalculator()).ReadAsync(file);
            var json = System.Text.Encoding.UTF8.GetString(parsed.HeaderJson.ToArray());
            Assert.Contains("\"version\"", json);
            Assert.Contains("\"keyProtection\"", json);
            Assert.Contains("\"keyWrapAlgorithm\"", json);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task MetadataAndRecipients_RoundTripExactly()
    {
        using var rsa = RSA.Create(2048);
        var file = TempFile();
        try
        {
            var created = DateTimeOffset.UtcNow.AddMinutes(-1);
            var source = CvkOperations.CreateNew(CvkKeyProtection.PublicKey, CvkKeyWrapAlgorithm.RsaOaepSha256);
            source.Label = "label";
            source.Description = "description";
            source.Comment = "comment";
            source.CreatedAt = created;
            source.Generator = "generator";
            source.RecipientKeys.Add(new AsymmetricRecipientKey("id", "RSA", rsa.ExportSubjectPublicKeyInfo(), "mail@example.com"));
            await new CvkWriter(new CvkPayloadProtectorAdapter(new RsaOaepSha256Cryptor())).WriteAsync(source, file);
            using var privateMaterial = new AsymmetricPrivateKeyMaterial("id", "RSA", rsa);
            var loaded = await new CvkReader(new Sha256IntegrityCalculator(), new CvkPayloadUnprotectorAdapter(new RsaOaepSha256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["id"] = privateMaterial }))).ReadDocumentAsync(file);
            Assert.Equal(source.Label, loaded.Label);
            Assert.Equal(source.Description, loaded.Description);
            Assert.Equal(source.Comment, loaded.Comment);
            Assert.Equal(source.CreatedAt, loaded.CreatedAt);
            Assert.Equal(source.Generator, loaded.Generator);
            Assert.Equal(source.RecipientKeys[0].KeyId, loaded.RecipientKeys[0].KeyId);
            Assert.Equal(source.RecipientKeys[0].Algorithm, loaded.RecipientKeys[0].Algorithm);
            Assert.Equal(source.RecipientKeys[0].Comment, loaded.RecipientKeys[0].Comment);
            Assert.Equal(source.RecipientKeys[0].PublicKeyBytes.ToArray(), loaded.RecipientKeys[0].PublicKeyBytes.ToArray());
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task PasswordDocument_RoundTripsOnlyWithPassword()
    {
        var file = TempFile();
        try
        {
            var source = CvkOperations.CreateNew(CvkKeyProtection.Password, CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256);
            await CvkOperations.WriteAsync(source, file, "correct-password");
            await Assert.ThrowsAsync<CryptographicException>(() => CvkOperations.LoadAsync(file, "wrong-password"));
            var loaded = await CvkOperations.LoadAsync(file, "correct-password");
            Assert.Equal(source.Cek, loaded.Cek);
            Assert.Equal(CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256, loaded.KeyWrapAlgorithm);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task PasswordDocument_WithoutPasswordCannotBeLoaded()
    {
        var file = TempFile();
        try
        {
            var source = CvkOperations.CreateNew(CvkKeyProtection.Password, CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256);
            await CvkOperations.WriteAsync(source, file, "secret");
            await Assert.ThrowsAnyAsync<Exception>(() => CvkOperations.LoadAsync(file));
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task PasswordDocument_EmptyPasswordCannotBeWritten()
    {
        var file = TempFile();
        try
        {
            var source = CvkOperations.CreateNew(CvkKeyProtection.Password, CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256);
            await Assert.ThrowsAnyAsync<Exception>(() => CvkOperations.WriteAsync(source, file, ""));
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task PublicDocument_WithoutRecipientsCannotBeWritten()
    {
        var file = TempFile();
        try
        {
            var source = CvkOperations.CreateNew(CvkKeyProtection.PublicKey, CvkKeyWrapAlgorithm.RsaOaepSha256);
            await Assert.ThrowsAsync<InvalidDataException>(() => CvkOperations.WriteAsync(source, file));
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task Tampering_IsRejectedByIntegrityCheck()
    {
        var file = TempFile();
        try
        {
            await CvkOperations.WriteAsync(CvkOperations.CreateNew(CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.None), file);
            var bytes = await File.ReadAllBytesAsync(file.FullName);
            bytes[^1] ^= 0x01;
            await File.WriteAllBytesAsync(file.FullName, bytes);
            await Assert.ThrowsAsync<CryptographicException>(() => CvkOperations.LoadAsync(file));
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Theory]
    [InlineData(16)]
    public async Task HeaderTampering_IsRejected(int relativeOffset)
    {
        await AssertTamperedFileAsync(bytes => { bytes[relativeOffset] ^= 1; return bytes; });
    }

    [Fact]
    public async Task KeyBodyTampering_IsRejected()
    {
        await AssertTamperedFileAsync(bytes =>
        {
            var headerLength = BitConverter.ToUInt32(bytes, 4);
            bytes[checked((int)(16 + headerLength))] ^= 1;
            return bytes;
        });
    }

    [Fact]
    public async Task IntegrityLengthTampering_IsRejected()
    {
        await AssertTamperedFileAsync(bytes => { bytes[12] = 0; return bytes; });
    }

    [Fact]
    public async Task TruncatedFile_IsRejected()
    {
        await AssertTamperedFileAsync(bytes => bytes[..^1]);
    }

    [Fact]
    public async Task AppendedFile_IsRejected()
    {
        await AssertTamperedFileAsync(bytes => [.. bytes, (byte)0]);
    }

    [Fact]
    public void Credentials_RejectInvalidCekLength()
    {
        Assert.Throws<ArgumentException>(() => new CvkCredentials(CvkKeyProtection.Plain, new byte[31]));
    }

    [Fact]
    public void Credentials_RejectUndefinedRouteValues()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new CvkCredentials((CvkKeyProtection)99, new byte[32], CvkKeyWrapAlgorithm.None));
        Assert.Throws<ArgumentOutOfRangeException>(() => new CvkCredentials(CvkKeyProtection.Plain, new byte[32], (CvkKeyWrapAlgorithm)99));
    }

    [Fact]
    public void Parser_RejectsInvalidMagic()
    {
        Assert.Throws<InvalidDataException>(() => CrypVol.Lib.Crypto.Reading.CvkParser.Parse("bad"u8.ToArray()));
    }

    [Theory]
    [InlineData(CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.None)]
    [InlineData(CvkKeyProtection.Password, CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256)]
    [InlineData(CvkKeyProtection.PublicKey, CvkKeyWrapAlgorithm.RsaOaepSha256)]
    public void CreateNew_InitializesExpectedCredentials(CvkKeyProtection protection, CvkKeyWrapAlgorithm algorithm)
    {
        var document = CvkOperations.CreateNew(protection, algorithm);
        Assert.Equal(32, document.Cek.Length);
        Assert.Equal(protection, document.KeyProtection);
        Assert.Equal(protection == CvkKeyProtection.Plain ? CvkKeyWrapAlgorithm.None : algorithm, document.KeyWrapAlgorithm);
        Assert.NotNull(document.CreatedAt);
        Assert.Equal("CrypVol", document.Generator);
    }

    [Fact]
    public void ToCredentials_CopiesCekAndRoute()
    {
        var document = CvkOperations.CreateNew(CvkKeyProtection.Password, CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256);
        var credentials = CvkOperations.ToCredentials(document);
        Assert.Equal(document.Cek, credentials.Cek.ToArray());
        Assert.Equal(document.KeyProtection, credentials.KeyProtection);
        Assert.Equal(document.KeyWrapAlgorithm, credentials.KeyWrapAlgorithm);
    }

    [Fact]
    public void Credentials_DefensivelyCopiesCek()
    {
        var source = new byte[32];
        source[0] = 7;
        var credentials = new CvkCredentials(CvkKeyProtection.Plain, source);
        source[0] = 9;
        Assert.Equal(7, credentials.Cek.Span[0]);
    }

    [Fact]
    public void AddPublicKey_PersistsMaterialAndSupportsCustomId()
    {
        using var rsa = RSA.Create(2048);
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-key-{Guid.NewGuid():N}.pub"));
        try
        {
            File.WriteAllText(file.FullName, rsa.ExportSubjectPublicKeyInfoPem());
            var document = CvkOperations.CreateNew(CvkKeyProtection.PublicKey, CvkKeyWrapAlgorithm.RsaOaepSha256);
            CvkOperations.AddPublicKey(document, file, "recipient-1");
            Assert.Single(document.RecipientKeys);
            Assert.Equal("recipient-1", document.RecipientKeys[0].KeyId);
            Assert.Equal("RSA", document.RecipientKeys[0].Algorithm);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public void AddPublicKey_StringOverload_RejectsMissingFile()
    {
        var document = CvkOperations.CreateNew(CvkKeyProtection.PublicKey, CvkKeyWrapAlgorithm.RsaOaepSha256);
        var path = Path.Combine(Path.GetTempPath(), $"missing-key-{Guid.NewGuid():N}.pub");
        Assert.Throws<FileNotFoundException>(() => CvkOperations.AddPublicKey(document, path));
    }

    [Fact]
    public async Task Operations_LoadAsync_UsesPrivateKeyForPublicMode()
    {
        using var rsa = RSA.Create(2048);
        var document = CvkOperations.CreateNew(CvkKeyProtection.PublicKey, CvkKeyWrapAlgorithm.RsaOaepSha256);
        document.RecipientKeys.Add(new AsymmetricRecipientKey("receiver", "RSA", rsa.ExportSubjectPublicKeyInfo()));
        var cvkFile = TempFile();
        var privateFile = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-private-{Guid.NewGuid():N}.pem"));
        try
        {
            await CvkOperations.WriteAsync(document, cvkFile);
            await File.WriteAllTextAsync(privateFile.FullName, rsa.ExportPkcs8PrivateKeyPem());
            var loaded = await CvkOperations.LoadAsync(cvkFile, null, privateFile, null, CancellationToken.None);
            Assert.Equal(document.Cek, loaded.Cek);
        }
        finally
        {
            if (cvkFile.Exists) cvkFile.Delete();
            if (privateFile.Exists) privateFile.Delete();
        }
    }

    [Fact]
    public async Task Operations_WriteAndLoad_HonorCancellation()
    {
        var file = TempFile();
        try
        {
            var document = CvkOperations.CreateNew(CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.None);
            using var cts = new CancellationTokenSource();
            cts.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => CvkOperations.WriteAsync(document, file, cts.Token));
            Assert.False(file.Exists);
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => CvkOperations.LoadAsync(file, null, cts.Token));
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task Write_CreatesMissingNestedDirectoryAtomically()
    {
        var root = Path.Combine(Path.GetTempPath(), $"cvk-dir-{Guid.NewGuid():N}");
        var file = new FileInfo(Path.Combine(root, "nested", "data.cvk"));
        try
        {
            await CvkOperations.WriteAsync(CvkOperations.CreateNew(CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.None), file);
            Assert.True(file.Exists);
            Assert.NotNull(await CvkOperations.LoadAsync(file));
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, true); }
    }

    private static FileInfo TempFile() => new(Path.Combine(Path.GetTempPath(), $"cvk-{Guid.NewGuid():N}.cvk"));

    private static async Task AssertTamperedFileAsync(Func<byte[], byte[]> mutate)
    {
        var file = TempFile();
        try
        {
            await CvkOperations.WriteAsync(CvkOperations.CreateNew(CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.None), file);
            var bytes = await File.ReadAllBytesAsync(file.FullName);
            bytes = mutate(bytes);
            await File.WriteAllBytesAsync(file.FullName, bytes);
            await Assert.ThrowsAnyAsync<Exception>(() => CvkOperations.LoadAsync(file));
        }
        finally { if (file.Exists) file.Delete(); }
    }
}

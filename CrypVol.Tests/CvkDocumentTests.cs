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

    [Theory]
    [InlineData(CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256)]
    [InlineData(CvkKeyProtection.Password, CvkKeyWrapAlgorithm.None)]
    [InlineData(CvkKeyProtection.PublicKey, CvkKeyWrapAlgorithm.None)]
    public void CreateNew_RejectsMismatchedProtectionAndWrap(CvkKeyProtection protection, CvkKeyWrapAlgorithm algorithm)
    {
        Assert.Throws<ArgumentException>(() => CvkOperations.CreateNew(protection, algorithm));
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
            Assert.Null(loaded.Label);
            Assert.Null(loaded.Description);
            Assert.Equal(source.CreatedAt, loaded.CreatedAt);
            Assert.Equal(source.Generator, loaded.Generator);
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
            var created = new DateTimeOffset(2026, 9, 2, 12, 34, 56, TimeSpan.FromHours(8));
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
    public async Task PasswordDocument_UnicodePasswordRoundTrips()
    {
        var file = TempFile();
        const string password = "密码🔐-пароль";
        try
        {
            var source = CvkOperations.CreateNew(CvkKeyProtection.Password, CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256);
            await CvkOperations.WriteAsync(source, file, password);
            var loaded = await CvkOperations.LoadAsync(file, password);
            Assert.Equal(source.Cek, loaded.Cek);
            await Assert.ThrowsAnyAsync<Exception>(() => CvkOperations.LoadAsync(file, "密码🔐-wrong"));
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
    public void ToCredentials_RejectsInvalidDocumentCekLength()
    {
        var document = new CvkDocument
        {
            Cek = new byte[31],
            KeyProtection = CvkKeyProtection.Plain,
            KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None
        };

        Assert.Throws<ArgumentException>(() => CvkOperations.ToCredentials(document));
    }

    [Fact]
    public void Credentials_RejectUndefinedRouteValues()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new CvkCredentials((CvkKeyProtection)99, new byte[32], CvkKeyWrapAlgorithm.None));
        Assert.Throws<ArgumentOutOfRangeException>(() => new CvkCredentials(CvkKeyProtection.Plain, new byte[32], (CvkKeyWrapAlgorithm)99));
    }

    [Theory]
    [InlineData(CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.RsaOaepSha256)]
    [InlineData(CvkKeyProtection.Password, CvkKeyWrapAlgorithm.None)]
    [InlineData(CvkKeyProtection.PublicKey, CvkKeyWrapAlgorithm.None)]
    public void Credentials_RejectMismatchedRoute(CvkKeyProtection protection, CvkKeyWrapAlgorithm algorithm)
    {
        Assert.Throws<ArgumentException>(() => new CvkCredentials(protection, new byte[32], algorithm));
    }

    [Fact]
    public void Parser_RejectsInvalidMagic()
    {
        Assert.Throws<InvalidDataException>(() => CrypVol.Lib.Crypto.Reading.CvkParser.Parse("bad"u8.ToArray()));
    }

    [Theory]
    [InlineData(CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.None)]
    [InlineData(CvkKeyProtection.Password, CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256)]
    [InlineData(CvkKeyProtection.Password, CvkKeyWrapAlgorithm.PasswordArgon2Id)]
    [InlineData(CvkKeyProtection.PublicKey, CvkKeyWrapAlgorithm.RsaOaepSha256)]
    [InlineData(CvkKeyProtection.PublicKey, CvkKeyWrapAlgorithm.RsaOaepSha384)]
    [InlineData(CvkKeyProtection.PublicKey, CvkKeyWrapAlgorithm.RsaOaepSha512)]
    [InlineData(CvkKeyProtection.PublicKey, CvkKeyWrapAlgorithm.EcdhP256)]
    [InlineData(CvkKeyProtection.PublicKey, CvkKeyWrapAlgorithm.EcdhP384)]
    [InlineData(CvkKeyProtection.PublicKey, CvkKeyWrapAlgorithm.EcdhP521)]
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
    public void CreateNew_GeneratesDistinctCekValues()
    {
        var first = CvkOperations.CreateNew(CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.None);
        var second = CvkOperations.CreateNew(CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.None);
        Assert.NotEqual(first.Cek, second.Cek);
        Assert.Contains(first.Cek, value => value != 0);
        Assert.Contains(second.Cek, value => value != 0);
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
    public void ToCredentials_DefensivelyCopiesDocumentCek()
    {
        var document = CvkOperations.CreateNew(CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.None);
        var credentials = CvkOperations.ToCredentials(document);
        var original = credentials.Cek.ToArray();

        document.Cek[0] ^= 0xFF;

        Assert.Equal(original, credentials.Cek.ToArray());
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
    public void Credentials_AcceptsAllZero32ByteCek()
    {
        var credentials = new CvkCredentials(CvkKeyProtection.Plain, new byte[32]);

        Assert.Equal(32, credentials.Cek.Length);
        Assert.All(credentials.Cek.ToArray(), value => Assert.Equal((byte)0, value));
    }

    [Fact]
    public void Credentials_AllowsEmptyCekWithoutAliasing()
    {
        var source = Array.Empty<byte>();
        var credentials = new CvkCredentials(CvkKeyProtection.Plain, source);

        Assert.True(credentials.Cek.IsEmpty);
        Assert.Empty(credentials.Cek.ToArray());
    }

    [Theory]
    [InlineData(CvkKeyProtection.Password, CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256)]
    [InlineData(CvkKeyProtection.PublicKey, CvkKeyWrapAlgorithm.RsaOaepSha256)]
    public void Credentials_RejectsEmptyCekForProtectedModes(CvkKeyProtection protection, CvkKeyWrapAlgorithm algorithm)
    {
        Assert.Throws<ArgumentException>(() => new CvkCredentials(protection, ReadOnlyMemory<byte>.Empty, algorithm));
    }

    [Theory]
    [InlineData(CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.RsaOaepSha256)]
    [InlineData(CvkKeyProtection.Password, CvkKeyWrapAlgorithm.None)]
    [InlineData(CvkKeyProtection.PublicKey, CvkKeyWrapAlgorithm.None)]
    public void ToCredentials_RejectsMismatchedProtectionAndWrap(CvkKeyProtection protection,
        CvkKeyWrapAlgorithm algorithm)
    {
        var document = new CvkDocument
        {
            Cek = new byte[32],
            KeyProtection = protection,
            KeyWrapAlgorithm = algorithm
        };
        Assert.ThrowsAny<Exception>(() => CvkOperations.ToCredentials(document));
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
            var publicKeyBytes = document.RecipientKeys[0].PublicKeyBytes.ToArray();
            file.Delete();
            Assert.Equal(publicKeyBytes, document.RecipientKeys[0].PublicKeyBytes.ToArray());
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
    public void AddPublicKey_RejectsNullOrEmptyFileArguments()
    {
        var document = CvkOperations.CreateNew(CvkKeyProtection.PublicKey, CvkKeyWrapAlgorithm.RsaOaepSha256);
        Assert.Throws<ArgumentNullException>(() => CvkOperations.AddPublicKey(document, (FileInfo)null!));
        Assert.Throws<ArgumentNullException>(() => CvkOperations.AddPublicKey(document, (string)null!));
        Assert.ThrowsAny<ArgumentException>(() => CvkOperations.AddPublicKey(document, string.Empty));
    }

    [Fact]
    public void AddPublicKey_RejectsDuplicateKeyId()
    {
        using var rsa = RSA.Create(2048);
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-duplicate-key-{Guid.NewGuid():N}.pub"));
        try
        {
            File.WriteAllText(file.FullName, rsa.ExportSubjectPublicKeyInfoPem());
            var document = CvkOperations.CreateNew(CvkKeyProtection.PublicKey, CvkKeyWrapAlgorithm.RsaOaepSha256);
            CvkOperations.AddPublicKey(document, file, "same-id");
            Assert.ThrowsAny<Exception>(() => CvkOperations.AddPublicKey(document, file, "same-id"));
            Assert.Single(document.RecipientKeys);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public void AddPublicKey_RejectsAlgorithmMismatchedWithDocument()
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-mismatched-key-{Guid.NewGuid():N}.pub"));
        try
        {
            File.WriteAllText(file.FullName, ecdh.ExportSubjectPublicKeyInfoPem());
            var document = CvkOperations.CreateNew(CvkKeyProtection.PublicKey, CvkKeyWrapAlgorithm.RsaOaepSha256);
            Assert.ThrowsAny<Exception>(() => CvkOperations.AddPublicKey(document, file, "ec"));
            Assert.Empty(document.RecipientKeys);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public void AddPublicKey_RejectsRsaKeyForEcdhDocument()
    {
        using var rsa = RSA.Create(2048);
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-mismatched-rsa-{Guid.NewGuid():N}.pub"));
        try
        {
            File.WriteAllText(file.FullName, rsa.ExportSubjectPublicKeyInfoPem());
            var document = CvkOperations.CreateNew(CvkKeyProtection.PublicKey, CvkKeyWrapAlgorithm.EcdhP256);
            Assert.ThrowsAny<Exception>(() => CvkOperations.AddPublicKey(document, file, "rsa"));
            Assert.Empty(document.RecipientKeys);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public void AddPublicKey_RejectsEcdhCurveMismatch()
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384);
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-mismatched-curve-{Guid.NewGuid():N}.pub"));
        try
        {
            File.WriteAllText(file.FullName, ecdh.ExportSubjectPublicKeyInfoPem());
            var document = CvkOperations.CreateNew(CvkKeyProtection.PublicKey, CvkKeyWrapAlgorithm.EcdhP256);
            Assert.ThrowsAny<Exception>(() => CvkOperations.AddPublicKey(document, file, "ec384"));
            Assert.Empty(document.RecipientKeys);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Theory]
    [InlineData(CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.None)]
    [InlineData(CvkKeyProtection.Password, CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256)]
    public void AddPublicKey_RejectsNonPublicKeyDocument(CvkKeyProtection protection,
        CvkKeyWrapAlgorithm algorithm)
    {
        using var rsa = RSA.Create(2048);
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-non-public-{Guid.NewGuid():N}.pub"));
        try
        {
            File.WriteAllText(file.FullName, rsa.ExportSubjectPublicKeyInfoPem());
            var document = CvkOperations.CreateNew(protection, algorithm);
            Assert.ThrowsAny<Exception>(() => CvkOperations.AddPublicKey(document, file, "rsa"));
            Assert.Empty(document.RecipientKeys);
        }
        finally { if (file.Exists) file.Delete(); }
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
    public async Task Operations_LoadAsync_UsesPrivateKeyPasswordForEncryptedPem()
    {
        using var rsa = RSA.Create(2048);
        var document = CvkOperations.CreateNew(CvkKeyProtection.PublicKey, CvkKeyWrapAlgorithm.RsaOaepSha256);
        document.RecipientKeys.Add(new AsymmetricRecipientKey("receiver", "RSA", rsa.ExportSubjectPublicKeyInfo()));
        var cvkFile = TempFile();
        var privateFile = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-private-encrypted-{Guid.NewGuid():N}.pem"));
        const string password = "private-password";
        try
        {
            await CvkOperations.WriteAsync(document, cvkFile);
            var pem = rsa.ExportEncryptedPkcs8PrivateKeyPem(password,
                new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100_000));
            await File.WriteAllTextAsync(privateFile.FullName, pem);

            var loaded = await CvkOperations.LoadAsync(cvkFile, null, privateFile, password, CancellationToken.None);
            Assert.Equal(document.Cek, loaded.Cek);
            var loadedWithUnusedCvkPassword = await CvkOperations.LoadAsync(cvkFile, "unused-cvk-password", privateFile, password, CancellationToken.None);
            Assert.Equal(document.Cek, loadedWithUnusedCvkPassword.Cek);
            await Assert.ThrowsAnyAsync<Exception>(() =>
                CvkOperations.LoadAsync(cvkFile, null, privateFile, "wrong-password", CancellationToken.None));
        }
        finally
        {
            if (cvkFile.Exists) cvkFile.Delete();
            if (privateFile.Exists) privateFile.Delete();
        }
    }

    [Fact]
    public async Task Header_OmitsNullOptionalMetadata()
    {
        var file = TempFile();
        try
        {
            await CvkOperations.WriteAsync(new CvkDocument
            {
                Cek = new byte[32],
                KeyProtection = CvkKeyProtection.Plain,
                KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None
            }, file);
            var parsed = await new CvkReader(new Sha256IntegrityCalculator()).ReadAsync(file);
            var json = System.Text.Encoding.UTF8.GetString(parsed.HeaderJson.ToArray());

            Assert.DoesNotContain("\"label\"", json);
            Assert.DoesNotContain("\"description\"", json);
            Assert.DoesNotContain("\"comment\"", json);
            Assert.DoesNotContain("\"createdAt\"", json);
            Assert.DoesNotContain("\"generator\"", json);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task Header_SerializesDeterministicallyForSameDocument()
    {
        var firstFile = TempFile();
        var secondFile = TempFile();
        try
        {
            var source = new CvkDocument
            {
                Cek = new byte[32],
                KeyProtection = CvkKeyProtection.Plain,
                KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None,
                Version = 7,
                Label = "stable",
                Description = "description",
                Comment = "comment",
                Generator = "generator",
                CreatedAt = new DateTimeOffset(2026, 9, 2, 12, 0, 0, TimeSpan.Zero)
            };
            var writer = new CvkWriter(new PlainCvkPayloadProtector());
            await writer.WriteAsync(source, firstFile);
            await writer.WriteAsync(source, secondFile);
            var first = await new CvkReader(new Sha256IntegrityCalculator()).ReadAsync(firstFile);
            var second = await new CvkReader(new Sha256IntegrityCalculator()).ReadAsync(secondFile);

            Assert.Equal(first.HeaderJson.ToArray(), second.HeaderJson.ToArray());
        }
        finally
        {
            if (firstFile.Exists) firstFile.Delete();
            if (secondFile.Exists) secondFile.Delete();
        }
    }

    [Fact]
    public async Task PasswordDocument_WhitespacePasswordRoundTripsThroughOperations()
    {
        var file = TempFile();
        try
        {
            var source = CvkOperations.CreateNew(CvkKeyProtection.Password, CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256);
            await CvkOperations.WriteAsync(source, file, " ");
            var loaded = await CvkOperations.LoadAsync(file, " ");
            Assert.Equal(source.Cek, loaded.Cek);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task Argon2Document_RoundTripsThroughOperations()
    {
        var file = TempFile();
        try
        {
            var source = CvkOperations.CreateNew(CvkKeyProtection.Password, CvkKeyWrapAlgorithm.PasswordArgon2Id);
            await CvkOperations.WriteAsync(source, file, "argon2-password");
            var loaded = await CvkOperations.LoadAsync(file, "argon2-password");
            Assert.Equal(source.Cek, loaded.Cek);
            Assert.Equal(CvkKeyWrapAlgorithm.PasswordArgon2Id, loaded.KeyWrapAlgorithm);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task Operations_LoadAsync_UsesEcdhPrivateKeyFileForPublicMode()
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var document = CvkOperations.CreateNew(CvkKeyProtection.PublicKey, CvkKeyWrapAlgorithm.EcdhP256);
        document.RecipientKeys.Add(new AsymmetricRecipientKey("receiver", "ECDH", ecdh.ExportSubjectPublicKeyInfo()));
        var cvkFile = TempFile();
        var privateFile = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-ecdh-private-{Guid.NewGuid():N}.pem"));
        try
        {
            await new CvkWriter(new CvkPayloadProtectorAdapter(new EcdhP256Cryptor())).WriteAsync(document, cvkFile);
            await File.WriteAllTextAsync(privateFile.FullName, ecdh.ExportPkcs8PrivateKeyPem());
            var loaded = await CvkOperations.LoadAsync(cvkFile, null, privateFile, null, CancellationToken.None);
            Assert.Equal(document.Cek, loaded.Cek);
        }
        finally
        {
            if (cvkFile.Exists) cvkFile.Delete();
            if (privateFile.Exists) privateFile.Delete();
        }
    }

    [Theory]
    [InlineData(CvkKeyWrapAlgorithm.EcdhP384)]
    [InlineData(CvkKeyWrapAlgorithm.EcdhP521)]
    public async Task Operations_LoadAsync_UsesEcdhPrivateKeyFileForOtherCurves(CvkKeyWrapAlgorithm algorithm)
    {
        var curve = algorithm == CvkKeyWrapAlgorithm.EcdhP384 ? ECCurve.NamedCurves.nistP384 : ECCurve.NamedCurves.nistP521;
        using var ecdh = ECDiffieHellman.Create(curve);
        var document = CvkOperations.CreateNew(CvkKeyProtection.PublicKey, algorithm);
        document.RecipientKeys.Add(new AsymmetricRecipientKey("receiver", "ECDH", ecdh.ExportSubjectPublicKeyInfo()));
        var cvkFile = TempFile();
        var privateFile = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-ecdh-private-{Guid.NewGuid():N}.pem"));
        try
        {
            await CvkOperations.WriteAsync(document, cvkFile);
            await File.WriteAllTextAsync(privateFile.FullName, ecdh.ExportPkcs8PrivateKeyPem());
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
    public async Task Operations_WriteAsync_RejectsUndefinedRouteWithoutCreatingTarget()
    {
        var document = new CvkDocument
        {
            Cek = new byte[32],
            KeyProtection = (CvkKeyProtection)99,
            KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None
        };
        var file = TempFile();
        if (file.Exists) file.Delete();
        try
        {
            await Assert.ThrowsAnyAsync<Exception>(() => CvkOperations.WriteAsync(document, file));
            Assert.False(file.Exists);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task Operations_WriteAsync_HonorsCancellationWithoutCreatingTarget()
    {
        var file = TempFile();
        if (file.Exists) file.Delete();
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        try
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                CvkOperations.WriteAsync(CvkOperations.CreateNew(CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.None), file, null, cts.Token));
            Assert.False(file.Exists);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task Operations_WriteAsync_TokenOverloadHonorsCancellation()
    {
        var file = TempFile();
        if (file.Exists) file.Delete();
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        try
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                CvkOperations.WriteAsync(CvkOperations.CreateNew(CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.None), file, cts.Token));
            Assert.False(file.Exists);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Theory]
    [InlineData(31)]
    [InlineData(33)]
    public async Task Operations_WriteAsync_RejectsInvalidCekLength(int length)
    {
        var file = TempFile();
        if (file.Exists) file.Delete();
        var document = new CvkDocument
        {
            Cek = new byte[length],
            KeyProtection = CvkKeyProtection.Plain,
            KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None
        };
        try
        {
            await Assert.ThrowsAsync<InvalidDataException>(() => CvkOperations.WriteAsync(document, file));
            Assert.False(file.Exists);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task Operations_LoadAsync_HonorsCancellationOnValidFile()
    {
        var file = TempFile();
        try
        {
            await CvkOperations.WriteAsync(CvkOperations.CreateNew(CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.None), file);
            using var cts = new CancellationTokenSource();
            cts.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => CvkOperations.LoadAsync(file, null, cts.Token));
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task Operations_LoadAsync_RejectsMissingPrivateKeyFile()
    {
        using var rsa = RSA.Create(2048);
        var cvkFile = TempFile();
        var privateFile = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-missing-private-{Guid.NewGuid():N}.pem"));
        try
        {
            var document = CvkOperations.CreateNew(CvkKeyProtection.PublicKey, CvkKeyWrapAlgorithm.RsaOaepSha256);
            document.RecipientKeys.Add(new AsymmetricRecipientKey("receiver", "RSA", rsa.ExportSubjectPublicKeyInfo()));
            await new CvkWriter(new CvkPayloadProtectorAdapter(new RsaOaepSha256Cryptor())).WriteAsync(document, cvkFile);

            await Assert.ThrowsAsync<FileNotFoundException>(() =>
                CvkOperations.LoadAsync(cvkFile, null, privateFile, null, CancellationToken.None));
        }
        finally { if (cvkFile.Exists) cvkFile.Delete(); }
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

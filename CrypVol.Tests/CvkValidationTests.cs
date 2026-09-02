using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using CrypVol.Lib.Crypto.Cryptography;
using CrypVol.Lib.Crypto.Keys;
using CrypVol.Lib.Crypto.Models;
using CrypVol.Lib.Crypto.Reading;
using CrypVol.Lib.Crypto.Writing;
using CrypVol.Lib.Utility;
using Xunit;

namespace CrypVol.Tests;

/// <summary>覆盖 CVK 解析、写入校验、路由注册和 Plain 处理器边界。</summary>
public sealed class CvkValidationTests
{
    [Fact]
    public async Task Writer_RejectsEmptyCek()
    {
        var document = new CrypVol.Lib.Crypto.CvkDocument { Cek = [], KeyProtection = CvkKeyProtection.Plain, KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None };
        await Assert.ThrowsAsync<InvalidDataException>(() => Write(document));
    }

    [Theory]
    [InlineData(31)]
    [InlineData(33)]
    public async Task Writer_RejectsCekLengthsOtherThan32(int length)
    {
        var document = new CrypVol.Lib.Crypto.CvkDocument
        {
            Cek = new byte[length],
            KeyProtection = CvkKeyProtection.Plain,
            KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None
        };

        await Assert.ThrowsAsync<InvalidDataException>(() => Write(document));
    }

    [Fact]
    public async Task Writer_InvalidDocumentPreservesExistingTarget()
    {
        var document = new CrypVol.Lib.Crypto.CvkDocument
        {
            Cek = new byte[31],
            KeyProtection = CvkKeyProtection.Plain,
            KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None
        };
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-invalid-preserve-{Guid.NewGuid():N}.cvk"));
        var original = new byte[] { 1, 2, 3, 4 };
        await File.WriteAllBytesAsync(file.FullName, original);
        try
        {
            await Assert.ThrowsAsync<InvalidDataException>(() =>
                new CvkWriter(new PlainCvkPayloadProtector()).WriteAsync(document, file));
            Assert.Equal(original, await File.ReadAllBytesAsync(file.FullName));
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task Writer_PreservesMaximumVersion()
    {
        var document = new CrypVol.Lib.Crypto.CvkDocument
        {
            Cek = new byte[32],
            Version = ushort.MaxValue,
            KeyProtection = CvkKeyProtection.Plain,
            KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None
        };
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-max-version-{Guid.NewGuid():N}.cvk"));
        try
        {
            await new CvkWriter(new PlainCvkPayloadProtector()).WriteAsync(document, file);
            var parsed = CvkParser.Parse(await File.ReadAllBytesAsync(file.FullName));
            Assert.Equal(ushort.MaxValue, parsed.Header.Version);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task Writer_DoesNotMutateDocumentData()
    {
        var document = CrypVol.Lib.Crypto.CvkOperations.CreateNew(CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.None);
        document.Label = "stable";
        var cekBefore = document.Cek.ToArray();
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-snapshot-{Guid.NewGuid():N}.cvk"));
        try
        {
            await new CvkWriter(new PlainCvkPayloadProtector()).WriteAsync(document, file);
            Assert.Equal(cekBefore, document.Cek);
            Assert.Equal("stable", document.Label);
            Assert.Empty(document.RecipientKeys);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task Writer_SnapshotsRecipientCollectionBeforeProtection()
    {
        var document = CrypVol.Lib.Crypto.CvkOperations.CreateNew(CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.None);
        var recipient = new AsymmetricRecipientKey("one", "RSA", new byte[] { 1, 2, 3 });
        document.RecipientKeys.Add(recipient);
        var protector = new SnapshotProtector(document.RecipientKeys);
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-recipient-snapshot-{Guid.NewGuid():N}.cvk"));
        try
        {
            await new CvkWriter(protector).WriteAsync(document, file);
            Assert.Single(protector.ObservedRecipients);
            Assert.Equal("one", protector.ObservedRecipients[0].KeyId);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task Writer_RejectsNullArguments()
    {
        var writer = new CvkWriter(new PlainCvkPayloadProtector());
        await Assert.ThrowsAsync<ArgumentNullException>(() => writer.WriteAsync(null!, new FileInfo("x")));
        var document = new CrypVol.Lib.Crypto.CvkDocument { Cek = new byte[32], KeyProtection = CvkKeyProtection.Plain, KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None };
        await Assert.ThrowsAsync<ArgumentNullException>(() => writer.WriteAsync(document, null!));
    }

    [Fact]
    public void Writer_RejectsNullProtector()
    {
        Assert.Throws<ArgumentNullException>(() => new CvkWriter(null!));
    }

    [Fact]
    public async Task Writer_RejectsInvalidVersion()
    {
        var document = new CrypVol.Lib.Crypto.CvkDocument { Cek = new byte[32], Version = 0, KeyProtection = CvkKeyProtection.Plain, KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None };
        await Assert.ThrowsAsync<InvalidDataException>(() => Write(document));
    }

    [Fact]
    public async Task Writer_RejectsHeaderExceedingParserLimit()
    {
        var document = new CrypVol.Lib.Crypto.CvkDocument
        {
            Cek = new byte[32],
            KeyProtection = CvkKeyProtection.Plain,
            KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None,
            Label = new string('x', 1_100_000)
        };
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-large-header-{Guid.NewGuid():N}.cvk"));
        try
        {
            await Assert.ThrowsAsync<InvalidDataException>(() =>
                new CvkWriter(new PlainCvkPayloadProtector()).WriteAsync(document, file));
            Assert.False(file.Exists);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task Writer_InvalidDocumentDoesNotCreateParentDirectory()
    {
        var parent = new DirectoryInfo(Path.Combine(Path.GetTempPath(), $"cvk-invalid-parent-{Guid.NewGuid():N}"));
        var file = new FileInfo(Path.Combine(parent.FullName, "nested", "value.cvk"));
        var document = new CrypVol.Lib.Crypto.CvkDocument
        {
            Cek = [],
            KeyProtection = CvkKeyProtection.Plain,
            KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None
        };
        try
        {
            await Assert.ThrowsAsync<InvalidDataException>(() =>
                new CvkWriter(new PlainCvkPayloadProtector()).WriteAsync(document, file));
            Assert.False(parent.Exists);
        }
        finally { if (parent.Exists) parent.Delete(true); }
    }

    [Fact]
    public async Task Writer_RejectsInvalidProtectionAlgorithmCombinations()
    {
        var password = new CrypVol.Lib.Crypto.CvkDocument { Cek = new byte[32], KeyProtection = CvkKeyProtection.Password, KeyWrapAlgorithm = CvkKeyWrapAlgorithm.RsaOaepSha256 };
        var publicKey = new CrypVol.Lib.Crypto.CvkDocument { Cek = new byte[32], KeyProtection = CvkKeyProtection.PublicKey, KeyWrapAlgorithm = CvkKeyWrapAlgorithm.RsaOaepSha256 };
        await Assert.ThrowsAsync<InvalidDataException>(() => Write(password));
        await Assert.ThrowsAsync<InvalidDataException>(() => Write(publicKey));
    }

    [Fact]
    public async Task Writer_RejectsUndefinedProtectionAndWrapAlgorithms()
    {
        var invalidProtection = new CrypVol.Lib.Crypto.CvkDocument
        {
            Cek = new byte[32],
            KeyProtection = (CvkKeyProtection)99,
            KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None
        };
        var invalidWrap = new CrypVol.Lib.Crypto.CvkDocument
        {
            Cek = new byte[32],
            KeyProtection = CvkKeyProtection.Plain,
            KeyWrapAlgorithm = (CvkKeyWrapAlgorithm)99
        };
        await Assert.ThrowsAnyAsync<Exception>(() => Write(invalidProtection));
        await Assert.ThrowsAsync<InvalidDataException>(() => Write(invalidWrap));
    }

    [Fact]
    public async Task Writer_RejectsDuplicateRecipientIds()
    {
        var document = new CrypVol.Lib.Crypto.CvkDocument
        {
            Cek = new byte[32],
            KeyProtection = CvkKeyProtection.PublicKey,
            KeyWrapAlgorithm = CvkKeyWrapAlgorithm.RsaOaepSha256
        };
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var publicKey = rsa.ExportSubjectPublicKeyInfo();
        document.RecipientKeys.Add(new CrypVol.Lib.Crypto.Keys.AsymmetricRecipientKey("same", "RSA", publicKey));
        document.RecipientKeys.Add(new CrypVol.Lib.Crypto.Keys.AsymmetricRecipientKey("same", "RSA", publicKey));
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-duplicate-{Guid.NewGuid():N}.cvk"));
        try
        {
            await Assert.ThrowsAnyAsync<Exception>(() => new CvkWriter(new CvkPayloadProtectorAdapter(new RsaOaepSha256Cryptor())).WriteAsync(document, file));
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task Writer_RejectsNullRecipientEntry()
    {
        var document = new CrypVol.Lib.Crypto.CvkDocument
        {
            Cek = new byte[32], KeyProtection = CvkKeyProtection.PublicKey,
            KeyWrapAlgorithm = CvkKeyWrapAlgorithm.RsaOaepSha256
        };
        document.RecipientKeys.Add(null!);
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-null-recipient-{Guid.NewGuid():N}.cvk"));
        try
        {
            await Assert.ThrowsAnyAsync<Exception>(() => new CvkWriter(new CvkPayloadProtectorAdapter(new RsaOaepSha256Cryptor())).WriteAsync(document, file));
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public void Registry_ResolvesEveryRegisteredAlgorithm()
    {
        var registry = CvkPayloadCryptorRegistry.CreateDefault();
        foreach (var algorithm in new[] { CvkKeyWrapAlgorithm.None, CvkKeyWrapAlgorithm.RsaOaepSha256, CvkKeyWrapAlgorithm.RsaOaepSha384, CvkKeyWrapAlgorithm.RsaOaepSha512, CvkKeyWrapAlgorithm.EcdhP256, CvkKeyWrapAlgorithm.EcdhP384, CvkKeyWrapAlgorithm.EcdhP521 })
        {
            var protection = algorithm == CvkKeyWrapAlgorithm.None ? CvkKeyProtection.Plain : CvkKeyProtection.PublicKey;
            Assert.NotNull(registry.Resolve(new CvkHeader(1, protection, algorithm, null, null, null, null, null)));
        }
        var passwordRegistry = CvkPayloadCryptorRegistry.CreateDefault("secret");
        Assert.NotNull(passwordRegistry.Resolve(new CvkHeader(1, CvkKeyProtection.Password, CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256, null, null, null, null, null)));
        Assert.NotNull(passwordRegistry.Resolve(new CvkHeader(1, CvkKeyProtection.Password, CvkKeyWrapAlgorithm.PasswordArgon2Id, null, null, null, null, null)));
    }

    [Fact]
    public void Registry_CoversEveryDeclaredWrapAlgorithm()
    {
        var defaultRegistry = CvkPayloadCryptorRegistry.CreateDefault();
        var passwordRegistry = CvkPayloadCryptorRegistry.CreateDefault("secret");
        foreach (var algorithm in Enum.GetValues<CvkKeyWrapAlgorithm>())
        {
            var protection = algorithm switch
            {
                CvkKeyWrapAlgorithm.None => CvkKeyProtection.Plain,
                CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256 or CvkKeyWrapAlgorithm.PasswordArgon2Id => CvkKeyProtection.Password,
                _ => CvkKeyProtection.PublicKey
            };
            var registry = protection == CvkKeyProtection.Password ? passwordRegistry : defaultRegistry;
            Assert.NotNull(registry.Resolve(new CvkHeader(1, protection, algorithm, null, null, null, null, null)));
        }
    }

    [Fact]
    public async Task Writer_RejectsNullRecipientEntryInPlainMode()
    {
        var document = new CrypVol.Lib.Crypto.CvkDocument
        {
            Cek = new byte[32],
            KeyProtection = CvkKeyProtection.Plain,
            KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None
        };
        document.RecipientKeys.Add(null!);
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-null-plain-recipient-{Guid.NewGuid():N}.cvk"));
        try
        {
            await Assert.ThrowsAnyAsync<Exception>(() =>
                new CvkWriter(new PlainCvkPayloadProtector()).WriteAsync(document, file));
            Assert.False(file.Exists);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task Writer_RejectsEmptyProtectedKeyBody()
    {
        var document = new CrypVol.Lib.Crypto.CvkDocument
        {
            Cek = new byte[32],
            KeyProtection = CvkKeyProtection.Plain,
            KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None
        };
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-empty-body-{Guid.NewGuid():N}.cvk"));
        try
        {
            await Assert.ThrowsAnyAsync<Exception>(() =>
                new CvkWriter(new EmptyProtector()).WriteAsync(document, file));
            Assert.False(file.Exists);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task Writer_ConcurrentWritesLeaveCompleteDocument()
    {
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-concurrent-{Guid.NewGuid():N}.cvk"));
        try
        {
            var first = CrypVol.Lib.Crypto.CvkOperations.CreateNew(CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.None);
            var second = CrypVol.Lib.Crypto.CvkOperations.CreateNew(CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.None);
            await Task.WhenAll(
                CrypVol.Lib.Crypto.CvkOperations.WriteAsync(first, file),
                CrypVol.Lib.Crypto.CvkOperations.WriteAsync(second, file));

            var parsed = CvkParser.Parse(await File.ReadAllBytesAsync(file.FullName));
            Assert.Equal(32, parsed.Integrity.Length);
            Assert.Equal(CvkKeyProtection.Plain, parsed.Header.KeyProtection);
            var loaded = await CrypVol.Lib.Crypto.CvkOperations.LoadAsync(file);
            Assert.True(loaded.Cek.AsSpan().SequenceEqual(first.Cek) ||
                        loaded.Cek.AsSpan().SequenceEqual(second.Cek));
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task Reader_ConcurrentWithAtomicReplacement_SeesOnlyCompleteFiles()
    {
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-concurrent-read-{Guid.NewGuid():N}.cvk"));
        try
        {
            await CrypVol.Lib.Crypto.CvkOperations.WriteAsync(
                CrypVol.Lib.Crypto.CvkOperations.CreateNew(CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.None), file);
            var writes = Enumerable.Range(0, 12).Select(_ =>
                CrypVol.Lib.Crypto.CvkOperations.WriteAsync(
                    CrypVol.Lib.Crypto.CvkOperations.CreateNew(CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.None), file));
            var reads = Enumerable.Range(0, 24).Select(async _ =>
            {
                var parsed = await new CvkReader(new Sha256IntegrityCalculator()).ReadAsync(file);
                Assert.Equal(32, parsed.Integrity.Length);
            });

            await Task.WhenAll(writes.Concat(reads));
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task Writer_ConcurrentFailureDoesNotCorruptSuccessfulWrite()
    {
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-concurrent-failure-{Guid.NewGuid():N}.cvk"));
        try
        {
            var document = CrypVol.Lib.Crypto.CvkOperations.CreateNew(CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.None);
            var successful = CrypVol.Lib.Crypto.CvkOperations.WriteAsync(document, file);
            var failingDocument = CrypVol.Lib.Crypto.CvkOperations.CreateNew(CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.None);
            var failing = new CvkWriter(new ThrowingProtector()).WriteAsync(failingDocument, file);

            await Assert.ThrowsAsync<InvalidOperationException>(async () => await failing);
            await successful;

            var loaded = await CrypVol.Lib.Crypto.CvkOperations.LoadAsync(file);
            Assert.Equal(document.Cek, loaded.Cek);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public void Registry_RejectsUnknownRoute()
    {
        var registry = CvkPayloadCryptorRegistry.CreateDefault();
        Assert.Throws<NotSupportedException>(() => registry.Resolve(new CvkHeader(1, CvkKeyProtection.Password, CvkKeyWrapAlgorithm.RsaOaepSha256, null, null, null, null, null)));
    }

    [Fact]
    public void Registry_RejectsUndefinedRouteRegistration()
    {
        var registry = new CvkPayloadCryptorRegistry();
        Assert.ThrowsAny<Exception>(() => registry.Register((CvkKeyProtection)99,
            (CvkKeyWrapAlgorithm)99, new PlainCvkPayloadCryptor()));
    }

    [Fact]
    public void CvkEnums_SerializeAsStableNames()
    {
        var json = JsonSerializer.Serialize(new CvkHeader(1, CvkKeyProtection.PublicKey,
            CvkKeyWrapAlgorithm.EcdhP521, null, null, null, null, null));
        Assert.Contains("\"keyProtection\":\"PublicKey\"", json, StringComparison.Ordinal);
        Assert.Contains("\"keyWrapAlgorithm\":\"EcdhP521\"", json, StringComparison.Ordinal);
        Assert.DoesNotContain("\"keyProtection\":2", json, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256)]
    [InlineData(CvkKeyWrapAlgorithm.PasswordArgon2Id)]
    public void Registry_DefaultDoesNotRegisterPasswordCryptors(CvkKeyWrapAlgorithm algorithm)
    {
        Assert.Throws<NotSupportedException>(() =>
            CvkPayloadCryptorRegistry.CreateDefault().Resolve(
                new CvkHeader(1, CvkKeyProtection.Password, algorithm, null, null, null, null, null)));
    }

    [Fact]
    public void Registry_RejectsEmptyPasswordFactoryInput()
    {
        Assert.Throws<ArgumentException>(() => CvkPayloadCryptorRegistry.CreateDefault(string.Empty));
        Assert.Throws<ArgumentException>(() => CvkPayloadCryptorRegistry.CreateDefault(null!));
    }

    [Fact]
    public void Registry_RejectsNullAndAllowsExplicitOverride()
    {
        var registry = new CvkPayloadCryptorRegistry();
        Assert.Throws<ArgumentNullException>(() => registry.Register(CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.None, null!));
        var first = new PlainCvkPayloadCryptor();
        var second = new PlainCvkPayloadCryptor();
        registry.Register(CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.None, first);
        registry.Register(CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.None, second);
        Assert.Same(second, registry.Resolve(new CvkHeader(1, CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.None, null, null, null, null, null)));
        Assert.ThrowsAny<Exception>(() => registry.Resolve(null!));
    }

    [Fact]
    public void PayloadAdapters_RejectNullInnerProcessor()
    {
        Assert.Throws<ArgumentNullException>(() => new CvkPayloadProtectorAdapter(null!));
        Assert.Throws<ArgumentNullException>(() => new CvkPayloadUnprotectorAdapter(null!));
    }

    [Fact]
    public async Task PlainProtector_RejectsNonPlainRoute()
    {
        var header = new CvkHeader(1, CvkKeyProtection.Plain,
            CvkKeyWrapAlgorithm.RsaOaepSha256, null, null, null, null, null);
        var payload = new CvkPayload(new byte[32], Array.Empty<AsymmetricRecipientKey>());
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await new PlainCvkPayloadProtector().ProtectAsync(header, payload));
    }

    [Fact]
    public async Task PlainUnprotector_RejectsNonPlainWrapAlgorithm()
    {
        var header = new CvkHeader(1, CvkKeyProtection.Plain,
            CvkKeyWrapAlgorithm.RsaOaepSha256, null, null, null, null, null);
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await new PlainCvkPayloadUnprotector().UnprotectAsync(header, "{}"u8.ToArray()));
    }

    [Fact]
    public async Task PlainUnprotector_RejectsRouteBeforeCancellation()
    {
        var header = new CvkHeader(1, CvkKeyProtection.PublicKey,
            CvkKeyWrapAlgorithm.None, null, null, null, null, null);
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await new PlainCvkPayloadUnprotector().UnprotectAsync(header, "{}"u8.ToArray(), cts.Token));
    }

    [Fact]
    public async Task AlgorithmCryptor_RejectsMismatchedRouteBeforeCancellation()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var header = new CvkHeader(1, CvkKeyProtection.Plain,
            CvkKeyWrapAlgorithm.None, null, null, null, null, null);
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await new RsaOaepSha256Cryptor().ProtectAsync(header,
                new CvkPayload(new byte[32], Array.Empty<AsymmetricRecipientKey>()), cts.Token));
    }

    [Fact]
    public void IntegrityCalculator_IsDeterministicAndInputSensitive()
    {
        var calculator = new Sha256IntegrityCalculator();
        var first = calculator.Compute("header"u8.ToArray(), "body"u8.ToArray());
        var second = calculator.Compute("header"u8.ToArray(), "body"u8.ToArray());
        var changed = calculator.Compute("header2"u8.ToArray(), "body"u8.ToArray());
        var changedBody = calculator.Compute("header"u8.ToArray(), "body2"u8.ToArray());
        Assert.Equal(first.ToArray(), second.ToArray());
        Assert.NotEqual(first.ToArray(), changed.ToArray());
        Assert.NotEqual(first.ToArray(), changedBody.ToArray());
        Assert.Equal(32, first.Length);
    }

    [Fact]
    public void IntegrityCalculator_SupportsEmptySegments()
    {
        var digest = new Sha256IntegrityCalculator().Compute(ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty);

        Assert.Equal(32, digest.Length);
        Assert.NotEqual(new byte[32], digest.ToArray());
    }

    [Fact]
    public void IntegrityCalculator_DistinguishesSegmentBoundaries()
    {
        var calculator = new Sha256IntegrityCalculator();
        var first = calculator.Compute("ab"u8.ToArray(), "c"u8.ToArray());
        var second = calculator.Compute("a"u8.ToArray(), "bc"u8.ToArray());

        Assert.NotEqual(first.ToArray(), second.ToArray());
    }

    [Fact]
    public void IntegrityCalculator_DoesNotMutateInputs()
    {
        var header = "header"u8.ToArray();
        var body = "body"u8.ToArray();
        var headerBefore = header.ToArray();
        var bodyBefore = body.ToArray();

        _ = new Sha256IntegrityCalculator().Compute(header, body);

        Assert.Equal(headerBefore, header);
        Assert.Equal(bodyBefore, body);
    }

    [Fact]
    public void IntegrityCalculator_HandlesLargeSegments()
    {
        var header = new byte[1024 * 1024];
        var body = new byte[2 * 1024 * 1024];
        RandomNumberGenerator.Fill(header);
        RandomNumberGenerator.Fill(body);

        var digest = new Sha256IntegrityCalculator().Compute(header, body);

        Assert.Equal(32, digest.Length);
    }

    [Fact]
    public async Task PlainCryptor_RejectsMismatchedHeaderAndInvalidJson()
    {
        var cryptor = new PlainCvkPayloadCryptor();
        var wrongHeader = new CvkHeader(1, CvkKeyProtection.Password, CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256, null, null, null, null, null);
        await Assert.ThrowsAsync<InvalidOperationException>(() => cryptor.ProtectAsync(wrongHeader, new CvkPayload(new byte[32], [])).AsTask());
        var header = new CvkHeader(1, CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.None, null, null, null, null, null);
        await Assert.ThrowsAsync<InvalidDataException>(() => cryptor.UnprotectAsync(header, "not-json"u8.ToArray()).AsTask());
    }

    [Theory]
    [InlineData("{\"cek\":\"AQI=\",\"recipientKeys\":[]}")]
    [InlineData("{\"cek\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"recipientKeys\":null}")]
    [InlineData("{\"cek\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"recipientKeys\":[null]}")]
    public async Task PlainPayloadUnprotector_RejectsSemanticallyMalformedPayloads(string json)
    {
        var header = new CvkHeader(1, CvkKeyProtection.Plain, CvkKeyWrapAlgorithm.None, null, null, null, null, null);
        var unprotector = new PlainCvkPayloadUnprotector();

        // JSON 语法有效，但 CEK 长度和接收者集合均不满足 CVK 契约；
        // 明文路径也必须执行与统一 Payload 编解码器相同的语义校验。
        await Assert.ThrowsAnyAsync<Exception>(() =>
            unprotector.UnprotectAsync(header, Encoding.UTF8.GetBytes(json)).AsTask());
    }

    [Fact]
    public void PayloadCodec_RoundTripsRecipientsAndCek()
    {
        var recipient = new CrypVol.Lib.Crypto.Keys.AsymmetricRecipientKey("id", "RSA", new byte[] { 1, 2, 3 }, "comment");
        var payload = new CvkPayload(new byte[32], [recipient]);
        var restored = CvkPayloadCodec.Decode(CvkPayloadCodec.Encode(payload));
        Assert.Equal(payload.Cek.ToArray(), restored.Cek.ToArray());
        Assert.Equal("id", restored.RecipientKeys[0].KeyId);
        Assert.Equal("comment", restored.RecipientKeys[0].Comment);
    }

    [Fact]
    public void PayloadCodec_RejectsMalformedJson()
    {
        Assert.Throws<InvalidDataException>(() => CvkPayloadCodec.Decode("{bad"u8));
    }

    [Fact]
    public void PayloadCodec_RejectsDuplicateFields()
    {
        var json = "{\"cek\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"cek\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"recipientKeys\":[]}";
        Assert.ThrowsAny<Exception>(() => CvkPayloadCodec.Decode(System.Text.Encoding.UTF8.GetBytes(json)));
    }

    [Fact]
    public void PayloadCodec_RejectsDuplicateNestedRecipientFields()
    {
        var json = "{\"cek\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"recipientKeys\":[{\"keyId\":\"id\",\"keyId\":\"other\",\"algorithm\":\"RSA\",\"publicKey\":\"AQI=\"}]}";
        Assert.ThrowsAny<Exception>(() => CvkPayloadCodec.Decode(System.Text.Encoding.UTF8.GetBytes(json)));
    }

    [Fact]
    public void PayloadCodec_RejectsTrailingGarbage()
    {
        var json = "{\"cek\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"recipientKeys\":[]}garbage";
        Assert.ThrowsAny<Exception>(() => CvkPayloadCodec.Decode(System.Text.Encoding.UTF8.GetBytes(json)));
    }

    [Fact]
    public void PayloadCodec_RejectsUnknownFields()
    {
        var json = "{\"cek\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"recipientKeys\":[],\"unexpected\":true}";
        Assert.ThrowsAny<Exception>(() => CvkPayloadCodec.Decode(System.Text.Encoding.UTF8.GetBytes(json)));
    }

    [Theory]
    [InlineData("CEK")]
    [InlineData("RecipientKeys")]
    public void PayloadCodec_RejectsNonCanonicalFieldCasing(string field)
    {
        var json = field == "CEK"
            ? "{\"CEK\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"recipientKeys\":[]}" 
            : "{\"cek\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"RecipientKeys\":[]}";
        Assert.ThrowsAny<Exception>(() => CvkPayloadCodec.Decode(Encoding.UTF8.GetBytes(json)));
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"cek\":null,\"recipientKeys\":[]}")]
    [InlineData("{\"cek\":\"AQI=\",\"recipientKeys\":null}")]
    public void PayloadCodec_RejectsMissingRequiredData(string json)
    {
        Assert.ThrowsAny<Exception>(() => CvkPayloadCodec.Decode(System.Text.Encoding.UTF8.GetBytes(json)));
    }

    [Fact]
    public void PayloadCodec_RejectsInvalidBase64AndEmptyCek()
    {
        Assert.ThrowsAny<Exception>(() => CvkPayloadCodec.Decode("{\"cek\":\"!not-base64!\",\"recipientKeys\":[]}"u8));
        Assert.ThrowsAny<Exception>(() => CvkPayloadCodec.Decode("{\"cek\":\"\",\"recipientKeys\":[]}"u8));
    }

    [Theory]
    [InlineData("{\"cek\":123,\"recipientKeys\":[]}")]
    [InlineData("{\"cek\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"recipientKeys\":[{\"keyId\":\"id\",\"algorithm\":\"RSA\",\"publicKey\":123}]}")]
    public void PayloadCodec_RejectsNumericBinaryFields(string json)
    {
        Assert.ThrowsAny<Exception>(() => CvkPayloadCodec.Decode(Encoding.UTF8.GetBytes(json)));
    }

    [Theory]
    [InlineData(31)]
    [InlineData(33)]
    public void PayloadCodec_RejectsCekLengthsOtherThan32(int length)
    {
        var encoded = Convert.ToBase64String(new byte[length]);
        var json = $"{{\"cek\":\"{encoded}\",\"recipientKeys\":[]}}";
        Assert.ThrowsAny<Exception>(() => CvkPayloadCodec.Decode(Encoding.UTF8.GetBytes(json)));
    }

    [Fact]
    public void PayloadCodec_AcceptsExactly32ByteCek()
    {
        var json = "{\"cek\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"recipientKeys\":[]}";

        var payload = CvkPayloadCodec.Decode(Encoding.UTF8.GetBytes(json));

        Assert.Equal(32, payload.Cek.Length);
        Assert.Empty(payload.RecipientKeys);
    }

    [Fact]
    public void PayloadCodec_RejectsNonArrayRecipients()
    {
        Assert.ThrowsAny<Exception>(() => CvkPayloadCodec.Decode("{\"cek\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"recipientKeys\":{}}"u8));
    }

    [Theory]
    [InlineData("{\"algorithm\":\"RSA\",\"publicKey\":\"AQI=\"}")]
    [InlineData("{\"keyId\":\"id\",\"publicKey\":\"AQI=\"}")]
    [InlineData("{\"keyId\":\"id\",\"algorithm\":\"RSA\"}")]
    [InlineData("{\"keyId\":\"\",\"algorithm\":\"RSA\",\"publicKey\":\"AQI=\"}")]
    [InlineData("{\"keyId\":null,\"algorithm\":\"RSA\",\"publicKey\":\"AQI=\"}")]
    [InlineData("{\"keyId\":\"id\",\"algorithm\":null,\"publicKey\":\"AQI=\"}")]
    [InlineData("{\"keyId\":\"id\",\"algorithm\":\"RSA\",\"publicKey\":null}")]
    public void PayloadCodec_RejectsInvalidRecipientMetadata(string recipient)
    {
        var json = $"{{\"cek\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"recipientKeys\":[{recipient}]}}";
        Assert.ThrowsAny<Exception>(() => CvkPayloadCodec.Decode(System.Text.Encoding.UTF8.GetBytes(json)));
    }

    [Theory]
    [InlineData("ECDSA")]
    [InlineData("Unknown")]
    [InlineData("rsa")]
    public void PayloadCodec_RejectsUnsupportedRecipientAlgorithms(string algorithm)
    {
        var json = $"{{\"cek\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"recipientKeys\":[{{\"keyId\":\"id\",\"algorithm\":\"{algorithm}\",\"publicKey\":\"AQI=\"}}]}}";
        Assert.ThrowsAny<Exception>(() => CvkPayloadCodec.Decode(Encoding.UTF8.GetBytes(json)));
    }

    [Fact]
    public void PayloadCodec_RejectsNullRecipientPublicKey()
    {
        var json = "{\"cek\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"recipientKeys\":[{\"keyId\":\"id\",\"algorithm\":\"RSA\",\"publicKey\":null}]}";
        Assert.ThrowsAny<Exception>(() => CvkPayloadCodec.Decode(System.Text.Encoding.UTF8.GetBytes(json)));
    }

    [Fact]
    public void PayloadCodec_RejectsEmptyRecipientPublicKey()
    {
        var json = "{\"cek\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"recipientKeys\":[{\"keyId\":\"id\",\"algorithm\":\"RSA\",\"publicKey\":\"\"}]}";
        Assert.ThrowsAny<Exception>(() => CvkPayloadCodec.Decode(System.Text.Encoding.UTF8.GetBytes(json)));
    }

    [Fact]
    public void PayloadCodec_RejectsNullRecipientElement()
    {
        var json = "{\"cek\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"recipientKeys\":[null]}";
        Assert.ThrowsAny<Exception>(() => CvkPayloadCodec.Decode(System.Text.Encoding.UTF8.GetBytes(json)));
    }

    [Fact]
    public void PayloadCodec_RejectsOversizedCek()
    {
        var oversized = Convert.ToBase64String(new byte[33]);
        Assert.ThrowsAny<Exception>(() => CvkPayloadCodec.Decode(System.Text.Encoding.UTF8.GetBytes($"{{\"cek\":\"{oversized}\",\"recipientKeys\":[]}}")));
    }

    [Fact]
    public void PayloadCodec_RejectsNullPayloadArguments()
    {
        Assert.ThrowsAny<Exception>(() => CvkPayloadCodec.Encode(null!));
        Assert.ThrowsAny<Exception>(() => CvkPayloadCodec.Encode(new CvkPayload(new byte[32], null!)));
        Assert.ThrowsAny<Exception>(() => CvkPayloadCodec.EncodeHeader(null!));
    }

    [Fact]
    public void Parser_RejectsInvalidSemanticEnums()
    {
        Assert.Throws<InvalidDataException>(() => CvkParser.Parse(BuildHeader("{\"version\":1,\"keyProtection\":99,\"keyWrapAlgorithm\":\"None\"}")));
        Assert.Throws<InvalidDataException>(() => CvkParser.Parse(BuildHeader("{\"version\":1,\"keyProtection\":\"Plain\",\"keyWrapAlgorithm\":\"RsaOaepSha256\"}")));
        Assert.Throws<InvalidDataException>(() => CvkParser.Parse(BuildHeader("{\"version\":1,\"keyProtection\":\"Password\",\"keyWrapAlgorithm\":\"RsaOaepSha256\"}")));
        Assert.Throws<InvalidDataException>(() => CvkParser.Parse(BuildHeader("{\"version\":1,\"keyProtection\":\"PublicKey\",\"keyWrapAlgorithm\":\"PasswordPbkdf2Sha256\"}")));
        Assert.Throws<InvalidDataException>(() => CvkParser.Parse(BuildHeader("{\"keyProtection\":\"Plain\",\"keyWrapAlgorithm\":\"None\"}")));
    }

    [Fact]
    public void Parser_AcceptsMaximumSupportedVersion()
    {
        var parsed = CvkParser.Parse(BuildHeader("{\"version\":65535,\"keyProtection\":\"Plain\",\"keyWrapAlgorithm\":\"None\"}"));
        Assert.Equal(ushort.MaxValue, parsed.Header.Version);
    }

    [Fact]
    public void Parser_RejectsVersionOverflow()
    {
        Assert.ThrowsAny<Exception>(() =>
            CvkParser.Parse(BuildHeader("{\"version\":65536,\"keyProtection\":\"Plain\",\"keyWrapAlgorithm\":\"None\"}")));
    }

    [Theory]
    [InlineData("Plain", "PasswordPbkdf2Sha256")]
    [InlineData("Plain", "RsaOaepSha256")]
    [InlineData("Plain", "EcdhP256")]
    [InlineData("Password", "None")]
    [InlineData("Password", "RsaOaepSha256")]
    [InlineData("Password", "EcdhP256")]
    [InlineData("PublicKey", "None")]
    [InlineData("PublicKey", "PasswordPbkdf2Sha256")]
    public void Parser_RejectsEveryProtectionAndWrapMismatch(string protection, string algorithm)
    {
        var json = $"{{\"version\":1,\"keyProtection\":\"{protection}\",\"keyWrapAlgorithm\":\"{algorithm}\"}}";
        Assert.Throws<InvalidDataException>(() => CvkParser.Parse(BuildHeader(json)));
    }

    [Fact]
    public void Parser_RejectsUnknownEnumNames()
    {
        Assert.Throws<InvalidDataException>(() => CvkParser.Parse(BuildHeader("{\"version\":1,\"keyProtection\":\"Unknown\",\"keyWrapAlgorithm\":\"None\"}")));
        Assert.Throws<InvalidDataException>(() => CvkParser.Parse(BuildHeader("{\"version\":1,\"keyProtection\":\"Plain\",\"keyWrapAlgorithm\":\"Unknown\"}")));
        Assert.Throws<InvalidDataException>(() => CvkParser.Parse(BuildHeader("{\"version\":1,\"keyProtection\":\"0\",\"keyWrapAlgorithm\":\"None\"}")));
    }

    [Theory]
    [InlineData("plain", "None")]
    [InlineData("Plain", "none")]
    [InlineData("password", "PasswordPbkdf2Sha256")]
    public void Parser_RejectsNonCanonicalEnumNames(string protection, string algorithm)
    {
        var json = $"{{\"version\":1,\"keyProtection\":\"{protection}\",\"keyWrapAlgorithm\":\"{algorithm}\"}}";
        Assert.Throws<InvalidDataException>(() => CvkParser.Parse(BuildHeader(json)));
    }

    [Fact]
    public void Parser_RejectsMissingOrNullRouteFields()
    {
        Assert.Throws<InvalidDataException>(() => CvkParser.Parse(BuildHeader("{\"version\":1}")));
        Assert.Throws<InvalidDataException>(() => CvkParser.Parse(BuildHeader("{\"version\":1,\"keyProtection\":null,\"keyWrapAlgorithm\":\"None\"}")));
        Assert.Throws<InvalidDataException>(() => CvkParser.Parse(BuildHeader("{\"version\":1,\"keyProtection\":\"Plain\",\"keyWrapAlgorithm\":null}")));
    }

    [Fact]
    public void Parser_RejectsDuplicateHeaderFields()
    {
        var json = "{\"version\":1,\"version\":1,\"keyProtection\":\"Plain\",\"keyWrapAlgorithm\":\"None\"}";
        Assert.ThrowsAny<Exception>(() => CvkParser.Parse(BuildHeader(json)));
    }

    [Theory]
    [InlineData("0", "0")]
    [InlineData("1", "1")]
    public void Parser_RejectsNumericEnumValues(string protection, string algorithm)
    {
        var json = $"{{\"version\":1,\"keyProtection\":{protection},\"keyWrapAlgorithm\":{algorithm}}}";
        Assert.ThrowsAny<Exception>(() => CvkParser.Parse(BuildHeader(json)));
    }

    [Theory]
    [InlineData("not-a-time")]
    [InlineData("123")]
    public void Parser_RejectsInvalidCreatedAt(string createdAt)
    {
        var json = $"{{\"version\":1,\"keyProtection\":\"Plain\",\"keyWrapAlgorithm\":\"None\",\"createdAt\":\"{createdAt}\"}}";
        Assert.ThrowsAny<Exception>(() => CvkParser.Parse(BuildHeader(json)));
    }

    [Fact]
    public void Parser_RejectsWrongCreatedAtType()
    {
        Assert.ThrowsAny<Exception>(() => CvkParser.Parse(BuildHeader("{\"version\":1,\"keyProtection\":\"Plain\",\"keyWrapAlgorithm\":\"None\",\"createdAt\":123}")));
    }

    [Theory]
    [InlineData("label", "123")]
    [InlineData("description", "{}")]
    [InlineData("comment", "[]")]
    [InlineData("generator", "false")]
    public void Parser_RejectsWrongStringMetadataType(string field, string value)
    {
        var json = $"{{\"version\":1,\"keyProtection\":\"Plain\",\"keyWrapAlgorithm\":\"None\",\"{field}\":{value}}}";
        Assert.ThrowsAny<Exception>(() => CvkParser.Parse(BuildHeader(json)));
    }

    [Fact]
    public void Parser_RejectsUnknownHeaderFields()
    {
        var json = "{\"version\":1,\"keyProtection\":\"Plain\",\"keyWrapAlgorithm\":\"None\",\"unexpected\":true}";
        Assert.ThrowsAny<Exception>(() => CvkParser.Parse(BuildHeader(json)));
    }

    [Fact]
    public void Parser_RejectsZeroOrMismatchedSegmentLengths()
    {
        var valid = BuildHeader("{\"version\":1,\"keyProtection\":\"Plain\",\"keyWrapAlgorithm\":\"None\"}");
        valid[8] = 0;
        Assert.Throws<InvalidDataException>(() => CvkParser.Parse(valid));
        valid = BuildHeader("{\"version\":1,\"keyProtection\":\"Plain\",\"keyWrapAlgorithm\":\"None\"}");
        valid[4] = 0;
        Assert.Throws<InvalidDataException>(() => CvkParser.Parse(valid));
        valid = BuildHeader("{\"version\":1,\"keyProtection\":\"Plain\",\"keyWrapAlgorithm\":\"None\"}");
        valid[12] = 0;
        Assert.Throws<InvalidDataException>(() => CvkParser.Parse(valid));
        valid = BuildHeader("{\"version\":1,\"keyProtection\":\"Plain\",\"keyWrapAlgorithm\":\"None\"}");
        BinaryPrimitives.WriteUInt32LittleEndian(valid.AsSpan(8), 2);
        Assert.Throws<InvalidDataException>(() => CvkParser.Parse(valid));
    }

    [Fact]
    public void Parser_RejectsOversizedSegmentLengths()
    {
        var bytes = new byte[16];
        "CVK1"u8.CopyTo(bytes);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4), 1_048_577);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(8), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(12), 32);
        Assert.Throws<InvalidDataException>(() => CvkParser.Parse(bytes));
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(8), 268_435_457);
        Assert.Throws<InvalidDataException>(() => CvkParser.Parse(bytes));
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(8), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(12), 4_097);
        Assert.Throws<InvalidDataException>(() => CvkParser.Parse(bytes));
    }

    [Fact]
    public void Parser_AcceptsMaximumIntegritySegmentLength()
    {
        var source = BuildHeader("{\"version\":1,\"keyProtection\":\"Plain\",\"keyWrapAlgorithm\":\"None\"}");
        var expanded = new byte[source.Length + 4_096 - 32];
        source.CopyTo(expanded, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(expanded.AsSpan(12), 4_096);

        var parsed = CvkParser.Parse(expanded);

        Assert.Equal(4_096, parsed.Integrity.Length);
    }

    [Fact]
    public void Parser_AcceptsHeaderAtLengthLimit()
    {
        const string prefix = "{\"version\":1,\"keyProtection\":\"Plain\",\"keyWrapAlgorithm\":\"None\",\"label\":\"";
        const string suffix = "\"}";
        var label = new string('x', 1_048_576 - Encoding.UTF8.GetByteCount(prefix) - Encoding.UTF8.GetByteCount(suffix));
        var json = prefix + label + suffix;
        Assert.Equal(1_048_576, Encoding.UTF8.GetByteCount(json));

        var parsed = CvkParser.Parse(BuildHeader(json));

        Assert.Equal(label, parsed.Header.Label);
    }

    [Fact]
    public void Parser_RejectsTrailingBytesAfterIntegritySegment()
    {
        var valid = BuildHeader("{\"version\":1,\"keyProtection\":\"Plain\",\"keyWrapAlgorithm\":\"None\"}");
        var withTrailing = valid.Concat(new byte[] { 0x7F }).ToArray();
        Assert.Throws<InvalidDataException>(() => CvkParser.Parse(withTrailing));
    }

    [Fact]
    public void Parser_CopiesSegmentMemoryFromInput()
    {
        var input = BuildHeader("{\"version\":1,\"keyProtection\":\"Plain\",\"keyWrapAlgorithm\":\"None\"}");
        var parsed = CvkParser.Parse(input);
        var headerBefore = parsed.HeaderJson.ToArray();
        var bodyBefore = parsed.KeyBody.ToArray();
        var integrityBefore = parsed.Integrity.ToArray();
        Array.Fill(input, (byte)0, 16, input.Length - 16);
        Assert.Equal(headerBefore, parsed.HeaderJson.ToArray());
        Assert.Equal(bodyBefore, parsed.KeyBody.ToArray());
        Assert.Equal(integrityBefore, parsed.Integrity.ToArray());
    }

    [Fact]
    public void Parser_OnlyParsesStructureWithoutVerifyingIntegrity()
    {
        var input = BuildHeader("{\"version\":1,\"keyProtection\":\"Plain\",\"keyWrapAlgorithm\":\"None\"}");
        var parsed = CvkParser.Parse(input);
        Assert.All(parsed.Integrity.ToArray(), value => Assert.Equal(0, value));
    }

    [Fact]
    public async Task Reader_RejectsStructurallyValidButZeroIntegrity()
    {
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-zero-integrity-{Guid.NewGuid():N}.cvk"));
        try
        {
            await File.WriteAllBytesAsync(file.FullName, BuildHeader("{\"version\":1,\"keyProtection\":\"Plain\",\"keyWrapAlgorithm\":\"None\"}"));
            await Assert.ThrowsAsync<CryptographicException>(() => new CvkReader(new Sha256IntegrityCalculator()).ReadAsync(file));
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task Reader_PropagatesIntegrityCalculatorFailure()
    {
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-integrity-exception-{Guid.NewGuid():N}.cvk"));
        try
        {
            var document = new CrypVol.Lib.Crypto.CvkDocument { Cek = new byte[32], KeyProtection = CvkKeyProtection.Plain, KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None };
            await new CvkWriter(new PlainCvkPayloadProtector()).WriteAsync(document, file);
            await Assert.ThrowsAsync<InvalidOperationException>(() => new CvkReader(new ThrowingIntegrity()).ReadAsync(file));
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public void Parser_RejectsEmptyOrMalformedHeaderJson()
    {
        var empty = BuildHeader(" ");
        Assert.Throws<InvalidDataException>(() => CvkParser.Parse(empty));
        var malformed = BuildHeader("{not-json}");
        Assert.Throws<InvalidDataException>(() => CvkParser.Parse(malformed));
    }

    [Fact]
    public void Parser_RejectsInvalidMagic()
    {
        var bytes = BuildHeader("{\"version\":1,\"keyProtection\":\"Plain\",\"keyWrapAlgorithm\":\"None\"}");
        bytes[0] = (byte)'X';
        Assert.Throws<InvalidDataException>(() => CvkParser.Parse(bytes));
    }

    [Fact]
    public void Parser_RejectsCaseVariantMagic()
    {
        var bytes = BuildHeader("{\"version\":1,\"keyProtection\":\"Plain\",\"keyWrapAlgorithm\":\"None\"}");
        bytes[0] = (byte)'c';
        Assert.Throws<InvalidDataException>(() => CvkParser.Parse(bytes));
    }

    [Fact]
    public void Parser_AcceptsHeaderJsonWithCrLfWhitespace()
    {
        var header = "{\r\n  \"version\": 1,\r\n  \"keyProtection\": \"Plain\",\r\n  \"keyWrapAlgorithm\": \"None\"\r\n}";
        var parsed = CvkParser.Parse(BuildHeader(header));

        Assert.Equal((ushort)1, parsed.Header.Version);
        Assert.Equal(CvkKeyProtection.Plain, parsed.Header.KeyProtection);
    }

    [Fact]
    public void Parser_AcceptsUtf8BomInHeaderJson()
    {
        var parsed = BuildHeader("\uFEFF{\"version\":1,\"keyProtection\":\"Plain\",\"keyWrapAlgorithm\":\"None\"}");

        Assert.Equal((ushort)1, CvkParser.Parse(parsed).Header.Version);
    }

    [Fact]
    public void Parser_RejectsEmptyAndShortBuffers()
    {
        Assert.Throws<InvalidDataException>(() => CvkParser.Parse(ReadOnlyMemory<byte>.Empty));
        Assert.Throws<InvalidDataException>(() => CvkParser.Parse(new byte[15]));
    }

    [Fact]
    public void Parser_RejectsInvalidUtf8Header()
    {
        var bytes = BuildHeader("{}");
        var headerLength = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(4));
        bytes[16] = 0xFF;
        Assert.Throws<InvalidDataException>(() => CvkParser.Parse(bytes));
        Assert.True(headerLength > 0);
    }

    [Fact]
    public async Task Reader_RejectsMissingFile()
    {
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"missing-{Guid.NewGuid():N}.cvk"));
        await Assert.ThrowsAsync<FileNotFoundException>(() => new CvkReader(new Sha256IntegrityCalculator()).ReadAsync(file));
    }

    [Fact]
    public async Task Reader_DocumentLoad_HonorsCancellation()
    {
        var document = new CrypVol.Lib.Crypto.CvkDocument
        {
            Cek = new byte[32],
            KeyProtection = CvkKeyProtection.Plain,
            KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None
        };
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-reader-cancel-{Guid.NewGuid():N}.cvk"));
        await new CvkWriter(new PlainCvkPayloadProtector()).WriteAsync(document, file);
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        try
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                new CvkReader(new Sha256IntegrityCalculator(), new PlainCvkPayloadUnprotector()).ReadDocumentAsync(file, cts.Token));
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task Reader_RejectsDirectoryPath()
    {
        var directory = new DirectoryInfo(Path.Combine(Path.GetTempPath(), $"cvk-directory-{Guid.NewGuid():N}"));
        directory.Create();
        try
        {
            await Assert.ThrowsAnyAsync<Exception>(() => new CvkReader(new Sha256IntegrityCalculator()).ReadAsync(new FileInfo(directory.FullName)));
        }
        finally { directory.Delete(); }
    }

    [Fact]
    public void Reader_RejectsNullDependencies()
    {
        Assert.Throws<ArgumentNullException>(() => new CvkReader(null!));
    }

    [Fact]
    public async Task Reader_RejectsNullAndMissingFileArguments()
    {
        var reader = new CvkReader(new Sha256IntegrityCalculator());
        await Assert.ThrowsAsync<ArgumentNullException>(() => reader.ReadAsync(null!));

        var path = Path.Combine(Path.GetTempPath(), $"cvk-missing-{Guid.NewGuid():N}.cvk");
        await Assert.ThrowsAsync<FileNotFoundException>(() => reader.ReadAsync(new FileInfo(path)));
    }

    [Fact]
    public async Task Reader_DocumentLoad_RejectsNullFileArgument()
    {
        var reader = new CvkReader(new Sha256IntegrityCalculator(), new PlainCvkPayloadUnprotector());
        await Assert.ThrowsAsync<ArgumentNullException>(() => reader.ReadDocumentAsync(null!));
    }

    [Fact]
    public async Task Reader_DocumentLoadRequiresUnprotector()
    {
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-reader-{Guid.NewGuid():N}.cvk"));
        try
        {
            var document = new CrypVol.Lib.Crypto.CvkDocument { Cek = new byte[32], KeyProtection = CvkKeyProtection.Plain, KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None };
            await new CvkWriter(new PlainCvkPayloadProtector()).WriteAsync(document, file);
            await Assert.ThrowsAsync<InvalidOperationException>(() => new CvkReader(new Sha256IntegrityCalculator()).ReadDocumentAsync(file));
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task Reader_ReadHonorsCancellation()
    {
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-reader-cancel-{Guid.NewGuid():N}.cvk"));
        try
        {
            var document = new CrypVol.Lib.Crypto.CvkDocument { Cek = new byte[32], KeyProtection = CvkKeyProtection.Plain, KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None };
            await new CvkWriter(new PlainCvkPayloadProtector()).WriteAsync(document, file);
            using var cts = new CancellationTokenSource();
            cts.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new CvkReader(new Sha256IntegrityCalculator()).ReadAsync(file, cts.Token));
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task Reader_DocumentLoadHonorsCancellation()
    {
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-reader-document-cancel-{Guid.NewGuid():N}.cvk"));
        try
        {
            var document = new CrypVol.Lib.Crypto.CvkDocument
            {
                Cek = new byte[32],
                KeyProtection = CvkKeyProtection.Plain,
                KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None
            };
            await new CvkWriter(new PlainCvkPayloadProtector()).WriteAsync(document, file);
            using var cts = new CancellationTokenSource();
            cts.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                new CvkReader(new Sha256IntegrityCalculator(), new PlainCvkPayloadUnprotector())
                    .ReadDocumentAsync(file, cts.Token));
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task Reader_RejectsIncorrectIntegrityCalculator()
    {
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-integrity-{Guid.NewGuid():N}.cvk"));
        try
        {
            var document = new CrypVol.Lib.Crypto.CvkDocument { Cek = new byte[32], KeyProtection = CvkKeyProtection.Plain, KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None };
            await new CvkWriter(new PlainCvkPayloadProtector()).WriteAsync(document, file);
            var wrong = new CvkReader(new ConstantIntegrityCalculator());
            await Assert.ThrowsAsync<System.Security.Cryptography.CryptographicException>(() => wrong.ReadAsync(file));
        }
        finally { if (file.Exists) file.Delete(); }
    }

    private sealed class ConstantIntegrityCalculator : ICvkIntegrityCalculator
    {
        public ReadOnlyMemory<byte> Compute(ReadOnlyMemory<byte> headerJson, ReadOnlyMemory<byte> keyBody) => new byte[32];
    }

    private sealed class CapturingIntegrity : ICvkIntegrityCalculator
    {
        public ReadOnlyMemory<byte> Header { get; private set; }
        public ReadOnlyMemory<byte> Body { get; private set; }

        public ReadOnlyMemory<byte> Compute(ReadOnlyMemory<byte> headerJson, ReadOnlyMemory<byte> keyBody)
        {
            Header = headerJson.ToArray();
            Body = keyBody.ToArray();
            return new byte[32];
        }
    }

    [Fact]
    public async Task Writer_RejectsDuplicateRecipientIdsInPlainMode()
    {
        var document = new CrypVol.Lib.Crypto.CvkDocument
        {
            Cek = new byte[32],
            KeyProtection = CvkKeyProtection.Plain,
            KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None
        };
        document.RecipientKeys.Add(new CrypVol.Lib.Crypto.Keys.AsymmetricRecipientKey("duplicate", "RSA", new byte[] { 1 }));
        document.RecipientKeys.Add(new CrypVol.Lib.Crypto.Keys.AsymmetricRecipientKey("duplicate", "RSA", new byte[] { 2 }));
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-duplicate-plain-{Guid.NewGuid():N}.cvk"));
        try
        {
            await Assert.ThrowsAnyAsync<Exception>(() =>
                new CvkWriter(new PlainCvkPayloadProtector()).WriteAsync(document, file));
            Assert.False(file.Exists);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Theory]
    [InlineData(31)]
    [InlineData(33)]
    public async Task Reader_RejectsIntegrityLengthMismatch(int length)
    {
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-integrity-length-{Guid.NewGuid():N}.cvk"));
        try
        {
            var document = new CrypVol.Lib.Crypto.CvkDocument { Cek = new byte[32], KeyProtection = CvkKeyProtection.Plain, KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None };
            await new CvkWriter(new PlainCvkPayloadProtector()).WriteAsync(document, file);
            var calculator = new VariableIntegrityCalculator(length);
            await Assert.ThrowsAsync<CryptographicException>(() => new CvkReader(calculator).ReadAsync(file));
        }
        finally { if (file.Exists) file.Delete(); }
    }

    private sealed class VariableIntegrityCalculator : ICvkIntegrityCalculator
    {
        private readonly int _length;
        public VariableIntegrityCalculator(int length) => _length = length;
        public ReadOnlyMemory<byte> Compute(ReadOnlyMemory<byte> headerJson, ReadOnlyMemory<byte> keyBody) => new byte[_length];
    }

    [Fact]
    public async Task Reader_DoesNotUnprotectBeforeIntegrityVerification()
    {
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-order-{Guid.NewGuid():N}.cvk"));
        try
        {
            var document = new CrypVol.Lib.Crypto.CvkDocument { Cek = new byte[32], KeyProtection = CvkKeyProtection.Plain, KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None };
            await new CvkWriter(new PlainCvkPayloadProtector()).WriteAsync(document, file);
            var bytes = await File.ReadAllBytesAsync(file.FullName);
            bytes[^1] ^= 1;
            await File.WriteAllBytesAsync(file.FullName, bytes);
            var unprotector = new CountingUnprotector();
            await Assert.ThrowsAsync<CryptographicException>(() => new CvkReader(new Sha256IntegrityCalculator(), unprotector).ReadDocumentAsync(file));
            Assert.Equal(0, unprotector.Calls);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task Writer_HonorsCancellationBeforeWriting()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var document = new CrypVol.Lib.Crypto.CvkDocument { Cek = new byte[32], KeyProtection = CvkKeyProtection.Plain, KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None };
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-cancel-{Guid.NewGuid():N}.cvk"));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new CvkWriter(new PlainCvkPayloadProtector()).WriteAsync(document, file, cts.Token));
        Assert.False(file.Exists);
    }

    [Fact]
    public async Task AtomicWrite_CancellationPreservesExistingFile()
    {
        var file = Path.Combine(Path.GetTempPath(), $"cvk-atomic-{Guid.NewGuid():N}.bin");
        try
        {
            await File.WriteAllBytesAsync(file, [1, 2, 3]);
            using var cts = new CancellationTokenSource();
            cts.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => AtomicFile.WriteBytesAsync(file, new byte[] { 9, 9, 9 }, cts.Token));
            Assert.Equal(new byte[] { 1, 2, 3 }, await File.ReadAllBytesAsync(file));
        }
        finally { if (File.Exists(file)) File.Delete(file); }
    }

    [Fact]
    public async Task AtomicWrite_CancellationCleansTemporaryFiles()
    {
        var file = Path.Combine(Path.GetTempPath(), $"cvk-atomic-clean-{Guid.NewGuid():N}.bin");
        var directory = Path.GetDirectoryName(file)!;
        try
        {
            using var cts = new CancellationTokenSource();
            cts.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
                AtomicFile.WriteBytesAsync(file, new byte[] { 1, 2, 3 }, cts.Token));

            Assert.Empty(Directory.EnumerateFiles(directory, $".{Path.GetFileName(file)}.*.tmp"));
        }
        finally { if (File.Exists(file)) File.Delete(file); }
    }

    private static Task Write(CrypVol.Lib.Crypto.CvkDocument document)
    {
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-invalid-{Guid.NewGuid():N}.cvk"));
        return new CvkWriter(new PlainCvkPayloadProtector()).WriteAsync(document, file);
    }

    private static byte[] BuildHeader(string json)
    {
        var header = Encoding.UTF8.GetBytes(json);
        var body = "x"u8.ToArray();
        var integrity = new byte[32];
        var result = new byte[16 + header.Length + body.Length + integrity.Length];
        "CVK1"u8.CopyTo(result);
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(4), (uint)header.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(8), (uint)body.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(12), (uint)integrity.Length);
        header.CopyTo(result, 16); body.CopyTo(result, 16 + header.Length); integrity.CopyTo(result, 16 + header.Length + body.Length);
        return result;
    }

    [Fact]
    public async Task Writer_ProtectorFailureDoesNotCreateTarget()
    {
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-protector-fail-{Guid.NewGuid():N}.cvk"));
        try
        {
            var document = new CrypVol.Lib.Crypto.CvkDocument { Cek = new byte[32], KeyProtection = CvkKeyProtection.Plain, KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None };
            await Assert.ThrowsAsync<InvalidOperationException>(() => new CvkWriter(new ThrowingProtector()).WriteAsync(document, file));
            Assert.False(file.Exists);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task Writer_CreatesMissingParentDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), $"cvk-missing-parent-{Guid.NewGuid():N}", "nested", "file.cvk");
        var document = new CrypVol.Lib.Crypto.CvkDocument { Cek = new byte[32], KeyProtection = CvkKeyProtection.Plain, KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None };
        try
        {
            await new CvkWriter(new PlainCvkPayloadProtector()).WriteAsync(document, new FileInfo(path));
            Assert.True(File.Exists(path));
        }
        finally
        {
            var root = Directory.GetParent(Path.GetDirectoryName(path)!)!.FullName;
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Reader_UnprotectsExactlyOnceAfterIntegrityVerification()
    {
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-order-valid-{Guid.NewGuid():N}.cvk"));
        try
        {
            var source = new CrypVol.Lib.Crypto.CvkDocument
            {
                Cek = new byte[32],
                KeyProtection = CvkKeyProtection.Plain,
                KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None
            };
            await new CvkWriter(new PlainCvkPayloadProtector()).WriteAsync(source, file);
            var unprotector = new RecordingUnprotector();
            var loaded = await new CvkReader(new Sha256IntegrityCalculator(), unprotector).ReadDocumentAsync(file);

            Assert.Equal(1, unprotector.Calls);
            Assert.NotEmpty(unprotector.HeaderJson);
            Assert.NotEmpty(unprotector.KeyBody);
            Assert.Equal(source.Cek, loaded.Cek);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task Writer_PassesExactWrittenSegmentsToIntegrityCalculator()
    {
        var calculator = new CapturingIntegrity();
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-capture-{Guid.NewGuid():N}.cvk"));
        try
        {
            var document = new CrypVol.Lib.Crypto.CvkDocument
            {
                Cek = new byte[32],
                KeyProtection = CvkKeyProtection.Plain,
                KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None
            };
            await new CvkWriter(new PlainCvkPayloadProtector(), calculator).WriteAsync(document, file);
            var parsed = CvkParser.Parse(await File.ReadAllBytesAsync(file.FullName));

            Assert.Equal(parsed.HeaderJson.ToArray(), calculator.Header.ToArray());
            Assert.Equal(parsed.KeyBody.ToArray(), calculator.Body.ToArray());
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task Writer_RejectsBlankRecipientKeyId(string keyId)
    {
        var document = CrypVol.Lib.Crypto.CvkOperations.CreateNew(CvkKeyProtection.PublicKey, CvkKeyWrapAlgorithm.RsaOaepSha256);
        document.RecipientKeys.Add(new CrypVol.Lib.Crypto.Keys.AsymmetricRecipientKey(keyId, "RSA", new byte[] { 1, 2, 3 }));

        await Assert.ThrowsAnyAsync<Exception>(() => Write(document));
    }

    [Fact]
    public async Task Writer_IntegrityFailureDoesNotCreateTarget()
    {
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-integrity-fail-{Guid.NewGuid():N}.cvk"));
        try
        {
            var document = new CrypVol.Lib.Crypto.CvkDocument { Cek = new byte[32], KeyProtection = CvkKeyProtection.Plain, KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None };
            await Assert.ThrowsAsync<InvalidOperationException>(() => new CvkWriter(new PlainCvkPayloadProtector(), new ThrowingIntegrity()).WriteAsync(document, file));
            Assert.False(file.Exists);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task Writer_FailurePreservesExistingTarget()
    {
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-preserve-{Guid.NewGuid():N}.cvk"));
        var original = new byte[] { 4, 5, 6, 7 };
        try
        {
            await File.WriteAllBytesAsync(file.FullName, original);
            var document = new CrypVol.Lib.Crypto.CvkDocument { Cek = new byte[32], KeyProtection = CvkKeyProtection.Plain, KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None };
            await Assert.ThrowsAsync<InvalidOperationException>(() => new CvkWriter(new PlainCvkPayloadProtector(), new ThrowingIntegrity()).WriteAsync(document, file));
            Assert.Equal(original, await File.ReadAllBytesAsync(file.FullName));
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task Writer_SuccessfullyReplacesExistingTarget()
    {
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-replace-{Guid.NewGuid():N}.cvk"));
        try
        {
            var first = new CrypVol.Lib.Crypto.CvkDocument
            {
                Cek = Enumerable.Repeat((byte)1, 32).ToArray(),
                KeyProtection = CvkKeyProtection.Plain,
                KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None,
                Label = "first"
            };
            var second = new CrypVol.Lib.Crypto.CvkDocument
            {
                Cek = Enumerable.Repeat((byte)2, 32).ToArray(),
                KeyProtection = CvkKeyProtection.Plain,
                KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None,
                Label = "second"
            };
            var writer = new CvkWriter(new PlainCvkPayloadProtector());
            await writer.WriteAsync(first, file);
            await writer.WriteAsync(second, file);

            var loaded = await new CvkReader(new Sha256IntegrityCalculator(), new PlainCvkPayloadUnprotector()).ReadDocumentAsync(file);
            Assert.Equal(second.Cek, loaded.Cek);
            Assert.Equal("second", loaded.Label);
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task Writer_RejectsIntegritySegmentExceedingParserLimit()
    {
        var document = new CrypVol.Lib.Crypto.CvkDocument { Cek = new byte[32], KeyProtection = CvkKeyProtection.Plain, KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None };
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-large-integrity-{Guid.NewGuid():N}.cvk"));
        try
        {
            await Assert.ThrowsAsync<InvalidDataException>(() => new CvkWriter(new PlainCvkPayloadProtector(), new LargeIntegrity()).WriteAsync(document, file));
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task Writer_RejectsEmptyIntegritySegment()
    {
        var document = new CrypVol.Lib.Crypto.CvkDocument { Cek = new byte[32], KeyProtection = CvkKeyProtection.Plain, KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None };
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-empty-integrity-{Guid.NewGuid():N}.cvk"));
        try
        {
            await Assert.ThrowsAsync<InvalidDataException>(() => new CvkWriter(new PlainCvkPayloadProtector(), new EmptyIntegrity()).WriteAsync(document, file));
        }
        finally { if (file.Exists) file.Delete(); }
    }

    private sealed class ThrowingProtector : ICvkPayloadProtector
    {
        public ValueTask<ReadOnlyMemory<byte>> ProtectAsync(CvkHeader header, CvkPayload payload, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("protector failure");
    }

    private sealed class EmptyProtector : ICvkPayloadProtector
    {
        public ValueTask<ReadOnlyMemory<byte>> ProtectAsync(CvkHeader header, CvkPayload payload,
            CancellationToken cancellationToken = default) => ValueTask.FromResult(ReadOnlyMemory<byte>.Empty);
    }

    private sealed class SnapshotProtector(IList<AsymmetricRecipientKey> source) : ICvkPayloadProtector
    {
        public IReadOnlyList<AsymmetricRecipientKey> ObservedRecipients { get; private set; } = [];

        public ValueTask<ReadOnlyMemory<byte>> ProtectAsync(CvkHeader header, CvkPayload payload,
            CancellationToken cancellationToken = default)
        {
            ObservedRecipients = payload.RecipientKeys.ToArray();
            source.Clear();
            return new PlainCvkPayloadProtector().ProtectAsync(header, payload, cancellationToken);
        }
    }

    private sealed class ThrowingIntegrity : ICvkIntegrityCalculator
    {
        public ReadOnlyMemory<byte> Compute(ReadOnlyMemory<byte> headerJson, ReadOnlyMemory<byte> keyBody)
            => throw new InvalidOperationException("integrity failure");
    }

    private sealed class CountingUnprotector : ICvkPayloadUnprotector
    {
        public int Calls { get; private set; }
        public ValueTask<CvkPayload> UnprotectAsync(CvkHeader header, ReadOnlyMemory<byte> keyBody, CancellationToken cancellationToken = default)
        {
            Calls++;
            throw new InvalidOperationException("must not be called");
        }
    }

    [Fact]
    public async Task Reader_IntegrityBindsSegmentBoundaries()
    {
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-boundary-integrity-{Guid.NewGuid():N}.cvk"));
        try
        {
            var header = CvkPayloadCodec.EncodeHeader(new CvkHeader(1, CvkKeyProtection.Plain,
                CvkKeyWrapAlgorithm.None, null, null, null, null, null));
            byte[] headerWithTrailingSpace = [.. header, (byte)' '];
            var body = CvkPayloadCodec.Encode(new CvkPayload(new byte[32], []));
            var integrity = new Sha256IntegrityCalculator().Compute(headerWithTrailingSpace, body).ToArray();
            var bytes = new byte[16 + headerWithTrailingSpace.Length + body.Length + integrity.Length];
            "CVK1"u8.CopyTo(bytes);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(4), (uint)headerWithTrailingSpace.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(8), (uint)body.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(12), (uint)integrity.Length);
            headerWithTrailingSpace.CopyTo(bytes, 16);
            body.CopyTo(bytes, 16 + headerWithTrailingSpace.Length);
            integrity.CopyTo(bytes, 16 + headerWithTrailingSpace.Length + body.Length);
            await File.WriteAllBytesAsync(file.FullName, bytes);

            var mutated = bytes.ToArray();
            BinaryPrimitives.WriteUInt32LittleEndian(mutated.AsSpan(4), (uint)(headerWithTrailingSpace.Length - 1));
            BinaryPrimitives.WriteUInt32LittleEndian(mutated.AsSpan(8), (uint)(body.Length + 1));
            await File.WriteAllBytesAsync(file.FullName, mutated);

            await Assert.ThrowsAsync<CryptographicException>(() => CrypVol.Lib.Crypto.CvkOperations.LoadAsync(file));
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task Reader_RejectsMalformedPayloadReturnedByUnprotector(int malformedKind)
    {
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-reader-malformed-{Guid.NewGuid():N}.cvk"));
        try
        {
            var source = new CrypVol.Lib.Crypto.CvkDocument
            {
                Cek = new byte[32],
                KeyProtection = CvkKeyProtection.Plain,
                KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None
            };
            await new CvkWriter(new PlainCvkPayloadProtector()).WriteAsync(source, file);
            var malformed = malformedKind switch
            {
                0 => new CvkPayload(null!, []),
                1 => new CvkPayload(new byte[32], [null!]),
                2 => new CvkPayload(new byte[31], []),
                _ => new CvkPayload(new byte[32], null!)
            };

            await Assert.ThrowsAnyAsync<Exception>(() =>
                new CvkReader(new Sha256IntegrityCalculator(), new ReturningUnprotector(malformed)).ReadDocumentAsync(file));
        }
        finally { if (file.Exists) file.Delete(); }
    }

    private sealed class RecordingUnprotector : ICvkPayloadUnprotector
    {
        public int Calls { get; private set; }
        public byte[] HeaderJson { get; private set; } = [];
        public byte[] KeyBody { get; private set; } = [];

        public ValueTask<CvkPayload> UnprotectAsync(CvkHeader header, ReadOnlyMemory<byte> keyBody, CancellationToken cancellationToken = default)
        {
            Calls++;
            HeaderJson = CvkPayloadCodec.EncodeHeader(header);
            KeyBody = keyBody.ToArray();
            return ValueTask.FromResult(new CvkPayload(new byte[32], []));
        }
    }

    private sealed class ReturningUnprotector(CvkPayload payload) : ICvkPayloadUnprotector
    {
        public ValueTask<CvkPayload> UnprotectAsync(CvkHeader header, ReadOnlyMemory<byte> keyBody, CancellationToken cancellationToken = default)
            => ValueTask.FromResult(payload);
    }

    [Fact]
    public async Task Writer_EncodesExactSegmentLengthsInPrefix()
    {
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-prefix-lengths-{Guid.NewGuid():N}.cvk"));
        try
        {
            var document = new CrypVol.Lib.Crypto.CvkDocument
            {
                Cek = new byte[32],
                KeyProtection = CvkKeyProtection.Plain,
                KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None
            };
            await new CvkWriter(new PlainCvkPayloadProtector()).WriteAsync(document, file);
            var bytes = await File.ReadAllBytesAsync(file.FullName);
            var parsed = CvkParser.Parse(bytes);

            Assert.Equal((uint)parsed.HeaderJson.Length, BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(4)));
            Assert.Equal((uint)parsed.KeyBody.Length, BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(8)));
            Assert.Equal((uint)parsed.Integrity.Length, BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(12)));
        }
        finally { if (file.Exists) file.Delete(); }
    }

    [Fact]
    public async Task Writer_RejectsPublicKeyDocumentWithoutEcdhRecipients()
    {
        var document = new CrypVol.Lib.Crypto.CvkDocument
        {
            Cek = new byte[32],
            KeyProtection = CvkKeyProtection.PublicKey,
            KeyWrapAlgorithm = CvkKeyWrapAlgorithm.EcdhP256
        };
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-empty-ecdh-{Guid.NewGuid():N}.cvk"));
        try
        {
            await Assert.ThrowsAsync<InvalidDataException>(() =>
                new CvkWriter(new CvkPayloadProtectorAdapter(new EcdhP256Cryptor())).WriteAsync(document, file));
        }
        finally { if (file.Exists) file.Delete(); }
    }

    private sealed class LargeIntegrity : ICvkIntegrityCalculator
    {
        public ReadOnlyMemory<byte> Compute(ReadOnlyMemory<byte> headerJson, ReadOnlyMemory<byte> keyBody) => new byte[4097];
    }

    private sealed class EmptyIntegrity : ICvkIntegrityCalculator
    {
        public ReadOnlyMemory<byte> Compute(ReadOnlyMemory<byte> headerJson, ReadOnlyMemory<byte> keyBody) => ReadOnlyMemory<byte>.Empty;
    }

    [Fact]
    public async Task Writer_RejectsParentPathThatIsAFile()
    {
        var parent = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-parent-file-{Guid.NewGuid():N}"));
        await File.WriteAllBytesAsync(parent.FullName, [1]);
        var target = new FileInfo(Path.Combine(parent.FullName, "child.cvk"));
        try
        {
            var document = new CrypVol.Lib.Crypto.CvkDocument
            {
                Cek = new byte[32],
                KeyProtection = CvkKeyProtection.Plain,
                KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None
            };
            await Assert.ThrowsAnyAsync<Exception>(() =>
                new CvkWriter(new PlainCvkPayloadProtector()).WriteAsync(document, target));
            Assert.False(target.Exists);
        }
        finally { if (parent.Exists) parent.Delete(); }
    }

    [Fact]
    public async Task Writer_RejectsDirectoryAsTarget()
    {
        var directory = new DirectoryInfo(Path.Combine(Path.GetTempPath(), $"cvk-target-directory-{Guid.NewGuid():N}"));
        directory.Create();
        try
        {
            var document = new CrypVol.Lib.Crypto.CvkDocument
            {
                Cek = new byte[32],
                KeyProtection = CvkKeyProtection.Plain,
                KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None
            };
            await Assert.ThrowsAnyAsync<Exception>(() =>
                new CvkWriter(new PlainCvkPayloadProtector()).WriteAsync(document, new FileInfo(directory.FullName)));
            Assert.True(directory.Exists);
            Assert.Empty(directory.EnumerateFileSystemInfos());
        }
        finally { if (directory.Exists) directory.Delete(true); }
    }
}

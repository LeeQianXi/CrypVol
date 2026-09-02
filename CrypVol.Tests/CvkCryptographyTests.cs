using System.Security.Cryptography;
using System.Text.Json.Nodes;
using CrypVol.Lib.Crypto.Cryptography;
using CrypVol.Lib.Crypto.Keys;
using CrypVol.Lib.Crypto.Models;
using Xunit;

namespace CrypVol.Tests;

/// <summary>覆盖新 CVK 各密钥封装处理器的往返和失败路径。</summary>
public sealed class CvkCryptographyTests
{
    private static CvkHeader Header(CvkKeyWrapAlgorithm algorithm) =>
        new(1, algorithm is CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256 or CvkKeyWrapAlgorithm.PasswordArgon2Id
            ? CvkKeyProtection.Password : algorithm == CvkKeyWrapAlgorithm.None ? CvkKeyProtection.Plain : CvkKeyProtection.PublicKey,
            algorithm, "test", null, null, null, "tests");

    private static CvkPayload Payload(AsymmetricRecipientKey[]? recipients = null) =>
        new(RandomNumberGenerator.GetBytes(32), recipients ?? []);

    [Fact]
    public void PasswordCryptors_RejectEmptyPassword()
    {
        Assert.Throws<ArgumentException>(() => new PasswordPbkdf2Sha256Cryptor(string.Empty));
        Assert.Throws<ArgumentException>(() => new PasswordArgon2IdCryptor(string.Empty));
        Assert.Throws<ArgumentException>(() => new PasswordPbkdf2Sha256Cryptor(null!));
        Assert.Throws<ArgumentException>(() => new PasswordArgon2IdCryptor(null!));
    }

    [Fact]
    public async Task PasswordCryptors_AcceptWhitespacePassword()
    {
        var cryptor = new PasswordPbkdf2Sha256Cryptor(" ");
        var header = Header(CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256);
        var payload = Payload();
        var body = await cryptor.ProtectAsync(header, payload);

        var restored = await new PasswordPbkdf2Sha256Cryptor(" ").UnprotectAsync(header, body);

        Assert.Equal(payload.Cek.ToArray(), restored.Cek.ToArray());
    }

    [Fact]
    public async Task Cryptors_RejectNullArguments()
    {
        var cryptor = new PlainCvkPayloadCryptor();
        await Assert.ThrowsAsync<ArgumentNullException>(() => cryptor.ProtectAsync(null!, Payload()).AsTask());
        await Assert.ThrowsAsync<ArgumentNullException>(() => cryptor.ProtectAsync(Header(CvkKeyWrapAlgorithm.None), null!).AsTask());
        await Assert.ThrowsAsync<ArgumentNullException>(() => cryptor.UnprotectAsync(null!, "{}"u8.ToArray()).AsTask());
    }

    [Fact]
    public async Task PayloadAdapters_ForwardArgumentsAndResultsWithoutMutation()
    {
        var inner = new RecordingCryptor();
        var protector = new CvkPayloadProtectorAdapter(inner);
        var unprotector = new CvkPayloadUnprotectorAdapter(inner);
        var header = Header(CvkKeyWrapAlgorithm.None);
        var payload = Payload();
        var token = new CancellationTokenSource().Token;

        var body = await protector.ProtectAsync(header, payload, token);
        var restored = await unprotector.UnprotectAsync(header, body, token);

        Assert.Same(header, inner.ProtectHeader);
        Assert.Same(payload, inner.ProtectPayload);
        Assert.Equal(token, inner.ProtectToken);
        Assert.Same(header, inner.UnprotectHeader);
        Assert.Equal(body.ToArray(), inner.UnprotectBody);
        Assert.Equal(token, inner.UnprotectToken);
        Assert.Equal(payload.Cek.ToArray(), restored.Cek.ToArray());
    }

    [Fact]
    public void PayloadAdapters_RejectNullInnerCryptor()
    {
        Assert.Throws<ArgumentNullException>(() => new CvkPayloadProtectorAdapter(null!));
        Assert.Throws<ArgumentNullException>(() => new CvkPayloadUnprotectorAdapter(null!));
    }

    [Fact]
    public async Task PasswordPbkdf2_RoundTrips()
    {
        var cryptor = new PasswordPbkdf2Sha256Cryptor("correct horse battery staple");
        var header = Header(CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256);
        var payload = Payload();
        var body = await cryptor.ProtectAsync(header, payload);
        var restored = await cryptor.UnprotectAsync(header, body);
        Assert.Equal(payload.Cek.ToArray(), restored.Cek.ToArray());
    }

    [Fact]
    public async Task PasswordCryptors_RejectEachOthersKeyBodies()
    {
        var payload = Payload();
        var pbkdf2 = new PasswordPbkdf2Sha256Cryptor("secret");
        var argon2 = new PasswordArgon2IdCryptor("secret");
        var pbkdf2Body = await pbkdf2.ProtectAsync(Header(CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256), payload);
        var argon2Body = await argon2.ProtectAsync(Header(CvkKeyWrapAlgorithm.PasswordArgon2Id), payload);

        await Assert.ThrowsAnyAsync<Exception>(() =>
            argon2.UnprotectAsync(Header(CvkKeyWrapAlgorithm.PasswordArgon2Id), pbkdf2Body).AsTask());
        await Assert.ThrowsAnyAsync<Exception>(() =>
            pbkdf2.UnprotectAsync(Header(CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256), argon2Body).AsTask());
    }

    [Theory]
    [InlineData("rsa")]
    [InlineData("ecdh")]
    public async Task PublicKeyCryptors_RejectWhitespaceOnlyKeyBody(string algorithm)
    {
        var (cryptor, header) = algorithm == "rsa"
            ? (new RsaOaepSha256Cryptor() as ICvkPayloadCryptor, Header(CvkKeyWrapAlgorithm.RsaOaepSha256))
            : (new EcdhP256Cryptor() as ICvkPayloadCryptor, Header(CvkKeyWrapAlgorithm.EcdhP256));

        await Assert.ThrowsAnyAsync<Exception>(() => cryptor.UnprotectAsync(header, " \t\r\n"u8.ToArray()).AsTask());
    }

    [Fact]
    public async Task PasswordCryptor_UsesFreshRandomParametersPerProtection()
    {
        var cryptor = new PasswordPbkdf2Sha256Cryptor("secret");
        var header = Header(CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256);
        var payload = Payload();

        var first = await cryptor.ProtectAsync(header, payload);
        var second = await cryptor.ProtectAsync(header, payload);

        Assert.NotEqual(first.ToArray(), second.ToArray());
    }

    [Theory]
    [InlineData(CvkKeyWrapAlgorithm.RsaOaepSha256)]
    [InlineData(CvkKeyWrapAlgorithm.RsaOaepSha384)]
    [InlineData(CvkKeyWrapAlgorithm.RsaOaepSha512)]
    public async Task AllRsaOaepVariants_RoundTrip(CvkKeyWrapAlgorithm algorithm)
    {
        using var rsa = RSA.Create(2048);
        var recipient = new AsymmetricRecipientKey("rsa", "RSA", rsa.ExportSubjectPublicKeyInfo());
        using var privateMaterial = new AsymmetricPrivateKeyMaterial("rsa", "RSA", rsa);
        ICvkPayloadCryptor cryptor = algorithm switch
        {
            CvkKeyWrapAlgorithm.RsaOaepSha384 => new RsaOaepSha384Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["rsa"] = privateMaterial }),
            CvkKeyWrapAlgorithm.RsaOaepSha512 => new RsaOaepSha512Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["rsa"] = privateMaterial }),
            _ => new RsaOaepSha256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["rsa"] = privateMaterial })
        };
        var header = Header(algorithm); var payload = Payload([recipient]);
        var restored = await cryptor.UnprotectAsync(header, await cryptor.ProtectAsync(header, payload));
        Assert.Equal(payload.Cek.ToArray(), restored.Cek.ToArray());
    }

    [Fact]
    public async Task RsaCryptor_UsesFreshRandomParametersPerProtection()
    {
        using var rsa = RSA.Create(2048);
        var recipient = new AsymmetricRecipientKey("rsa", "RSA", rsa.ExportSubjectPublicKeyInfo());
        var cryptor = new RsaOaepSha256Cryptor();
        var header = Header(CvkKeyWrapAlgorithm.RsaOaepSha256);
        var payload = Payload([recipient]);

        var first = await cryptor.ProtectAsync(header, payload);
        var second = await cryptor.ProtectAsync(header, payload);

        Assert.NotEqual(first.ToArray(), second.ToArray());
    }

    [Theory]
    [InlineData(CvkKeyWrapAlgorithm.EcdhP256)]
    [InlineData(CvkKeyWrapAlgorithm.EcdhP384)]
    [InlineData(CvkKeyWrapAlgorithm.EcdhP521)]
    public async Task AllEcdhVariants_RoundTrip(CvkKeyWrapAlgorithm algorithm)
    {
        var curve = algorithm switch
        {
            CvkKeyWrapAlgorithm.EcdhP384 => ECCurve.NamedCurves.nistP384,
            CvkKeyWrapAlgorithm.EcdhP521 => ECCurve.NamedCurves.nistP521,
            _ => ECCurve.NamedCurves.nistP256
        };
        using var ecdh = ECDiffieHellman.Create(curve);
        var recipient = new AsymmetricRecipientKey("ec", "ECDH", ecdh.ExportSubjectPublicKeyInfo());
        using var privateMaterial = new AsymmetricPrivateKeyMaterial("ec", "ECDH", ecdh);
        ICvkPayloadCryptor cryptor = algorithm switch
        {
            CvkKeyWrapAlgorithm.EcdhP384 => new EcdhP384Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["ec"] = privateMaterial }),
            CvkKeyWrapAlgorithm.EcdhP521 => new EcdhP521Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["ec"] = privateMaterial }),
            _ => new EcdhP256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["ec"] = privateMaterial })
        };
        var header = Header(algorithm); var payload = Payload([recipient]);
        var restored = await cryptor.UnprotectAsync(header, await cryptor.ProtectAsync(header, payload));
        Assert.Equal(payload.Cek.ToArray(), restored.Cek.ToArray());
    }

    [Fact]
    public async Task EcdhCryptor_UsesFreshEphemeralKeyPerProtection()
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var recipient = new AsymmetricRecipientKey("ec", "ECDH", ecdh.ExportSubjectPublicKeyInfo());
        var cryptor = new EcdhP256Cryptor();
        var header = Header(CvkKeyWrapAlgorithm.EcdhP256);
        var payload = Payload([recipient]);

        var first = await cryptor.ProtectAsync(header, payload);
        var second = await cryptor.ProtectAsync(header, payload);

        Assert.NotEqual(first.ToArray(), second.ToArray());
    }

    [Fact]
    public async Task Argon2_RoundTrips()
    {
        var cryptor = new PasswordArgon2IdCryptor("secret");
        var header = Header(CvkKeyWrapAlgorithm.PasswordArgon2Id);
        var payload = Payload();
        var body = await cryptor.ProtectAsync(header, payload);
        var restored = await cryptor.UnprotectAsync(header, body);
        Assert.Equal(payload.Cek.ToArray(), restored.Cek.ToArray());
    }

    [Fact]
    public async Task Argon2_UsesFreshRandomParametersPerProtection()
    {
        var cryptor = new PasswordArgon2IdCryptor("secret");
        var header = Header(CvkKeyWrapAlgorithm.PasswordArgon2Id);
        var payload = Payload();

        var first = await cryptor.ProtectAsync(header, payload);
        var second = await cryptor.ProtectAsync(header, payload);

        Assert.NotEqual(first.ToArray(), second.ToArray());
    }

    [Fact]
    public async Task Argon2CiphertextTampering_IsRejected()
    {
        var header = Header(CvkKeyWrapAlgorithm.PasswordArgon2Id);
        var cryptor = new PasswordArgon2IdCryptor("secret");
        var body = (await cryptor.ProtectAsync(header, Payload())).ToArray();
        body[^1] ^= 1;

        await Assert.ThrowsAsync<CryptographicException>(() => cryptor.UnprotectAsync(header, body).AsTask());
    }

    [Theory]
    [InlineData(CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256)]
    [InlineData(CvkKeyWrapAlgorithm.PasswordArgon2Id)]
    public async Task ProtectedKeyBodies_DoNotExposeRawCek(CvkKeyWrapAlgorithm algorithm)
    {
        var cek = Enumerable.Repeat((byte)0xA5, 32).ToArray();
        var payload = new CvkPayload(cek, []);
        var cryptor = algorithm == CvkKeyWrapAlgorithm.PasswordArgon2Id
            ? (ICvkPayloadCryptor)new PasswordArgon2IdCryptor("secret")
            : new PasswordPbkdf2Sha256Cryptor("secret");

        var body = (await cryptor.ProtectAsync(Header(algorithm), payload)).ToArray();

        Assert.Equal(-1, body.AsSpan().IndexOf(cek));
    }

    [Fact]
    public async Task RsaOaep_RoundTrips()
    {
        using var rsa = RSA.Create(2048);
        var recipient = new AsymmetricRecipientKey("rsa", "RSA", rsa.ExportSubjectPublicKeyInfo());
        var file = new FileInfo(Path.Combine(Path.GetTempPath(), $"cvk-{Guid.NewGuid():N}.pem"));
        await File.WriteAllTextAsync(file.FullName, rsa.ExportPkcs8PrivateKeyPem());
        using var privateMaterial = AsymmetricKeyFileLoader.LoadPrivateKey(file, keyId: "rsa");
        try
        {
            var cryptor = new RsaOaepSha256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["rsa"] = privateMaterial });
            var header = Header(CvkKeyWrapAlgorithm.RsaOaepSha256); var payload = Payload([recipient]);
            var restored = await cryptor.UnprotectAsync(header, await cryptor.ProtectAsync(header, payload));
            Assert.Equal(payload.Cek.ToArray(), restored.Cek.ToArray());
        }
        finally { file.Delete(); }
    }

    [Fact]
    public async Task EcdhP256_RoundTrips()
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var recipient = new AsymmetricRecipientKey("ec", "ECDH", ecdh.ExportSubjectPublicKeyInfo());
        using var privateMaterial = new AsymmetricPrivateKeyMaterial("ec", "ECDH", ecdh);
        try
        {
            var cryptor = new EcdhP256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["ec"] = privateMaterial });
            var header = Header(CvkKeyWrapAlgorithm.EcdhP256); var payload = Payload([recipient]);
            var restored = await cryptor.UnprotectAsync(header, await cryptor.ProtectAsync(header, payload));
            Assert.Equal(payload.Cek.ToArray(), restored.Cek.ToArray());
        }
        finally { }
    }

    [Fact]
    public async Task WrongPassword_IsRejected()
    {
        var header = Header(CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256);
        var body = await new PasswordPbkdf2Sha256Cryptor("right").ProtectAsync(header, Payload());
        await Assert.ThrowsAsync<CryptographicException>(() =>
            new PasswordPbkdf2Sha256Cryptor("wrong").UnprotectAsync(header, body).AsTask());
    }

    [Fact]
    public async Task PublicKeyCryptor_RejectsUnknownPrivateKeyId()
    {
        using var rsa = RSA.Create(2048);
        var recipient = new AsymmetricRecipientKey("known", "RSA", rsa.ExportSubjectPublicKeyInfo());
        var cryptor = new RsaOaepSha256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial>());
        var body = await cryptor.ProtectAsync(Header(CvkKeyWrapAlgorithm.RsaOaepSha256), Payload([recipient]));
        await Assert.ThrowsAsync<CryptographicException>(() => cryptor.UnprotectAsync(Header(CvkKeyWrapAlgorithm.RsaOaepSha256), body).AsTask());
    }

    [Fact]
    public async Task RsaCryptor_FallsBackAfterFirstPrivateKeyFails()
    {
        using var first = RSA.Create(2048);
        using var second = RSA.Create(2048);
        using var wrong = RSA.Create(2048);
        var recipients = new[]
        {
            new AsymmetricRecipientKey("first", "RSA", first.ExportSubjectPublicKeyInfo()),
            new AsymmetricRecipientKey("second", "RSA", second.ExportSubjectPublicKeyInfo())
        };
        using var wrongMaterial = new AsymmetricPrivateKeyMaterial("first", "RSA", wrong);
        using var secondMaterial = new AsymmetricPrivateKeyMaterial("second", "RSA", second);
        var keys = new Dictionary<string, AsymmetricPrivateKeyMaterial>
        {
            ["first"] = wrongMaterial,
            ["second"] = secondMaterial
        };
        var header = Header(CvkKeyWrapAlgorithm.RsaOaepSha256);
        var body = await new RsaOaepSha256Cryptor().ProtectAsync(header, Payload(recipients));

        var restored = await new RsaOaepSha256Cryptor(keys).UnprotectAsync(header, body);

        Assert.Equal(32, restored.Cek.Length);
    }

    [Fact]
    public async Task EcdhCryptor_FallsBackAfterFirstPrivateKeyFails()
    {
        using var first = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var second = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var wrong = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var recipients = new[]
        {
            new AsymmetricRecipientKey("first", "ECDH", first.ExportSubjectPublicKeyInfo()),
            new AsymmetricRecipientKey("second", "ECDH", second.ExportSubjectPublicKeyInfo())
        };
        using var wrongMaterial = new AsymmetricPrivateKeyMaterial("first", "ECDH", wrong);
        using var secondMaterial = new AsymmetricPrivateKeyMaterial("second", "ECDH", second);
        var keys = new Dictionary<string, AsymmetricPrivateKeyMaterial>
        {
            ["first"] = wrongMaterial,
            ["second"] = secondMaterial
        };
        var header = Header(CvkKeyWrapAlgorithm.EcdhP256);
        var body = await new EcdhP256Cryptor().ProtectAsync(header, Payload(recipients));

        var restored = await new EcdhP256Cryptor(keys).UnprotectAsync(header, body);

        Assert.Equal(32, restored.Cek.Length);
    }

    [Fact]
    public async Task EcdhCryptor_SkipsRecipientWithoutPrivateKey()
    {
        using var first = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var second = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var recipients = new[]
        {
            new AsymmetricRecipientKey("first", "ECDH", first.ExportSubjectPublicKeyInfo()),
            new AsymmetricRecipientKey("second", "ECDH", second.ExportSubjectPublicKeyInfo())
        };
        using var secondMaterial = new AsymmetricPrivateKeyMaterial("second", "ECDH", second);
        var header = Header(CvkKeyWrapAlgorithm.EcdhP256);
        var body = await new EcdhP256Cryptor().ProtectAsync(header, Payload(recipients));

        var restored = await new EcdhP256Cryptor(
            new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["second"] = secondMaterial })
            .UnprotectAsync(header, body);

        Assert.Equal(32, restored.Cek.Length);
    }

    [Fact]
    public async Task Cryptors_HonorCancellation()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var header = Header(CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new PasswordPbkdf2Sha256Cryptor("secret").ProtectAsync(header, Payload(), cts.Token).AsTask());
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new PlainCvkPayloadCryptor().ProtectAsync(Header(CvkKeyWrapAlgorithm.None), Payload(), cts.Token).AsTask());
    }

    [Fact]
    public async Task PublicKeyCryptors_RejectMissingRecipientsAndCorruptBody()
    {
        var header = Header(CvkKeyWrapAlgorithm.RsaOaepSha256);
        var cryptor = new RsaOaepSha256Cryptor();
        await Assert.ThrowsAsync<InvalidDataException>(() => cryptor.ProtectAsync(header, Payload()).AsTask());
        await Assert.ThrowsAsync<InvalidDataException>(() => cryptor.UnprotectAsync(header, "broken"u8.ToArray()).AsTask());
    }

    [Fact]
    public async Task EcdhCryptor_RejectsMissingRecipientsAndCorruptBody()
    {
        var header = Header(CvkKeyWrapAlgorithm.EcdhP256);
        var cryptor = new EcdhP256Cryptor();
        await Assert.ThrowsAsync<InvalidDataException>(() => cryptor.ProtectAsync(header, Payload()).AsTask());
        await Assert.ThrowsAsync<InvalidDataException>(() => cryptor.UnprotectAsync(header, "broken"u8.ToArray()).AsTask());
    }

    [Fact]
    public async Task Cryptor_RejectsRouteMismatch()
    {
        var cryptor = new RsaOaepSha256Cryptor();
        var wrongHeader = Header(CvkKeyWrapAlgorithm.RsaOaepSha384);
        await Assert.ThrowsAsync<InvalidOperationException>(() => cryptor.ProtectAsync(wrongHeader, Payload()).AsTask());
    }

    [Theory]
    [InlineData(CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256, CvkKeyWrapAlgorithm.PasswordArgon2Id)]
    [InlineData(CvkKeyWrapAlgorithm.RsaOaepSha256, CvkKeyWrapAlgorithm.RsaOaepSha384)]
    [InlineData(CvkKeyWrapAlgorithm.EcdhP256, CvkKeyWrapAlgorithm.EcdhP384)]
    public async Task Cryptors_RejectRouteMismatchOnUnprotect(CvkKeyWrapAlgorithm expected, CvkKeyWrapAlgorithm actual)
    {
        ICvkPayloadCryptor cryptor = expected switch
        {
            CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256 => new PasswordPbkdf2Sha256Cryptor("secret"),
            CvkKeyWrapAlgorithm.RsaOaepSha256 => new RsaOaepSha256Cryptor(),
            _ => new EcdhP256Cryptor()
        };

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            cryptor.UnprotectAsync(Header(actual), ReadOnlyMemory<byte>.Empty).AsTask());
    }

    [Fact]
    public async Task RsaCryptor_RejectsMalformedRecipientPublicKey()
    {
        var header = Header(CvkKeyWrapAlgorithm.RsaOaepSha256);
        var payload = Payload([new AsymmetricRecipientKey("bad", "RSA", new byte[] { 1, 2, 3 })]);
        await Assert.ThrowsAnyAsync<Exception>(() => new RsaOaepSha256Cryptor().ProtectAsync(header, payload).AsTask());
    }

    [Fact]
    public async Task RsaCryptor_RejectsNonRsaRecipientAlgorithm()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var recipient = new AsymmetricRecipientKey("ec", "ECDSA", ecdsa.ExportSubjectPublicKeyInfo());
        await Assert.ThrowsAnyAsync<Exception>(() => new RsaOaepSha256Cryptor().ProtectAsync(Header(CvkKeyWrapAlgorithm.RsaOaepSha256), Payload([recipient])).AsTask());
    }

    [Fact]
    public async Task RsaCryptor_RejectsAlgorithmClaimWithNonRsaKeyBytes()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var recipient = new AsymmetricRecipientKey("fake-rsa", "RSA", ecdsa.ExportSubjectPublicKeyInfo());
        await Assert.ThrowsAnyAsync<Exception>(() =>
            new RsaOaepSha256Cryptor().ProtectAsync(Header(CvkKeyWrapAlgorithm.RsaOaepSha256), Payload([recipient])).AsTask());
    }

    [Fact]
    public async Task RsaOaepSha512_RejectsInsufficientRsaKeySize()
    {
        using var rsa = RSA.Create(1024);
        var recipient = new AsymmetricRecipientKey("rsa", "RSA", rsa.ExportSubjectPublicKeyInfo());

        await Assert.ThrowsAnyAsync<CryptographicException>(() =>
            new RsaOaepSha512Cryptor().ProtectAsync(Header(CvkKeyWrapAlgorithm.RsaOaepSha512), Payload([recipient])).AsTask());
    }

    [Fact]
    public async Task RsaOaepSha256_Handles1024BitRsaKey()
    {
        using var rsa = RSA.Create(1024);
        var recipient = new AsymmetricRecipientKey("rsa", "RSA", rsa.ExportSubjectPublicKeyInfo());
        using var privateMaterial = new AsymmetricPrivateKeyMaterial("rsa", "RSA", rsa);
        var keys = new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["rsa"] = privateMaterial };
        var cryptor = new RsaOaepSha256Cryptor(keys);
        var header = Header(CvkKeyWrapAlgorithm.RsaOaepSha256);

        var body = await new RsaOaepSha256Cryptor().ProtectAsync(header, Payload([recipient]));
        var restored = await cryptor.UnprotectAsync(header, body);

        Assert.Equal(32, restored.Cek.Length);
    }

    [Fact]
    public async Task EcdhCryptor_RejectsNonEcdhRecipientAlgorithm()
    {
        using var rsa = RSA.Create(2048);
        var recipient = new AsymmetricRecipientKey("rsa", "RSA", rsa.ExportSubjectPublicKeyInfo());
        await Assert.ThrowsAnyAsync<Exception>(() => new EcdhP256Cryptor().ProtectAsync(Header(CvkKeyWrapAlgorithm.EcdhP256), Payload([recipient])).AsTask());
    }

    [Fact]
    public async Task EcdhCryptor_AcceptsStructurallyCompatibleEcPublicKeyBytes()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var recipient = new AsymmetricRecipientKey("fake-ecdh", "ECDH", ecdsa.ExportSubjectPublicKeyInfo());
        var body = await new EcdhP256Cryptor()
            .ProtectAsync(Header(CvkKeyWrapAlgorithm.EcdhP256), Payload([recipient]));
        Assert.NotEmpty(body.ToArray());
    }

    [Fact]
    public async Task EcdhP256Cryptor_RejectsP384RecipientKey()
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384);
        var recipient = new AsymmetricRecipientKey("ec", "ECDH", ecdh.ExportSubjectPublicKeyInfo());

        await Assert.ThrowsAnyAsync<Exception>(() =>
            new EcdhP256Cryptor().ProtectAsync(Header(CvkKeyWrapAlgorithm.EcdhP256), Payload([recipient])).AsTask());
    }

    [Theory]
    [InlineData("", "RSA")]
    [InlineData("id", "")]
    [InlineData(" ", "RSA")]
    public async Task PublicKeyCryptors_RejectInvalidRecipientIdentity(string keyId, string algorithm)
    {
        var recipient = new AsymmetricRecipientKey(keyId, algorithm, ReadOnlyMemory<byte>.Empty);
        await Assert.ThrowsAnyAsync<Exception>(() => new RsaOaepSha256Cryptor().ProtectAsync(Header(CvkKeyWrapAlgorithm.RsaOaepSha256), Payload([recipient])).AsTask());
    }

    [Fact]
    public async Task RsaCryptor_RejectsAlgorithmCaseVariant()
    {
        using var rsa = RSA.Create(2048);
        var recipient = new AsymmetricRecipientKey("id", "rsa", rsa.ExportSubjectPublicKeyInfo());
        await Assert.ThrowsAnyAsync<Exception>(() => new RsaOaepSha256Cryptor().ProtectAsync(Header(CvkKeyWrapAlgorithm.RsaOaepSha256), Payload([recipient])).AsTask());
    }

    [Fact]
    public async Task PasswordCiphertextTampering_IsRejected()
    {
        var header = Header(CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256);
        var body = await new PasswordPbkdf2Sha256Cryptor("secret").ProtectAsync(header, Payload());
        var tampered = body.ToArray();
        tampered[^1] ^= 1;
        await Assert.ThrowsAsync<CryptographicException>(() => new PasswordPbkdf2Sha256Cryptor("secret").UnprotectAsync(header, tampered).AsTask());
    }

    [Theory]
    [InlineData(1)]   // salt
    [InlineData(17)]  // nonce
    [InlineData(29)]  // authentication tag
    public async Task PasswordKeyBodyMetadataTampering_IsRejected(int offset)
    {
        var header = Header(CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256);
        var body = (await new PasswordPbkdf2Sha256Cryptor("secret").ProtectAsync(header, Payload())).ToArray();
        body[offset] ^= 0x01;

        await Assert.ThrowsAsync<CryptographicException>(() =>
            new PasswordPbkdf2Sha256Cryptor("secret").UnprotectAsync(header, body).AsTask());
    }

    [Fact]
    public async Task Password_HeaderAadTampering_IsRejected()
    {
        var header = Header(CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256);
        var body = await new PasswordPbkdf2Sha256Cryptor("secret").ProtectAsync(header, Payload());
        var altered = header with { Label = "changed" };
        await Assert.ThrowsAsync<CryptographicException>(() => new PasswordPbkdf2Sha256Cryptor("secret").UnprotectAsync(altered, body).AsTask());
    }

    [Fact]
    public async Task RsaCiphertextTampering_IsRejected()
    {
        using var rsa = RSA.Create(2048);
        var recipient = new AsymmetricRecipientKey("rsa", "RSA", rsa.ExportSubjectPublicKeyInfo());
        using var privateMaterial = new AsymmetricPrivateKeyMaterial("rsa", "RSA", rsa);
        var keys = new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["rsa"] = privateMaterial };
        var header = Header(CvkKeyWrapAlgorithm.RsaOaepSha256);
        var writer = new RsaOaepSha256Cryptor();
        var body = (await writer.ProtectAsync(header, Payload([recipient]))).ToArray();
        var text = System.Text.Encoding.UTF8.GetString(body);
        var marker = "\"ciphertext\":\"";
        var chars = text.ToCharArray();
        var index = text.IndexOf(marker, StringComparison.Ordinal) + marker.Length;
        chars[index] = chars[index] == 'A' ? 'B' : 'A';
        body = System.Text.Encoding.UTF8.GetBytes(new string(chars));
        await Assert.ThrowsAnyAsync<CryptographicException>(() => new RsaOaepSha256Cryptor(keys).UnprotectAsync(header, body).AsTask());
    }

    [Fact]
    public async Task Rsa_HeaderAadTampering_IsRejected()
    {
        using var rsa = RSA.Create(2048);
        var recipient = new AsymmetricRecipientKey("rsa", "RSA", rsa.ExportSubjectPublicKeyInfo());
        using var privateMaterial = new AsymmetricPrivateKeyMaterial("rsa", "RSA", rsa);
        var keys = new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["rsa"] = privateMaterial };
        var header = Header(CvkKeyWrapAlgorithm.RsaOaepSha256);
        var body = await new RsaOaepSha256Cryptor().ProtectAsync(header, Payload([recipient]));

        await Assert.ThrowsAnyAsync<CryptographicException>(() =>
            new RsaOaepSha256Cryptor(keys)
                .UnprotectAsync(header with { Label = "changed" }, body).AsTask());
    }

    [Theory]
    [InlineData("nonce")]
    [InlineData("tag")]
    [InlineData("wrappedKey")]
    public async Task RsaKeyBodyFieldTampering_IsRejected(string field)
    {
        using var rsa = RSA.Create(2048);
        var recipient = new AsymmetricRecipientKey("rsa", "RSA", rsa.ExportSubjectPublicKeyInfo());
        using var privateMaterial = new AsymmetricPrivateKeyMaterial("rsa", "RSA", rsa);
        var keys = new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["rsa"] = privateMaterial };
        var header = Header(CvkKeyWrapAlgorithm.RsaOaepSha256);
        var body = await new RsaOaepSha256Cryptor().ProtectAsync(header, Payload([recipient]));
        var json = System.Text.Encoding.UTF8.GetString(body.ToArray());
        var marker = $"\"{field}\":\"";
        var index = json.IndexOf(marker, StringComparison.Ordinal);
        Assert.True(index >= 0);
        var valueIndex = index + marker.Length;
        var chars = json.ToCharArray();
        chars[valueIndex] = chars[valueIndex] == 'A' ? 'B' : 'A';

        await Assert.ThrowsAnyAsync<CryptographicException>(() =>
            new RsaOaepSha256Cryptor(keys).UnprotectAsync(header,
                System.Text.Encoding.UTF8.GetBytes(new string(chars))).AsTask());
    }

    [Fact]
    public async Task RsaKeyBody_RejectsUnknownFields()
    {
        using var rsa = RSA.Create(2048);
        var recipient = new AsymmetricRecipientKey("rsa", "RSA", rsa.ExportSubjectPublicKeyInfo());
        using var privateMaterial = new AsymmetricPrivateKeyMaterial("rsa", "RSA", rsa);
        var header = Header(CvkKeyWrapAlgorithm.RsaOaepSha256);
        var body = await new RsaOaepSha256Cryptor().ProtectAsync(header, Payload([recipient]));
        var json = JsonNode.Parse(System.Text.Encoding.UTF8.GetString(body.ToArray()))!.AsObject();
        json["unexpected"] = true;

        await Assert.ThrowsAnyAsync<Exception>(() =>
            new RsaOaepSha256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["rsa"] = privateMaterial })
                .UnprotectAsync(header, System.Text.Encoding.UTF8.GetBytes(json.ToJsonString())).AsTask());
    }

    [Fact]
    public async Task RsaKeyBody_RejectsNonStringBinaryFields()
    {
        using var rsa = RSA.Create(2048);
        var recipient = new AsymmetricRecipientKey("rsa", "RSA", rsa.ExportSubjectPublicKeyInfo());
        using var privateMaterial = new AsymmetricPrivateKeyMaterial("rsa", "RSA", rsa);
        var header = Header(CvkKeyWrapAlgorithm.RsaOaepSha256);
        var body = await new RsaOaepSha256Cryptor().ProtectAsync(header, Payload([recipient]));
        var json = JsonNode.Parse(System.Text.Encoding.UTF8.GetString(body.ToArray()))!.AsObject();
        json["nonce"] = 123;

        await Assert.ThrowsAnyAsync<Exception>(() =>
            new RsaOaepSha256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["rsa"] = privateMaterial })
                .UnprotectAsync(header, System.Text.Encoding.UTF8.GetBytes(json.ToJsonString())).AsTask());
    }

    [Theory]
    [InlineData("nonce")]
    [InlineData("tag")]
    [InlineData("ciphertext")]
    [InlineData("recipients")]
    public async Task RsaKeyBodyMissingField_IsRejected(string field)
    {
        using var rsa = RSA.Create(2048);
        var recipient = new AsymmetricRecipientKey("rsa", "RSA", rsa.ExportSubjectPublicKeyInfo());
        using var privateMaterial = new AsymmetricPrivateKeyMaterial("rsa", "RSA", rsa);
        var header = Header(CvkKeyWrapAlgorithm.RsaOaepSha256);
        var body = await new RsaOaepSha256Cryptor().ProtectAsync(header, Payload([recipient]));
        var json = JsonNode.Parse(System.Text.Encoding.UTF8.GetString(body.ToArray()))!.AsObject();
        json.Remove(field);

        await Assert.ThrowsAnyAsync<Exception>(() =>
            new RsaOaepSha256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["rsa"] = privateMaterial })
                .UnprotectAsync(header, System.Text.Encoding.UTF8.GetBytes(json.ToJsonString())).AsTask());
    }

    [Theory]
    [InlineData("keyId")]
    [InlineData("wrappedKey")]
    [InlineData("recipient")]
    public async Task RsaWrappedRecipientMissingField_IsRejected(string field)
    {
        using var rsa = RSA.Create(2048);
        var recipient = new AsymmetricRecipientKey("rsa", "RSA", rsa.ExportSubjectPublicKeyInfo());
        using var privateMaterial = new AsymmetricPrivateKeyMaterial("rsa", "RSA", rsa);
        var header = Header(CvkKeyWrapAlgorithm.RsaOaepSha256);
        var body = await new RsaOaepSha256Cryptor().ProtectAsync(header, Payload([recipient]));
        var json = JsonNode.Parse(System.Text.Encoding.UTF8.GetString(body.ToArray()))!.AsObject();
        json["recipients"]!.AsArray()[0]!.AsObject().Remove(field);

        await Assert.ThrowsAnyAsync<Exception>(() =>
            new RsaOaepSha256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["rsa"] = privateMaterial })
                .UnprotectAsync(header, System.Text.Encoding.UTF8.GetBytes(json.ToJsonString())).AsTask());
    }

    [Theory]
    [InlineData("nonce")]
    [InlineData("tag")]
    [InlineData("ciphertext")]
    public async Task RsaKeyBody_RejectsEmptyBinaryFields(string field)
    {
        using var rsa = RSA.Create(2048);
        var recipient = new AsymmetricRecipientKey("rsa", "RSA", rsa.ExportSubjectPublicKeyInfo());
        using var privateMaterial = new AsymmetricPrivateKeyMaterial("rsa", "RSA", rsa);
        var header = Header(CvkKeyWrapAlgorithm.RsaOaepSha256);
        var body = await new RsaOaepSha256Cryptor().ProtectAsync(header, Payload([recipient]));
        var json = JsonNode.Parse(System.Text.Encoding.UTF8.GetString(body.ToArray()))!.AsObject();
        json[field] = string.Empty;

        await Assert.ThrowsAnyAsync<Exception>(() =>
            new RsaOaepSha256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["rsa"] = privateMaterial })
                .UnprotectAsync(header, System.Text.Encoding.UTF8.GetBytes(json.ToJsonString())).AsTask());
    }

    [Fact]
    public async Task RsaKeyBody_RejectsNullRecipientsArray()
    {
        using var rsa = RSA.Create(2048);
        var recipient = new AsymmetricRecipientKey("rsa", "RSA", rsa.ExportSubjectPublicKeyInfo());
        using var privateMaterial = new AsymmetricPrivateKeyMaterial("rsa", "RSA", rsa);
        var header = Header(CvkKeyWrapAlgorithm.RsaOaepSha256);
        var body = await new RsaOaepSha256Cryptor().ProtectAsync(header, Payload([recipient]));
        var json = JsonNode.Parse(System.Text.Encoding.UTF8.GetString(body.ToArray()))!.AsObject();
        json["recipients"] = null;

        await Assert.ThrowsAnyAsync<Exception>(() =>
            new RsaOaepSha256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["rsa"] = privateMaterial })
                .UnprotectAsync(header, System.Text.Encoding.UTF8.GetBytes(json.ToJsonString())).AsTask());
    }

    [Fact]
    public async Task RsaKeyBody_RejectsTrailingGarbage()
    {
        using var rsa = RSA.Create(2048);
        var header = Header(CvkKeyWrapAlgorithm.RsaOaepSha256);
        var body = await new RsaOaepSha256Cryptor().ProtectAsync(header,
            Payload([new AsymmetricRecipientKey("rsa", "RSA", rsa.ExportSubjectPublicKeyInfo())]));
        var malformed = body.ToArray().Concat(new byte[] { (byte)'x' }).ToArray();
        using var material = new AsymmetricPrivateKeyMaterial("rsa", "RSA", rsa);

        await Assert.ThrowsAnyAsync<Exception>(() =>
            new RsaOaepSha256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["rsa"] = material })
                .UnprotectAsync(header, malformed).AsTask());
    }

    [Fact]
    public async Task RsaUnprotect_RejectsBlankRecipientKeyId()
    {
        using var rsa = RSA.Create(2048);
        var header = Header(CvkKeyWrapAlgorithm.RsaOaepSha256);
        var body = await new RsaOaepSha256Cryptor().ProtectAsync(header,
            Payload([new AsymmetricRecipientKey("rsa", "RSA", rsa.ExportSubjectPublicKeyInfo())]));
        var json = JsonNode.Parse(System.Text.Encoding.UTF8.GetString(body.ToArray()))!.AsObject();
        json["recipients"]!.AsArray()[0]!["keyId"] = string.Empty;
        using var material = new AsymmetricPrivateKeyMaterial(string.Empty, "RSA", rsa);

        await Assert.ThrowsAnyAsync<Exception>(() =>
            new RsaOaepSha256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial> { [string.Empty] = material })
                .UnprotectAsync(header, System.Text.Encoding.UTF8.GetBytes(json.ToJsonString())).AsTask());
    }

    [Fact]
    public async Task RsaUnprotect_RejectsDuplicateRecipientIds()
    {
        using var first = RSA.Create(2048);
        using var second = RSA.Create(2048);
        var header = Header(CvkKeyWrapAlgorithm.RsaOaepSha256);
        var body = await new RsaOaepSha256Cryptor().ProtectAsync(header, Payload([
            new AsymmetricRecipientKey("first", "RSA", first.ExportSubjectPublicKeyInfo()),
            new AsymmetricRecipientKey("second", "RSA", second.ExportSubjectPublicKeyInfo())]));
        var json = JsonNode.Parse(System.Text.Encoding.UTF8.GetString(body.ToArray()))!.AsObject();
        json["recipients"]!.AsArray()[1]!["keyId"] = "first";
        using var material = new AsymmetricPrivateKeyMaterial("first", "RSA", first);

        await Assert.ThrowsAnyAsync<Exception>(() =>
            new RsaOaepSha256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["first"] = material })
                .UnprotectAsync(header, System.Text.Encoding.UTF8.GetBytes(json.ToJsonString())).AsTask());
    }

    [Fact]
    public async Task RsaWrappedRecipient_RejectsMalformedEmbeddedMetadata()
    {
        using var rsa = RSA.Create(2048);
        var recipient = new AsymmetricRecipientKey("rsa", "RSA", rsa.ExportSubjectPublicKeyInfo());
        using var privateMaterial = new AsymmetricPrivateKeyMaterial("rsa", "RSA", rsa);
        var header = Header(CvkKeyWrapAlgorithm.RsaOaepSha256);
        var body = await new RsaOaepSha256Cryptor().ProtectAsync(header, Payload([recipient]));
        var json = JsonNode.Parse(System.Text.Encoding.UTF8.GetString(body.ToArray()))!.AsObject();
        json["recipients"]!.AsArray()[0]!["recipient"]!["publicKey"] = string.Empty;

        await Assert.ThrowsAnyAsync<Exception>(() =>
            new RsaOaepSha256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["rsa"] = privateMaterial })
                .UnprotectAsync(header, System.Text.Encoding.UTF8.GetBytes(json.ToJsonString())).AsTask());
    }

    [Fact]
    public async Task RsaWrappedRecipient_RejectsNullEmbeddedRecipient()
    {
        using var rsa = RSA.Create(2048);
        var header = Header(CvkKeyWrapAlgorithm.RsaOaepSha256);
        var body = await new RsaOaepSha256Cryptor().ProtectAsync(header,
            Payload([new AsymmetricRecipientKey("rsa", "RSA", rsa.ExportSubjectPublicKeyInfo())]));
        var json = JsonNode.Parse(System.Text.Encoding.UTF8.GetString(body.ToArray()))!.AsObject();
        json["recipients"]!.AsArray()[0]!["recipient"] = null;
        using var material = new AsymmetricPrivateKeyMaterial("rsa", "RSA", rsa);

        await Assert.ThrowsAnyAsync<Exception>(() =>
            new RsaOaepSha256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["rsa"] = material })
                .UnprotectAsync(header, System.Text.Encoding.UTF8.GetBytes(json.ToJsonString())).AsTask());
    }

    [Fact]
    public async Task RsaUnprotect_SkipsMalformedFirstRecipientAndUsesNext()
    {
        using var first = RSA.Create(2048);
        using var second = RSA.Create(2048);
        var recipients = new[]
        {
            new AsymmetricRecipientKey("first", "RSA", first.ExportSubjectPublicKeyInfo()),
            new AsymmetricRecipientKey("second", "RSA", second.ExportSubjectPublicKeyInfo())
        };
        var header = Header(CvkKeyWrapAlgorithm.RsaOaepSha256);
        var body = await new RsaOaepSha256Cryptor().ProtectAsync(header, Payload(recipients));
        var json = JsonNode.Parse(System.Text.Encoding.UTF8.GetString(body.ToArray()))!.AsObject();
        json["recipients"]!.AsArray()[0]!["wrappedKey"] = "not-base64";
        using var firstMaterial = new AsymmetricPrivateKeyMaterial("first", "RSA", first);
        using var secondMaterial = new AsymmetricPrivateKeyMaterial("second", "RSA", second);

        var restored = await new RsaOaepSha256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial>
        {
            ["first"] = firstMaterial, ["second"] = secondMaterial
        }).UnprotectAsync(header, System.Text.Encoding.UTF8.GetBytes(json.ToJsonString()));
        Assert.Equal(32, restored.Cek.Length);
    }

    [Fact]
    public async Task RsaUnprotect_SkipsNullFirstRecipientAndUsesNext()
    {
        using var first = RSA.Create(2048);
        using var second = RSA.Create(2048);
        var header = Header(CvkKeyWrapAlgorithm.RsaOaepSha256);
        var body = await new RsaOaepSha256Cryptor().ProtectAsync(header, Payload([
            new AsymmetricRecipientKey("first", "RSA", first.ExportSubjectPublicKeyInfo()),
            new AsymmetricRecipientKey("second", "RSA", second.ExportSubjectPublicKeyInfo())]));
        var json = JsonNode.Parse(System.Text.Encoding.UTF8.GetString(body.ToArray()))!.AsObject();
        json["recipients"]!.AsArray()[0] = null;
        using var firstMaterial = new AsymmetricPrivateKeyMaterial("first", "RSA", first);
        using var secondMaterial = new AsymmetricPrivateKeyMaterial("second", "RSA", second);

        var restored = await new RsaOaepSha256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial>
        {
            ["first"] = firstMaterial, ["second"] = secondMaterial
        }).UnprotectAsync(header, System.Text.Encoding.UTF8.GetBytes(json.ToJsonString()));
        Assert.Equal(32, restored.Cek.Length);
    }

    [Fact]
    public async Task RsaUnprotect_SkipsNullPrivateMaterialAndUsesNext()
    {
        using var first = RSA.Create(2048);
        using var second = RSA.Create(2048);
        var header = Header(CvkKeyWrapAlgorithm.RsaOaepSha256);
        var body = await new RsaOaepSha256Cryptor().ProtectAsync(header, Payload([
            new AsymmetricRecipientKey("first", "RSA", first.ExportSubjectPublicKeyInfo()),
            new AsymmetricRecipientKey("second", "RSA", second.ExportSubjectPublicKeyInfo())]));
        using var secondMaterial = new AsymmetricPrivateKeyMaterial("second", "RSA", second);
        var restored = await new RsaOaepSha256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial>
        {
            ["first"] = null!, ["second"] = secondMaterial
        }).UnprotectAsync(header, body);
        Assert.Equal(32, restored.Cek.Length);
    }

    [Fact]
    public async Task RsaUnprotect_SkipsWrongPrivateAlgorithmAndUsesNext()
    {
        using var first = RSA.Create(2048);
        using var second = RSA.Create(2048);
        using var wrong = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var header = Header(CvkKeyWrapAlgorithm.RsaOaepSha256);
        var body = await new RsaOaepSha256Cryptor().ProtectAsync(header, Payload([
            new AsymmetricRecipientKey("first", "RSA", first.ExportSubjectPublicKeyInfo()),
            new AsymmetricRecipientKey("second", "RSA", second.ExportSubjectPublicKeyInfo())]));
        using var wrongMaterial = new AsymmetricPrivateKeyMaterial("first", "ECDSA", wrong);
        using var secondMaterial = new AsymmetricPrivateKeyMaterial("second", "RSA", second);

        var restored = await new RsaOaepSha256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial>
        {
            ["first"] = wrongMaterial, ["second"] = secondMaterial
        }).UnprotectAsync(header, body);
        Assert.Equal(32, restored.Cek.Length);
    }

    [Fact]
    public async Task RsaCryptor_RejectsDuplicateRecipientIds()
    {
        using var rsa = RSA.Create(2048);
        var publicKey = rsa.ExportSubjectPublicKeyInfo();
        var recipients = new[]
        {
            new AsymmetricRecipientKey("duplicate", "RSA", publicKey),
            new AsymmetricRecipientKey("duplicate", "RSA", publicKey)
        };

        await Assert.ThrowsAnyAsync<Exception>(() =>
            new RsaOaepSha256Cryptor().ProtectAsync(Header(CvkKeyWrapAlgorithm.RsaOaepSha256), Payload(recipients)).AsTask());
    }

    [Fact]
    public async Task RsaCryptor_RejectsEmptyRecipients()
    {
        await Assert.ThrowsAnyAsync<Exception>(() =>
            new RsaOaepSha256Cryptor().ProtectAsync(Header(CvkKeyWrapAlgorithm.RsaOaepSha256), Payload()).AsTask());
    }

    [Fact]
    public async Task RsaCryptor_RejectsNullRecipientElement()
    {
        await Assert.ThrowsAnyAsync<Exception>(() =>
            new RsaOaepSha256Cryptor().ProtectAsync(Header(CvkKeyWrapAlgorithm.RsaOaepSha256),
                Payload([null!])).AsTask());
    }

    [Fact]
    public async Task RsaCryptor_RejectsNullRecipientsCollection()
    {
        await Assert.ThrowsAnyAsync<Exception>(() =>
            new RsaOaepSha256Cryptor().ProtectAsync(Header(CvkKeyWrapAlgorithm.RsaOaepSha256),
                new CvkPayload(new byte[32], null!)).AsTask());
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task RsaCryptor_RejectsBlankRecipientKeyId(string keyId)
    {
        using var rsa = RSA.Create(2048);
        var recipient = new AsymmetricRecipientKey(keyId, "RSA", rsa.ExportSubjectPublicKeyInfo());
        await Assert.ThrowsAnyAsync<Exception>(() =>
            new RsaOaepSha256Cryptor().ProtectAsync(Header(CvkKeyWrapAlgorithm.RsaOaepSha256), Payload([recipient])).AsTask());
    }

    [Fact]
    public async Task RsaCryptor_DoesNotMutateRecipientMetadata()
    {
        using var rsa = RSA.Create(2048);
        var publicKey = rsa.ExportSubjectPublicKeyInfo();
        var recipients = new List<AsymmetricRecipientKey>
        {
            new("first", "RSA", publicKey, "one"),
            new("second", "RSA", publicKey, "two")
        };
        var snapshot = recipients.ToArray();

        await new RsaOaepSha256Cryptor().ProtectAsync(Header(CvkKeyWrapAlgorithm.RsaOaepSha256), Payload(recipients.ToArray()));

        Assert.Equal(snapshot, recipients);
        for (var i = 0; i < snapshot.Length; i++)
            Assert.Equal(snapshot[i].PublicKeyBytes.ToArray(), recipients[i].PublicKeyBytes.ToArray());
    }

    [Fact]
    public async Task EcdhCiphertextTampering_IsRejected()
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var recipient = new AsymmetricRecipientKey("ec", "ECDH", ecdh.ExportSubjectPublicKeyInfo());
        using var privateMaterial = new AsymmetricPrivateKeyMaterial("ec", "ECDH", ecdh);
        var header = Header(CvkKeyWrapAlgorithm.EcdhP256);
        var body = (await new EcdhP256Cryptor().ProtectAsync(header, Payload([recipient]))).ToArray();
        var text = System.Text.Encoding.UTF8.GetString(body);
        var marker = "\"ciphertext\":\"";
        var chars = text.ToCharArray();
        var index = text.IndexOf(marker, StringComparison.Ordinal) + marker.Length;
        chars[index] = chars[index] == 'A' ? 'B' : 'A';
        body = System.Text.Encoding.UTF8.GetBytes(new string(chars));
        var keys = new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["ec"] = privateMaterial };
        await Assert.ThrowsAnyAsync<Exception>(() => new EcdhP256Cryptor(keys).UnprotectAsync(header, body).AsTask());
    }

    [Fact]
    public async Task Ecdh_HeaderAadTampering_IsRejected()
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var recipient = new AsymmetricRecipientKey("ec", "ECDH", ecdh.ExportSubjectPublicKeyInfo());
        using var privateMaterial = new AsymmetricPrivateKeyMaterial("ec", "ECDH", ecdh);
        var keys = new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["ec"] = privateMaterial };
        var header = Header(CvkKeyWrapAlgorithm.EcdhP256);
        var body = await new EcdhP256Cryptor().ProtectAsync(header, Payload([recipient]));

        await Assert.ThrowsAnyAsync<CryptographicException>(() =>
            new EcdhP256Cryptor(keys)
                .UnprotectAsync(header with { Label = "changed" }, body).AsTask());
    }

    [Theory]
    [InlineData("dataNonce")]
    [InlineData("dataTag")]
    [InlineData("ephemeralPublicKey")]
    [InlineData("nonce")]
    [InlineData("tag")]
    [InlineData("wrappedKey")]
    public async Task EcdhKeyBodyFieldTampering_IsRejected(string field)
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var recipient = new AsymmetricRecipientKey("ec", "ECDH", ecdh.ExportSubjectPublicKeyInfo());
        using var privateMaterial = new AsymmetricPrivateKeyMaterial("ec", "ECDH", ecdh);
        var keys = new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["ec"] = privateMaterial };
        var header = Header(CvkKeyWrapAlgorithm.EcdhP256);
        var body = await new EcdhP256Cryptor().ProtectAsync(header, Payload([recipient]));
        var json = System.Text.Encoding.UTF8.GetString(body.ToArray());
        var marker = $"\"{field}\":\"";
        var index = json.IndexOf(marker, StringComparison.Ordinal);
        Assert.True(index >= 0);
        var chars = json.ToCharArray();
        var valueIndex = index + marker.Length;
        chars[valueIndex] = chars[valueIndex] == 'A' ? 'B' : 'A';

        await Assert.ThrowsAnyAsync<CryptographicException>(() =>
            new EcdhP256Cryptor(keys).UnprotectAsync(header,
                System.Text.Encoding.UTF8.GetBytes(new string(chars))).AsTask());
    }

    [Fact]
    public async Task EcdhKeyBody_RejectsUnknownFields()
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var recipient = new AsymmetricRecipientKey("ec", "ECDH", ecdh.ExportSubjectPublicKeyInfo());
        using var privateMaterial = new AsymmetricPrivateKeyMaterial("ec", "ECDH", ecdh);
        var header = Header(CvkKeyWrapAlgorithm.EcdhP256);
        var body = await new EcdhP256Cryptor().ProtectAsync(header, Payload([recipient]));
        var json = JsonNode.Parse(System.Text.Encoding.UTF8.GetString(body.ToArray()))!.AsObject();
        json["unexpected"] = true;

        await Assert.ThrowsAnyAsync<Exception>(() =>
            new EcdhP256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["ec"] = privateMaterial })
                .UnprotectAsync(header, System.Text.Encoding.UTF8.GetBytes(json.ToJsonString())).AsTask());
    }

    [Fact]
    public async Task EcdhKeyBody_RejectsNonStringBinaryFields()
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var recipient = new AsymmetricRecipientKey("ec", "ECDH", ecdh.ExportSubjectPublicKeyInfo());
        using var privateMaterial = new AsymmetricPrivateKeyMaterial("ec", "ECDH", ecdh);
        var header = Header(CvkKeyWrapAlgorithm.EcdhP256);
        var body = await new EcdhP256Cryptor().ProtectAsync(header, Payload([recipient]));
        var json = JsonNode.Parse(System.Text.Encoding.UTF8.GetString(body.ToArray()))!.AsObject();
        json["dataNonce"] = 123;

        await Assert.ThrowsAnyAsync<Exception>(() =>
            new EcdhP256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["ec"] = privateMaterial })
                .UnprotectAsync(header, System.Text.Encoding.UTF8.GetBytes(json.ToJsonString())).AsTask());
    }

    [Theory]
    [InlineData("dataNonce")]
    [InlineData("dataTag")]
    [InlineData("ciphertext")]
    public async Task EcdhKeyBody_RejectsEmptyBinaryFields(string field)
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var recipient = new AsymmetricRecipientKey("ec", "ECDH", ecdh.ExportSubjectPublicKeyInfo());
        using var privateMaterial = new AsymmetricPrivateKeyMaterial("ec", "ECDH", ecdh);
        var header = Header(CvkKeyWrapAlgorithm.EcdhP256);
        var body = await new EcdhP256Cryptor().ProtectAsync(header, Payload([recipient]));
        var json = JsonNode.Parse(System.Text.Encoding.UTF8.GetString(body.ToArray()))!.AsObject();
        json[field] = string.Empty;

        await Assert.ThrowsAnyAsync<Exception>(() =>
            new EcdhP256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["ec"] = privateMaterial })
                .UnprotectAsync(header, System.Text.Encoding.UTF8.GetBytes(json.ToJsonString())).AsTask());
    }

    [Fact]
    public async Task EcdhKeyBody_RejectsNullRecipientsArray()
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var recipient = new AsymmetricRecipientKey("ec", "ECDH", ecdh.ExportSubjectPublicKeyInfo());
        using var privateMaterial = new AsymmetricPrivateKeyMaterial("ec", "ECDH", ecdh);
        var header = Header(CvkKeyWrapAlgorithm.EcdhP256);
        var body = await new EcdhP256Cryptor().ProtectAsync(header, Payload([recipient]));
        var json = JsonNode.Parse(System.Text.Encoding.UTF8.GetString(body.ToArray()))!.AsObject();
        json["recipients"] = null;

        await Assert.ThrowsAnyAsync<Exception>(() =>
            new EcdhP256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["ec"] = privateMaterial })
                .UnprotectAsync(header, System.Text.Encoding.UTF8.GetBytes(json.ToJsonString())).AsTask());
    }

    [Fact]
    public async Task EcdhKeyBody_RejectsTrailingGarbage()
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var header = Header(CvkKeyWrapAlgorithm.EcdhP256);
        var body = await new EcdhP256Cryptor().ProtectAsync(header,
            Payload([new AsymmetricRecipientKey("ec", "ECDH", ecdh.ExportSubjectPublicKeyInfo())]));
        var malformed = body.ToArray().Concat(new byte[] { (byte)'x' }).ToArray();
        using var material = new AsymmetricPrivateKeyMaterial("ec", "ECDH", ecdh);

        await Assert.ThrowsAnyAsync<Exception>(() =>
            new EcdhP256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["ec"] = material })
                .UnprotectAsync(header, malformed).AsTask());
    }

    [Fact]
    public async Task EcdhUnprotect_RejectsBlankRecipientKeyId()
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var header = Header(CvkKeyWrapAlgorithm.EcdhP256);
        var body = await new EcdhP256Cryptor().ProtectAsync(header,
            Payload([new AsymmetricRecipientKey("ec", "ECDH", ecdh.ExportSubjectPublicKeyInfo())]));
        var json = JsonNode.Parse(System.Text.Encoding.UTF8.GetString(body.ToArray()))!.AsObject();
        json["recipients"]!.AsArray()[0]!["keyId"] = string.Empty;
        using var material = new AsymmetricPrivateKeyMaterial(string.Empty, "ECDH", ecdh);

        await Assert.ThrowsAnyAsync<Exception>(() =>
            new EcdhP256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial> { [string.Empty] = material })
                .UnprotectAsync(header, System.Text.Encoding.UTF8.GetBytes(json.ToJsonString())).AsTask());
    }

    [Fact]
    public async Task EcdhUnprotect_RejectsDuplicateRecipientIds()
    {
        using var first = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var second = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var header = Header(CvkKeyWrapAlgorithm.EcdhP256);
        var body = await new EcdhP256Cryptor().ProtectAsync(header, Payload([
            new AsymmetricRecipientKey("first", "ECDH", first.ExportSubjectPublicKeyInfo()),
            new AsymmetricRecipientKey("second", "ECDH", second.ExportSubjectPublicKeyInfo())]));
        var json = JsonNode.Parse(System.Text.Encoding.UTF8.GetString(body.ToArray()))!.AsObject();
        json["recipients"]!.AsArray()[1]!["keyId"] = "first";
        using var material = new AsymmetricPrivateKeyMaterial("first", "ECDH", first);

        await Assert.ThrowsAnyAsync<Exception>(() =>
            new EcdhP256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["first"] = material })
                .UnprotectAsync(header, System.Text.Encoding.UTF8.GetBytes(json.ToJsonString())).AsTask());
    }

    [Fact]
    public async Task EcdhWrappedRecipient_RejectsMalformedEmbeddedMetadata()
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var recipient = new AsymmetricRecipientKey("ec", "ECDH", ecdh.ExportSubjectPublicKeyInfo());
        using var privateMaterial = new AsymmetricPrivateKeyMaterial("ec", "ECDH", ecdh);
        var header = Header(CvkKeyWrapAlgorithm.EcdhP256);
        var body = await new EcdhP256Cryptor().ProtectAsync(header, Payload([recipient]));
        var json = JsonNode.Parse(System.Text.Encoding.UTF8.GetString(body.ToArray()))!.AsObject();
        json["recipients"]!.AsArray()[0]!["recipient"]!["publicKey"] = string.Empty;

        await Assert.ThrowsAnyAsync<Exception>(() =>
            new EcdhP256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["ec"] = privateMaterial })
                .UnprotectAsync(header, System.Text.Encoding.UTF8.GetBytes(json.ToJsonString())).AsTask());
    }

    [Fact]
    public async Task EcdhWrappedRecipient_RejectsNullEmbeddedRecipient()
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var header = Header(CvkKeyWrapAlgorithm.EcdhP256);
        var body = await new EcdhP256Cryptor().ProtectAsync(header,
            Payload([new AsymmetricRecipientKey("ec", "ECDH", ecdh.ExportSubjectPublicKeyInfo())]));
        var json = JsonNode.Parse(System.Text.Encoding.UTF8.GetString(body.ToArray()))!.AsObject();
        json["recipients"]!.AsArray()[0]!["recipient"] = null;
        using var material = new AsymmetricPrivateKeyMaterial("ec", "ECDH", ecdh);

        await Assert.ThrowsAnyAsync<Exception>(() =>
            new EcdhP256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["ec"] = material })
                .UnprotectAsync(header, System.Text.Encoding.UTF8.GetBytes(json.ToJsonString())).AsTask());
    }

    [Fact]
    public async Task EcdhUnprotect_SkipsMalformedFirstRecipientAndUsesNext()
    {
        using var first = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var second = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var recipients = new[]
        {
            new AsymmetricRecipientKey("first", "ECDH", first.ExportSubjectPublicKeyInfo()),
            new AsymmetricRecipientKey("second", "ECDH", second.ExportSubjectPublicKeyInfo())
        };
        var header = Header(CvkKeyWrapAlgorithm.EcdhP256);
        var body = await new EcdhP256Cryptor().ProtectAsync(header, Payload(recipients));
        var json = JsonNode.Parse(System.Text.Encoding.UTF8.GetString(body.ToArray()))!.AsObject();
        json["recipients"]!.AsArray()[0]!["nonce"] = "not-base64";
        using var firstMaterial = new AsymmetricPrivateKeyMaterial("first", "ECDH", first);
        using var secondMaterial = new AsymmetricPrivateKeyMaterial("second", "ECDH", second);

        var restored = await new EcdhP256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial>
        {
            ["first"] = firstMaterial, ["second"] = secondMaterial
        }).UnprotectAsync(header, System.Text.Encoding.UTF8.GetBytes(json.ToJsonString()));
        Assert.Equal(32, restored.Cek.Length);
    }

    [Fact]
    public async Task EcdhUnprotect_SkipsNullFirstRecipientAndUsesNext()
    {
        using var first = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var second = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var header = Header(CvkKeyWrapAlgorithm.EcdhP256);
        var body = await new EcdhP256Cryptor().ProtectAsync(header, Payload([
            new AsymmetricRecipientKey("first", "ECDH", first.ExportSubjectPublicKeyInfo()),
            new AsymmetricRecipientKey("second", "ECDH", second.ExportSubjectPublicKeyInfo())]));
        var json = JsonNode.Parse(System.Text.Encoding.UTF8.GetString(body.ToArray()))!.AsObject();
        json["recipients"]!.AsArray()[0] = null;
        using var firstMaterial = new AsymmetricPrivateKeyMaterial("first", "ECDH", first);
        using var secondMaterial = new AsymmetricPrivateKeyMaterial("second", "ECDH", second);

        var restored = await new EcdhP256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial>
        {
            ["first"] = firstMaterial, ["second"] = secondMaterial
        }).UnprotectAsync(header, System.Text.Encoding.UTF8.GetBytes(json.ToJsonString()));
        Assert.Equal(32, restored.Cek.Length);
    }

    [Fact]
    public async Task EcdhUnprotect_SkipsNullPrivateMaterialAndUsesNext()
    {
        using var first = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var second = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var header = Header(CvkKeyWrapAlgorithm.EcdhP256);
        var body = await new EcdhP256Cryptor().ProtectAsync(header, Payload([
            new AsymmetricRecipientKey("first", "ECDH", first.ExportSubjectPublicKeyInfo()),
            new AsymmetricRecipientKey("second", "ECDH", second.ExportSubjectPublicKeyInfo())]));
        using var secondMaterial = new AsymmetricPrivateKeyMaterial("second", "ECDH", second);
        var restored = await new EcdhP256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial>
        {
            ["first"] = null!, ["second"] = secondMaterial
        }).UnprotectAsync(header, body);
        Assert.Equal(32, restored.Cek.Length);
    }

    [Fact]
    public async Task EcdhUnprotect_SkipsWrongPrivateAlgorithmAndUsesNext()
    {
        using var first = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var second = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var wrong = RSA.Create(2048);
        var header = Header(CvkKeyWrapAlgorithm.EcdhP256);
        var body = await new EcdhP256Cryptor().ProtectAsync(header, Payload([
            new AsymmetricRecipientKey("first", "ECDH", first.ExportSubjectPublicKeyInfo()),
            new AsymmetricRecipientKey("second", "ECDH", second.ExportSubjectPublicKeyInfo())]));
        using var wrongMaterial = new AsymmetricPrivateKeyMaterial("first", "RSA", wrong);
        using var secondMaterial = new AsymmetricPrivateKeyMaterial("second", "ECDH", second);

        var restored = await new EcdhP256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial>
        {
            ["first"] = wrongMaterial, ["second"] = secondMaterial
        }).UnprotectAsync(header, body);
        Assert.Equal(32, restored.Cek.Length);
    }

    [Fact]
    public async Task EcdhUnprotect_SkipsFirstRecipientWithWrongCurve()
    {
        using var first = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var second = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var wrongCurve = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384);
        var recipients = new[]
        {
            new AsymmetricRecipientKey("first", "ECDH", first.ExportSubjectPublicKeyInfo()),
            new AsymmetricRecipientKey("second", "ECDH", second.ExportSubjectPublicKeyInfo())
        };
        var header = Header(CvkKeyWrapAlgorithm.EcdhP256);
        var body = await new EcdhP256Cryptor().ProtectAsync(header, Payload(recipients));
        var json = JsonNode.Parse(System.Text.Encoding.UTF8.GetString(body.ToArray()))!.AsObject();
        json["recipients"]!.AsArray()[0]!["ephemeralPublicKey"] =
            Convert.ToBase64String(wrongCurve.ExportSubjectPublicKeyInfo());
        using var firstMaterial = new AsymmetricPrivateKeyMaterial("first", "ECDH", first);
        using var secondMaterial = new AsymmetricPrivateKeyMaterial("second", "ECDH", second);

        var restored = await new EcdhP256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial>
        {
            ["first"] = firstMaterial, ["second"] = secondMaterial
        }).UnprotectAsync(header, System.Text.Encoding.UTF8.GetBytes(json.ToJsonString()));
        Assert.Equal(32, restored.Cek.Length);
    }

    [Fact]
    public async Task EcdhCryptor_RejectsDuplicateRecipientIds()
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = ecdh.ExportSubjectPublicKeyInfo();
        var recipients = new[]
        {
            new AsymmetricRecipientKey("duplicate", "ECDH", publicKey),
            new AsymmetricRecipientKey("duplicate", "ECDH", publicKey)
        };

        await Assert.ThrowsAnyAsync<Exception>(() =>
            new EcdhP256Cryptor().ProtectAsync(Header(CvkKeyWrapAlgorithm.EcdhP256), Payload(recipients)).AsTask());
    }

    [Fact]
    public async Task EcdhCryptor_RejectsEmptyRecipients()
    {
        await Assert.ThrowsAnyAsync<Exception>(() =>
            new EcdhP256Cryptor().ProtectAsync(Header(CvkKeyWrapAlgorithm.EcdhP256), Payload()).AsTask());
    }

    [Fact]
    public async Task EcdhCryptor_RejectsNullRecipientElement()
    {
        await Assert.ThrowsAnyAsync<Exception>(() =>
            new EcdhP256Cryptor().ProtectAsync(Header(CvkKeyWrapAlgorithm.EcdhP256),
                Payload([null!])).AsTask());
    }

    [Fact]
    public async Task EcdhCryptor_RejectsNullRecipientsCollection()
    {
        await Assert.ThrowsAnyAsync<Exception>(() =>
            new EcdhP256Cryptor().ProtectAsync(Header(CvkKeyWrapAlgorithm.EcdhP256),
                new CvkPayload(new byte[32], null!)).AsTask());
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task EcdhCryptor_RejectsBlankRecipientKeyId(string keyId)
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var recipient = new AsymmetricRecipientKey(keyId, "ECDH", ecdh.ExportSubjectPublicKeyInfo());
        await Assert.ThrowsAnyAsync<Exception>(() =>
            new EcdhP256Cryptor().ProtectAsync(Header(CvkKeyWrapAlgorithm.EcdhP256), Payload([recipient])).AsTask());
    }

    [Fact]
    public async Task EcdhCryptor_DoesNotMutateRecipientMetadata()
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = ecdh.ExportSubjectPublicKeyInfo();
        var recipients = new List<AsymmetricRecipientKey>
        {
            new("first", "ECDH", publicKey, "one"),
            new("second", "ECDH", publicKey, "two")
        };
        var snapshot = recipients.ToArray();

        await new EcdhP256Cryptor().ProtectAsync(Header(CvkKeyWrapAlgorithm.EcdhP256), Payload(recipients.ToArray()));

        Assert.Equal(snapshot, recipients);
        for (var i = 0; i < snapshot.Length; i++)
            Assert.Equal(snapshot[i].PublicKeyBytes.ToArray(), recipients[i].PublicKeyBytes.ToArray());
    }

    [Theory]
    [InlineData("dataNonce")]
    [InlineData("dataTag")]
    [InlineData("ciphertext")]
    [InlineData("ephemeralPublicKey")]
    [InlineData("nonce")]
    [InlineData("tag")]
    [InlineData("wrappedKey")]
    [InlineData("recipients")]
    public async Task EcdhKeyBodyMissingField_IsRejected(string field)
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var recipient = new AsymmetricRecipientKey("ec", "ECDH", ecdh.ExportSubjectPublicKeyInfo());
        using var privateMaterial = new AsymmetricPrivateKeyMaterial("ec", "ECDH", ecdh);
        var header = Header(CvkKeyWrapAlgorithm.EcdhP256);
        var body = await new EcdhP256Cryptor().ProtectAsync(header, Payload([recipient]));
        var json = JsonNode.Parse(System.Text.Encoding.UTF8.GetString(body.ToArray()))!.AsObject();
        if (json.ContainsKey(field))
            json.Remove(field);
        else
            json["recipients"]!.AsArray()[0]![field] = null;

        await Assert.ThrowsAnyAsync<Exception>(() =>
            new EcdhP256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["ec"] = privateMaterial })
                .UnprotectAsync(header, System.Text.Encoding.UTF8.GetBytes(json.ToJsonString())).AsTask());
    }

    [Fact]
    public async Task PasswordCryptor_RejectsInvalidCekLength()
    {
        var header = Header(CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256);
        var payload = new CvkPayload(new byte[31], []);
        await Assert.ThrowsAsync<InvalidDataException>(() => new PasswordPbkdf2Sha256Cryptor("secret").ProtectAsync(header, payload).AsTask());
    }

    [Fact]
    public async Task PasswordUnprotect_HonorsCancellation()
    {
        var header = Header(CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256);
        var body = await new PasswordPbkdf2Sha256Cryptor("secret").ProtectAsync(header, Payload());
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new PasswordPbkdf2Sha256Cryptor("secret").UnprotectAsync(header, body, cts.Token).AsTask());
    }

    [Fact]
    public async Task Argon2Cryptor_HonorsCancellation()
    {
        var cryptor = new PasswordArgon2IdCryptor("secret");
        var header = Header(CvkKeyWrapAlgorithm.PasswordArgon2Id);
        var payload = Payload();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cryptor.ProtectAsync(header, payload, cts.Token).AsTask());
        var body = await cryptor.ProtectAsync(header, payload);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cryptor.UnprotectAsync(header, body, cts.Token).AsTask());
    }

    [Fact]
    public async Task EcdhCryptor_HonorsCancellation()
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var recipient = new AsymmetricRecipientKey("ec", "ECDH", ecdh.ExportSubjectPublicKeyInfo());
        using var privateMaterial = new AsymmetricPrivateKeyMaterial("ec", "ECDH", ecdh);
        var header = Header(CvkKeyWrapAlgorithm.EcdhP256);
        var payload = Payload([recipient]);
        var protector = new EcdhP256Cryptor();
        var body = await protector.ProtectAsync(header, payload);
        var unprotector = new EcdhP256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["ec"] = privateMaterial });
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => protector.ProtectAsync(header, payload, cts.Token).AsTask());
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => unprotector.UnprotectAsync(header, body, cts.Token).AsTask());
    }

    [Fact]
    public async Task EcdhUnprotect_RejectsPrivateKeyOnWrongCurve()
    {
        using var recipientKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var wrongCurveKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384);
        var recipient = new AsymmetricRecipientKey("ec", "ECDH", recipientKey.ExportSubjectPublicKeyInfo());
        var header = Header(CvkKeyWrapAlgorithm.EcdhP256);
        var body = await new EcdhP256Cryptor().ProtectAsync(header, Payload([recipient]));
        using var wrongMaterial = new AsymmetricPrivateKeyMaterial("ec", "ECDH", wrongCurveKey);

        await Assert.ThrowsAnyAsync<Exception>(() =>
            new EcdhP256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["ec"] = wrongMaterial })
                .UnprotectAsync(header, body).AsTask());
    }

    [Fact]
    public async Task RsaCryptor_HonorsCancellation()
    {
        using var rsa = RSA.Create(2048);
        var recipient = new AsymmetricRecipientKey("rsa", "RSA", rsa.ExportSubjectPublicKeyInfo());
        using var privateMaterial = new AsymmetricPrivateKeyMaterial("rsa", "RSA", rsa);
        var header = Header(CvkKeyWrapAlgorithm.RsaOaepSha256);
        var payload = Payload([recipient]);
        var protector = new RsaOaepSha256Cryptor();
        var body = await protector.ProtectAsync(header, payload);
        var unprotector = new RsaOaepSha256Cryptor(new Dictionary<string, AsymmetricPrivateKeyMaterial> { ["rsa"] = privateMaterial });
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => protector.ProtectAsync(header, payload, cts.Token).AsTask());
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => unprotector.UnprotectAsync(header, body, cts.Token).AsTask());
    }

    [Theory]
    [InlineData(CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256)]
    [InlineData(CvkKeyWrapAlgorithm.PasswordArgon2Id)]
    public async Task PasswordCryptors_RejectMissingBodyFields(CvkKeyWrapAlgorithm algorithm)
    {
        var cryptor = algorithm == CvkKeyWrapAlgorithm.PasswordArgon2Id
            ? (ICvkPayloadCryptor)new PasswordArgon2IdCryptor("secret")
            : new PasswordPbkdf2Sha256Cryptor("secret");
        await Assert.ThrowsAnyAsync<Exception>(() => cryptor.UnprotectAsync(Header(algorithm), "{}"u8.ToArray()).AsTask());
    }

    [Theory]
    [InlineData(CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256, (byte)2)]
    [InlineData(CvkKeyWrapAlgorithm.PasswordArgon2Id, (byte)1)]
    public async Task PasswordCryptors_RejectWrongBodyVersion(CvkKeyWrapAlgorithm algorithm, byte version)
    {
        var cryptor = algorithm == CvkKeyWrapAlgorithm.PasswordArgon2Id
            ? (ICvkPayloadCryptor)new PasswordArgon2IdCryptor("secret")
            : new PasswordPbkdf2Sha256Cryptor("secret");
        var body = (await cryptor.ProtectAsync(Header(algorithm), Payload())).ToArray();
        body[0] = version;
        await Assert.ThrowsAsync<InvalidDataException>(() => cryptor.UnprotectAsync(Header(algorithm), body).AsTask());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(28)]
    public async Task PasswordCryptor_RejectsTruncatedKeyBody(int length)
    {
        var body = new byte[length];
        if (length > 0) body[0] = 1;

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            new PasswordPbkdf2Sha256Cryptor("secret")
                .UnprotectAsync(Header(CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256), body).AsTask());
    }

    [Fact]
    public async Task PasswordCiphertext_InvalidBase64_IsRejected()
    {
        var header = Header(CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256);
        var body = await new PasswordPbkdf2Sha256Cryptor("secret").ProtectAsync(header, Payload());
        var text = System.Text.Encoding.UTF8.GetString(body.ToArray()).Replace("\"ciphertext\":\"", "\"ciphertext\":\"!", StringComparison.Ordinal);
        await Assert.ThrowsAnyAsync<Exception>(() => new PasswordPbkdf2Sha256Cryptor("secret").UnprotectAsync(header, System.Text.Encoding.UTF8.GetBytes(text)).AsTask());
    }

    [Fact]
    public async Task RsaCryptor_RejectsInvalidCekLength()
    {
        using var rsa = RSA.Create(2048);
        var recipient = new AsymmetricRecipientKey("rsa", "RSA", rsa.ExportSubjectPublicKeyInfo());
        var payload = new CvkPayload(new byte[31], [recipient]);
        await Assert.ThrowsAsync<InvalidDataException>(() => new RsaOaepSha256Cryptor().ProtectAsync(Header(CvkKeyWrapAlgorithm.RsaOaepSha256), payload).AsTask());
    }

    [Fact]
    public async Task EcdhCryptor_RejectsInvalidCekLength()
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var recipient = new AsymmetricRecipientKey("ec", "ECDH", ecdh.ExportSubjectPublicKeyInfo());
        var payload = new CvkPayload(new byte[31], [recipient]);
        await Assert.ThrowsAsync<InvalidDataException>(() => new EcdhP256Cryptor().ProtectAsync(Header(CvkKeyWrapAlgorithm.EcdhP256), payload).AsTask());
    }

    private sealed class RecordingCryptor : ICvkPayloadCryptor
    {
        public CvkHeader? ProtectHeader { get; private set; }
        public CvkPayload? ProtectPayload { get; private set; }
        public CancellationToken ProtectToken { get; private set; }
        public CvkHeader? UnprotectHeader { get; private set; }
        public byte[] UnprotectBody { get; private set; } = [];
        public CancellationToken UnprotectToken { get; private set; }

        public ValueTask<ReadOnlyMemory<byte>> ProtectAsync(CvkHeader header, CvkPayload payload, CancellationToken cancellationToken = default)
        {
            ProtectHeader = header;
            ProtectPayload = payload;
            ProtectToken = cancellationToken;
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(CvkPayloadCodec.Encode(payload));
        }

        public ValueTask<CvkPayload> UnprotectAsync(CvkHeader header, ReadOnlyMemory<byte> keyBody, CancellationToken cancellationToken = default)
        {
            UnprotectHeader = header;
            UnprotectBody = keyBody.ToArray();
            UnprotectToken = cancellationToken;
            return ValueTask.FromResult(CvkPayloadCodec.Decode(keyBody.Span));
        }
    }
}

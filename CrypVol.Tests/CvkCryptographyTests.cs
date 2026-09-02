using System.Security.Cryptography;
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
    public async Task PasswordPbkdf2_RoundTrips()
    {
        var cryptor = new PasswordPbkdf2Sha256Cryptor("correct horse battery staple");
        var header = Header(CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256);
        var payload = Payload();
        var body = await cryptor.ProtectAsync(header, payload);
        var restored = await cryptor.UnprotectAsync(header, body);
        Assert.Equal(payload.Cek.ToArray(), restored.Cek.ToArray());
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
    public async Task EcdhCryptor_RejectsNonEcdhRecipientAlgorithm()
    {
        using var rsa = RSA.Create(2048);
        var recipient = new AsymmetricRecipientKey("rsa", "RSA", rsa.ExportSubjectPublicKeyInfo());
        await Assert.ThrowsAnyAsync<Exception>(() => new EcdhP256Cryptor().ProtectAsync(Header(CvkKeyWrapAlgorithm.EcdhP256), Payload([recipient])).AsTask());
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
    public async Task PasswordCiphertextTampering_IsRejected()
    {
        var header = Header(CvkKeyWrapAlgorithm.PasswordPbkdf2Sha256);
        var body = await new PasswordPbkdf2Sha256Cryptor("secret").ProtectAsync(header, Payload());
        var tampered = body.ToArray();
        tampered[^1] ^= 1;
        await Assert.ThrowsAsync<CryptographicException>(() => new PasswordPbkdf2Sha256Cryptor("secret").UnprotectAsync(header, tampered).AsTask());
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
}

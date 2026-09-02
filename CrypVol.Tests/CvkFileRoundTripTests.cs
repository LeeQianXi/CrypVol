using System.Security.Cryptography;
using CrypVol.Lib.Crypto;
using CrypVol.Lib.Crypto.Cryptography;
using CrypVol.Lib.Crypto.Keys;
using CrypVol.Lib.Crypto.Models;
using CrypVol.Lib.Crypto.Reading;
using CrypVol.Lib.Crypto.Writing;
using Xunit;

namespace CrypVol.Tests;

/// <summary>验证 CVK 各保护算法经过真实文件写入、读取和解封后的完整行为。</summary>
public sealed class CvkFileRoundTripTests
{
    [Fact]
    public async Task Argon2_FileRoundTrip()
    {
        var document = CvkOperations.CreateNew(CvkKeyProtection.Password, CvkKeyWrapAlgorithm.PasswordArgon2Id);
        var file = TempFile();
        try
        {
            var cryptor = new PasswordArgon2IdCryptor("file-password");
            await new CvkWriter(new CvkPayloadProtectorAdapter(cryptor)).WriteAsync(document, file);
            var loaded = await new CvkReader(new Sha256IntegrityCalculator(), new CvkPayloadUnprotectorAdapter(
                new PasswordArgon2IdCryptor("file-password"))).ReadDocumentAsync(file);
            Assert.Equal(document.Cek, loaded.Cek);
            Assert.Equal(document.KeyWrapAlgorithm, loaded.KeyWrapAlgorithm);
        }
        finally { Delete(file); }
    }

    [Fact]
    public async Task Argon2_FileWrongPassword_IsRejected()
    {
        var document = CvkOperations.CreateNew(CvkKeyProtection.Password, CvkKeyWrapAlgorithm.PasswordArgon2Id);
        var file = TempFile();
        try
        {
            await new CvkWriter(new CvkPayloadProtectorAdapter(new PasswordArgon2IdCryptor("right"))).WriteAsync(document, file);
            await Assert.ThrowsAnyAsync<CryptographicException>(() => new CvkReader(new Sha256IntegrityCalculator(), new CvkPayloadUnprotectorAdapter(new PasswordArgon2IdCryptor("wrong"))).ReadDocumentAsync(file));
        }
        finally { Delete(file); }
    }

    [Theory]
    [InlineData(CvkKeyWrapAlgorithm.RsaOaepSha256)]
    [InlineData(CvkKeyWrapAlgorithm.RsaOaepSha384)]
    [InlineData(CvkKeyWrapAlgorithm.RsaOaepSha512)]
    public async Task Rsa_FileRoundTrip_WithMultipleRecipients(CvkKeyWrapAlgorithm algorithm)
    {
        using var first = RSA.Create(2048);
        using var second = RSA.Create(2048);
        var recipients = new[]
        {
            new AsymmetricRecipientKey("first", "RSA", first.ExportSubjectPublicKeyInfo(), "first recipient"),
            new AsymmetricRecipientKey("second", "RSA", second.ExportSubjectPublicKeyInfo(), "second recipient")
        };
        using var firstPrivate = new AsymmetricPrivateKeyMaterial("first", "RSA", first);
        using var secondPrivate = new AsymmetricPrivateKeyMaterial("second", "RSA", second);
        var document = CvkOperations.CreateNew(CvkKeyProtection.PublicKey, algorithm);
        foreach (var recipient in recipients) document.RecipientKeys.Add(recipient);
        var file = TempFile();
        try
        {
            var writerCryptor = CreateRsa(algorithm);
            await new CvkWriter(new CvkPayloadProtectorAdapter(writerCryptor)).WriteAsync(document, file);
            foreach (var privateKey in new[] { firstPrivate, secondPrivate })
            {
                var readerCryptor = CreateRsa(algorithm, new Dictionary<string, AsymmetricPrivateKeyMaterial> { [privateKey.KeyId] = privateKey });
                var loaded = await new CvkReader(new Sha256IntegrityCalculator(), new CvkPayloadUnprotectorAdapter(readerCryptor)).ReadDocumentAsync(file);
                Assert.Equal(document.Cek, loaded.Cek);
                Assert.Equal(2, loaded.RecipientKeys.Count);
                Assert.Equal("second recipient", loaded.RecipientKeys[1].Comment);
            }
        }
        finally { Delete(file); }
    }

    [Theory]
    [InlineData(CvkKeyWrapAlgorithm.EcdhP256)]
    [InlineData(CvkKeyWrapAlgorithm.EcdhP384)]
    [InlineData(CvkKeyWrapAlgorithm.EcdhP521)]
    public async Task Ecdh_FileRoundTrip_WithMultipleRecipients(CvkKeyWrapAlgorithm algorithm)
    {
        var curve = algorithm switch
        {
            CvkKeyWrapAlgorithm.EcdhP384 => ECCurve.NamedCurves.nistP384,
            CvkKeyWrapAlgorithm.EcdhP521 => ECCurve.NamedCurves.nistP521,
            _ => ECCurve.NamedCurves.nistP256
        };
        using var first = ECDiffieHellman.Create(curve);
        using var second = ECDiffieHellman.Create(curve);
        var recipients = new[]
        {
            new AsymmetricRecipientKey("first", "ECDH", first.ExportSubjectPublicKeyInfo()),
            new AsymmetricRecipientKey("second", "ECDH", second.ExportSubjectPublicKeyInfo())
        };
        using var firstPrivate = new AsymmetricPrivateKeyMaterial("first", "ECDH", first);
        using var secondPrivate = new AsymmetricPrivateKeyMaterial("second", "ECDH", second);
        var document = CvkOperations.CreateNew(CvkKeyProtection.PublicKey, algorithm);
        foreach (var recipient in recipients) document.RecipientKeys.Add(recipient);
        var file = TempFile();
        try
        {
            await new CvkWriter(new CvkPayloadProtectorAdapter(CreateEcdh(algorithm))).WriteAsync(document, file);
            foreach (var privateKey in new[] { firstPrivate, secondPrivate })
            {
                var privateKeys = new Dictionary<string, AsymmetricPrivateKeyMaterial> { [privateKey.KeyId] = privateKey };
                var loaded = await new CvkReader(new Sha256IntegrityCalculator(), new CvkPayloadUnprotectorAdapter(CreateEcdh(algorithm, privateKeys))).ReadDocumentAsync(file);
                Assert.Equal(document.Cek, loaded.Cek);
                Assert.Equal(2, loaded.RecipientKeys.Count);
            }
        }
        finally { Delete(file); }
    }

    private static ICvkPayloadCryptor CreateRsa(CvkKeyWrapAlgorithm algorithm, IReadOnlyDictionary<string, AsymmetricPrivateKeyMaterial>? keys = null) => algorithm switch
    {
        CvkKeyWrapAlgorithm.RsaOaepSha384 => new RsaOaepSha384Cryptor(keys),
        CvkKeyWrapAlgorithm.RsaOaepSha512 => new RsaOaepSha512Cryptor(keys),
        _ => new RsaOaepSha256Cryptor(keys)
    };

    private static ICvkPayloadCryptor CreateEcdh(CvkKeyWrapAlgorithm algorithm, IReadOnlyDictionary<string, AsymmetricPrivateKeyMaterial>? keys = null) => algorithm switch
    {
        CvkKeyWrapAlgorithm.EcdhP384 => new EcdhP384Cryptor(keys),
        CvkKeyWrapAlgorithm.EcdhP521 => new EcdhP521Cryptor(keys),
        _ => new EcdhP256Cryptor(keys)
    };

    private static FileInfo TempFile() => new(Path.Combine(Path.GetTempPath(), $"cvk-file-{Guid.NewGuid():N}.cvk"));
    private static void Delete(FileInfo file) { if (file.Exists) file.Delete(); }
}

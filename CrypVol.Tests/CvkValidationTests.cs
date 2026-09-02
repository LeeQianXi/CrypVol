using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using CrypVol.Lib.Crypto.Cryptography;
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
        await Assert.ThrowsAsync<InvalidDataException>(() => Write(document));
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
    public void Registry_RejectsUnknownRoute()
    {
        var registry = CvkPayloadCryptorRegistry.CreateDefault();
        Assert.Throws<NotSupportedException>(() => registry.Resolve(new CvkHeader(1, CvkKeyProtection.Password, CvkKeyWrapAlgorithm.RsaOaepSha256, null, null, null, null, null)));
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
    public void IntegrityCalculator_IsDeterministicAndInputSensitive()
    {
        var calculator = new Sha256IntegrityCalculator();
        var first = calculator.Compute("header"u8.ToArray(), "body"u8.ToArray());
        var second = calculator.Compute("header"u8.ToArray(), "body"u8.ToArray());
        var changed = calculator.Compute("header2"u8.ToArray(), "body"u8.ToArray());
        Assert.Equal(first.ToArray(), second.ToArray());
        Assert.NotEqual(first.ToArray(), changed.ToArray());
        Assert.Equal(32, first.Length);
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
    public void PayloadCodec_RejectsInvalidRecipientMetadata(string recipient)
    {
        var json = $"{{\"cek\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"recipientKeys\":[{recipient}]}}";
        Assert.ThrowsAny<Exception>(() => CvkPayloadCodec.Decode(System.Text.Encoding.UTF8.GetBytes(json)));
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
    public void Parser_RejectsUnknownEnumNames()
    {
        Assert.ThrowsAny<Exception>(() => CvkParser.Parse(BuildHeader("{\"version\":1,\"keyProtection\":\"Unknown\",\"keyWrapAlgorithm\":\"None\"}")));
        Assert.ThrowsAny<Exception>(() => CvkParser.Parse(BuildHeader("{\"version\":1,\"keyProtection\":\"Plain\",\"keyWrapAlgorithm\":\"Unknown\"}")));
        Assert.ThrowsAny<Exception>(() => CvkParser.Parse(BuildHeader("{\"version\":1,\"keyProtection\":\"0\",\"keyWrapAlgorithm\":\"None\"}")));
    }

    [Fact]
    public void Parser_RejectsMissingOrNullRouteFields()
    {
        Assert.ThrowsAny<Exception>(() => CvkParser.Parse(BuildHeader("{\"version\":1}")));
        Assert.ThrowsAny<Exception>(() => CvkParser.Parse(BuildHeader("{\"version\":1,\"keyProtection\":null,\"keyWrapAlgorithm\":\"None\"}")));
        Assert.ThrowsAny<Exception>(() => CvkParser.Parse(BuildHeader("{\"version\":1,\"keyProtection\":\"Plain\",\"keyWrapAlgorithm\":null}")));
    }

    [Fact]
    public void Parser_RejectsDuplicateHeaderFields()
    {
        var json = "{\"version\":1,\"version\":1,\"keyProtection\":\"Plain\",\"keyWrapAlgorithm\":\"None\"}";
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
    public async Task Writer_RejectsMissingParentDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), $"cvk-missing-parent-{Guid.NewGuid():N}", "nested", "file.cvk");
        var document = new CrypVol.Lib.Crypto.CvkDocument { Cek = new byte[32], KeyProtection = CvkKeyProtection.Plain, KeyWrapAlgorithm = CvkKeyWrapAlgorithm.None };
        await Assert.ThrowsAnyAsync<Exception>(() => new CvkWriter(new PlainCvkPayloadProtector()).WriteAsync(document, new FileInfo(path)));
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

    private sealed class LargeIntegrity : ICvkIntegrityCalculator
    {
        public ReadOnlyMemory<byte> Compute(ReadOnlyMemory<byte> headerJson, ReadOnlyMemory<byte> keyBody) => new byte[4097];
    }

    private sealed class EmptyIntegrity : ICvkIntegrityCalculator
    {
        public ReadOnlyMemory<byte> Compute(ReadOnlyMemory<byte> headerJson, ReadOnlyMemory<byte> keyBody) => ReadOnlyMemory<byte>.Empty;
    }
}

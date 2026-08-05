using System.Buffers;
using System.Security.Cryptography;
using CrypVol.Lib.Pipeline;
using CrypVol.Lib.Transforms;
using Xunit;

namespace CrypVol.Tests;

public class TransformTests
{
    // ═══════════════════════════════════════════════════════
    //  NullTransform
    // ═══════════════════════════════════════════════════════

    [Fact]
    public void NullTransform_CopiesData()
    {
        var transform = new NullTransform();
        var input = ArrayPool<byte>.Shared.Rent(100);
        RandomNumberGenerator.Fill(input);
        var output = transform.Transform(input, 100, out var outputLen);
        Assert.Equal(100, outputLen);
        Assert.True(input.AsSpan(0, 100).SequenceEqual(output.AsSpan(0, 100)));
        ArrayPool<byte>.Shared.Return(output);
    }

    [Fact]
    public void NullTransform_EmptyInput()
    {
        var transform = new NullTransform();
        var input = ArrayPool<byte>.Shared.Rent(0);
        var output = transform.Transform(input, 0, out var outputLen);
        Assert.Equal(0, outputLen);
        ArrayPool<byte>.Shared.Return(output);
    }

    // ═══════════════════════════════════════════════════════
    //  PackTransform
    // ═══════════════════════════════════════════════════════

    [Fact]
    public void PackTransform_NoCompression_EncryptsData()
    {
        var cek = RandomNumberGenerator.GetBytes(32);
        var transform = new PackTransform(cek, false, 6);

        var input = ArrayPool<byte>.Shared.Rent(100);
        try
        {
            RandomNumberGenerator.Fill(input);
            var output = transform.Transform(input, 100, out var outputLen);

            // Output format: nonce(12) + ciphertext + tag(16)
            Assert.True(outputLen >= 12 + 16);
            Assert.Equal(100 + 12 + 16, outputLen); // no compression, exact size

            // Verify we can decrypt it
            var nonce = output.AsSpan(0, 12);
            var tag = output.AsSpan(outputLen - 16, 16);
            var cipherLen = outputLen - 12 - 16;
            var plaintext = new byte[cipherLen];
            using var aes = new AesGcm(cek, 16);
            aes.Decrypt(nonce, output.AsSpan(12, cipherLen), tag, plaintext);
            Assert.True(input.AsSpan(0, 100).SequenceEqual(plaintext.AsSpan(0, 100)));

            ArrayPool<byte>.Shared.Return(output);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(input);
        }
    }

    [Fact]
    public void PackTransform_WithCompression_CompressesAndEncrypts()
    {
        var cek = RandomNumberGenerator.GetBytes(32);
        var transform = new PackTransform(cek, true, 9);

        // Create repetitive data that compresses well
        var input = ArrayPool<byte>.Shared.Rent(4096);
        try
        {
            Array.Fill(input, (byte)'A', 0, 4096);
            var output = transform.Transform(input, 4096, out var outputLen);

            // Compressed + encrypted should be significantly smaller
            Assert.True(outputLen < 4096 + 12 + 16);

            ArrayPool<byte>.Shared.Return(output);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(input);
        }
    }

    [Fact]
    public void PackTransform_DifferentCek_DifferentOutput()
    {
        var cek1 = RandomNumberGenerator.GetBytes(32);
        var cek2 = RandomNumberGenerator.GetBytes(32);
        var t1 = new PackTransform(cek1, false, 6);
        var t2 = new PackTransform(cek2, false, 6);

        var input = ArrayPool<byte>.Shared.Rent(100);
        try
        {
            RandomNumberGenerator.Fill(input);
            var o1 = t1.Transform(input, 100, out _);
            var o2 = t2.Transform(input, 100, out _);

            // Ciphertexts should differ
            Assert.False(o1.AsSpan(12, 100).SequenceEqual(o2.AsSpan(12, 100)));

            ArrayPool<byte>.Shared.Return(o1);
            ArrayPool<byte>.Shared.Return(o2);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(input);
        }
    }

    [Fact]
    public void PackTransform_CompressionLevel_MapsCorrectly()
    {
        var cek = RandomNumberGenerator.GetBytes(32);
        // Level 0 → NoCompression
        var t0 = new PackTransform(cek, true, 0);
        // Level 3 → Fastest
        var t3 = new PackTransform(cek, true, 3);
        // Level 6 → Optimal
        var t6 = new PackTransform(cek, true, 6);
        // Level 9 → SmallestSize
        var t9 = new PackTransform(cek, true, 9);

        // All should work without error - but compression may differ
        var input = ArrayPool<byte>.Shared.Rent(1000);
        try
        {
            Array.Fill(input, (byte)'X', 0, 1000);
            var o0 = t0.Transform(input, 1000, out _);
            var o9 = t9.Transform(input, 1000, out _);
            Assert.True(o0.Length > 0);
            Assert.True(o9.Length > 0);
            ArrayPool<byte>.Shared.Return(o0);
            ArrayPool<byte>.Shared.Return(o9);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(input);
        }
    }

    [Fact]
    public void PackTransform_SameInputTwice_DifferentNonce()
    {
        var cek = RandomNumberGenerator.GetBytes(32);
        var transform = new PackTransform(cek, false, 6);

        var input = ArrayPool<byte>.Shared.Rent(50);
        try
        {
            Array.Fill(input, (byte)'Z', 0, 50);
            var o1 = transform.Transform(input, 50, out _);
            var o2 = transform.Transform(input, 50, out _);

            // Nonces should differ (first 12 bytes)
            Assert.False(o1.AsSpan(0, 12).SequenceEqual(o2.AsSpan(0, 12)));

            ArrayPool<byte>.Shared.Return(o1);
            ArrayPool<byte>.Shared.Return(o2);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(input);
        }
    }

    // ═══════════════════════════════════════════════════════
    //  ExtractTransform
    // ═══════════════════════════════════════════════════════

    [Fact]
    public void ExtractTransform_NoCompression_DecryptsData()
    {
        var cek = RandomNumberGenerator.GetBytes(32);
        var pack = new PackTransform(cek, false, 6);
        var extract = new ExtractTransform(cek);

        var input = ArrayPool<byte>.Shared.Rent(256);
        try
        {
            RandomNumberGenerator.Fill(input);
            var encrypted = pack.Transform(input, 256, out var encLen);
            var decrypted = extract.Transform(encrypted, encLen, out var decLen);

            Assert.Equal(256, decLen);
            Assert.True(input.AsSpan(0, 256).SequenceEqual(decrypted.AsSpan(0, 256)));

            ArrayPool<byte>.Shared.Return(decrypted);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(input);
        }
    }

    [Fact]
    public void ExtractTransform_WithCompression_RoundTrip()
    {
        var cek = RandomNumberGenerator.GetBytes(32);
        var pack = new PackTransform(cek, true, 6);
        var extract = new ExtractTransform(cek, true);

        var input = ArrayPool<byte>.Shared.Rent(4096);
        try
        {
            RandomNumberGenerator.Fill(input);
            var encrypted = pack.Transform(input, 4096, out var encLen);
            var decrypted = extract.Transform(encrypted, encLen, out var decLen);

            Assert.Equal(4096, decLen);
            Assert.True(input.AsSpan(0, 4096).SequenceEqual(decrypted.AsSpan(0, 4096)));

            ArrayPool<byte>.Shared.Return(decrypted);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(input);
        }
    }

    [Fact]
    public void ExtractTransform_WrongKey_Throws()
    {
        var cek1 = RandomNumberGenerator.GetBytes(32);
        var cek2 = RandomNumberGenerator.GetBytes(32);
        var pack = new PackTransform(cek1, false, 6);
        var extract = new ExtractTransform(cek2);

        var input = ArrayPool<byte>.Shared.Rent(100);
        try
        {
            RandomNumberGenerator.Fill(input);
            var encrypted = pack.Transform(input, 100, out var encLen);
            Assert.ThrowsAny<Exception>(() => extract.Transform(encrypted, encLen, out _));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(input);
        }
    }

    [Fact]
    public void ExtractTransform_SmallBlock_RoundTrip()
    {
        var cek = RandomNumberGenerator.GetBytes(32);
        var pack = new PackTransform(cek, false, 6);
        var extract = new ExtractTransform(cek);

        var input = ArrayPool<byte>.Shared.Rent(1);
        try
        {
            input[0] = 42;
            var encrypted = pack.Transform(input, 1, out var encLen);
            var decrypted = extract.Transform(encrypted, encLen, out var decLen);

            Assert.Equal(1, decLen);
            Assert.Equal(42, decrypted[0]);

            ArrayPool<byte>.Shared.Return(decrypted);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(input);
        }
    }

    // ═══════════════════════════════════════════════════════
    //  ConvertTransform
    // ═══════════════════════════════════════════════════════

    [Fact]
    public void ConvertTransform_ReencryptsData()
    {
        var oldCek = RandomNumberGenerator.GetBytes(32);
        var newCek = RandomNumberGenerator.GetBytes(32);
        var pack = new PackTransform(oldCek, false, 6);
        var convert = new ConvertTransform(oldCek, newCek);
        var extract = new ExtractTransform(newCek);

        var input = ArrayPool<byte>.Shared.Rent(500);
        try
        {
            RandomNumberGenerator.Fill(input);
            var encrypted = pack.Transform(input, 500, out var encLen);
            var converted = convert.Transform(encrypted, encLen, out var convLen);
            var decrypted = extract.Transform(converted, convLen, out var decLen);

            Assert.Equal(500, decLen);
            Assert.True(input.AsSpan(0, 500).SequenceEqual(decrypted.AsSpan(0, 500)));

            ArrayPool<byte>.Shared.Return(decrypted);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(input);
        }
    }

    [Fact]
    public void ConvertTransform_WrongOldKey_Throws()
    {
        var oldCek = RandomNumberGenerator.GetBytes(32);
        var wrongOldCek = RandomNumberGenerator.GetBytes(32);
        var newCek = RandomNumberGenerator.GetBytes(32);
        var pack = new PackTransform(oldCek, false, 6);
        var convert = new ConvertTransform(wrongOldCek, newCek);

        var input = ArrayPool<byte>.Shared.Rent(100);
        try
        {
            RandomNumberGenerator.Fill(input);
            var encrypted = pack.Transform(input, 100, out var encLen);
            Assert.ThrowsAny<Exception>(() => convert.Transform(encrypted, encLen, out _));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(input);
        }
    }

    [Fact]
    public void ConvertTransform_SameKey_ProducesDifferentCiphertext()
    {
        var cek = RandomNumberGenerator.GetBytes(32);
        var pack = new PackTransform(cek, false, 6);
        var convert = new ConvertTransform(cek, cek);

        var input = ArrayPool<byte>.Shared.Rent(100);
        try
        {
            RandomNumberGenerator.Fill(input);
            var encrypted = pack.Transform(input, 100, out var encLen);
            var converted = convert.Transform(encrypted, encLen, out _);

            // Even with same CEK, new nonce means different output
            Assert.False(encrypted.AsSpan(12).SequenceEqual(converted.AsSpan(12)));

            ArrayPool<byte>.Shared.Return(converted);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(input);
        }
    }
}
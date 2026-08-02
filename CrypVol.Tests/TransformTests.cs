using System.Security.Cryptography;
using CrypVol.Lib.Pipeline;
using CrypVol.Lib.Transforms;

namespace CrypVol.Tests;

public class TransformTests
{
    private static byte[] RandomCek()
    {
        return RandomNumberGenerator.GetBytes(32);
    }

    private static byte[] RandomData(int size)
    {
        return RandomNumberGenerator.GetBytes(size);
    }

    [Fact]
    public void PackThenExtract_NoCompression_RoundTrip()
    {
        var cek = RandomCek();
        var original = RandomData(4096);

        var pack = new PackTransform(cek, false, 6);
        var encrypted = pack.Transform(original, original.Length, out var encLen);

        var extract = new ExtractTransform(cek, false);
        var decrypted = extract.Transform(encrypted, encLen, out var decLen);

        Assert.Equal(original.Length, decLen);
        Assert.Equal(original, decrypted[..decLen]);
    }

    [Fact]
    public void PackThenExtract_WithCompression_RoundTrip()
    {
        var cek = RandomCek();
        var original = RandomData(8192);

        var pack = new PackTransform(cek, true, 6);
        var encrypted = pack.Transform(original, original.Length, out var encLen);

        var extract = new ExtractTransform(cek, true);
        var decrypted = extract.Transform(encrypted, encLen, out var decLen);

        Assert.Equal(original.Length, decLen);
        Assert.Equal(original, decrypted[..decLen]);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(256)]
    [InlineData(4096)]
    [InlineData(65536)]
    public void PackExtract_VariousSizes(int size)
    {
        var cek = RandomCek();
        var original = RandomData(size);

        var pack = new PackTransform(cek, false, 0);
        var enc = pack.Transform(original, original.Length, out var el);

        // Encrypted size = 12 nonce + size + 16 tag
        Assert.Equal(12 + size + 16, el);

        var ext = new ExtractTransform(cek, false);
        var dec = ext.Transform(enc, el, out var dl);

        Assert.Equal(size, dl);
        Assert.Equal(original, dec[..dl]);
    }

    [Fact]
    public void NullTransform_PassThrough()
    {
        var original = RandomData(1024);
        var nt = new NullTransform();
        var result = nt.Transform(original, original.Length, out var len);

        Assert.Equal(original.Length, len);
        Assert.Equal(original, result[..len]);
    }

    [Fact]
    public void ConvertTransform_RoundTrip()
    {
        var oldCek = RandomCek();
        var newCek = RandomCek();
        var original = RandomData(4096);

        // Encrypt with old key
        var pack = new PackTransform(oldCek, false, 0);
        var enc = pack.Transform(original, original.Length, out var el);

        // Convert (decrypt old + encrypt new)
        var conv = new ConvertTransform(oldCek, newCek);
        var converted = conv.Transform(enc, el, out var cl);

        // Decrypt with new key
        var ext = new ExtractTransform(newCek, false);
        var dec = ext.Transform(converted, cl, out var dl);

        Assert.Equal(original.Length, dl);
        Assert.Equal(original, dec[..dl]);
    }
}
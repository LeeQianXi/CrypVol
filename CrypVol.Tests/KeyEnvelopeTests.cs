using System.Security.Cryptography;
using CrypVol.Lib;

namespace CrypVol.Tests;

public class KeyEnvelopeTests
{
    [Fact]
    public void PlainKey_RoundTrip()
    {
        var path = Path.GetTempFileName();
        try
        {
            KeyEnvelope.SaveEnvelope(path, EnvelopeMode.Plain);
            var (c, s, _) = KeyEnvelope.LoadEnvelope(path);
            Assert.Equal(32, c.Length);
            Assert.Equal(32, s.Length);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Password_RoundTrip()
    {
        var path = Path.GetTempFileName();
        try
        {
            KeyEnvelope.SaveEnvelope(path, EnvelopeMode.Password, "pwd");
            var (c, _, _) = KeyEnvelope.LoadEnvelope(path, "pwd");
            Assert.Equal(32, c.Length);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Password_WrongPassword_Fails()
    {
        var path = Path.GetTempFileName();
        try
        {
            KeyEnvelope.SaveEnvelope(path, EnvelopeMode.Password, "correct");
            Assert.ThrowsAny<Exception>(() => KeyEnvelope.LoadEnvelope(path, "wrong"));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void ReadMode_ReturnsCorrectMode()
    {
        var path = Path.GetTempFileName();
        try
        {
            KeyEnvelope.SaveEnvelope(path, EnvelopeMode.Plain);
            Assert.Equal(EnvelopeMode.Plain, KeyEnvelope.ReadMode(path));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void SaveEnvelope_WithExistingCek_PreservesCEK()
    {
        var path = Path.GetTempFileName();
        try
        {
            KeyEnvelope.SaveEnvelope(path, EnvelopeMode.Plain);
            var (c1, _, _) = KeyEnvelope.LoadEnvelope(path);
            KeyEnvelope.SaveEnvelope(path, EnvelopeMode.Password, c1, RandomNumberGenerator.GetBytes(32), "p");
            var (c2, _, _) = KeyEnvelope.LoadEnvelope(path, "p");
            Assert.Equal(c1, c2);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Asymmetric_RoundTrip()
    {
        var path = Path.GetTempFileName();
        var rsa = RSA.Create(2048);
        try
        {
            KeyEnvelope.SaveEnvelope(path, EnvelopeMode.PublicKey, recipients: new Dictionary<string, RSA>
            {
                ["test"] = rsa
            });
            var (c, _, _) = KeyEnvelope.LoadEnvelope(path, privateKey: rsa);
            Assert.Equal(32, c.Length);
        }
        finally
        {
            File.Delete(path);
            rsa.Dispose();
        }
    }
}
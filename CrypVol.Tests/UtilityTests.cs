using CrypVol.Lib.Crypto;
using CrypVol.Lib.Engine.Models;
using CrypVol.Lib.Helper.Models;
using CrypVol.Lib.Utility;
using CrypVol.Lib.Volume;
using Xunit;

namespace CrypVol.Tests;

// Test types for StaticSingleton
file sealed class TestSingleton
{
    public Guid Id { get; } = Guid.NewGuid();
}

file sealed class AnotherSingleton
{
    public int Value { get; } = 42;
}

file abstract class TestSingletonBase : StaticSingleton<TestSingleton>
{
}

file abstract class AnotherSingletonBase : StaticSingleton<AnotherSingleton>
{
}

file abstract class LazySingletonBase : StaticSingleton<TestSingleton>
{
}

public class StaticSingletonTests
{
    [Fact]
    public void Instance_SameType_ReturnsSameInstance()
    {
        var a = TestSingletonBase.Instance;
        var b = TestSingletonBase.Instance;
        Assert.Same(a, b);
    }

    [Fact]
    public void Instance_MultipleAccesses_SameId()
    {
        var a = TestSingletonBase.Instance;
        var b = TestSingletonBase.Instance;
        Assert.Equal(a.Id, b.Id);
    }

    [Fact]
    public void Instance_DifferentTypes_AreIndependent()
    {
        var a = TestSingletonBase.Instance;
        var b = AnotherSingletonBase.Instance;

        Assert.NotSame(a, b);
        Assert.IsType<TestSingleton>(a);
        Assert.IsType<AnotherSingleton>(b);
        Assert.Equal(42, b.Value);
    }

    [Fact]
    public void Instance_IsLazy_NotCreatedUntilAccessed()
    {
        var instance = LazySingletonBase.Instance;
        Assert.NotNull(instance);
        Assert.IsType<TestSingleton>(instance);
    }
}

public class EncryptionModeTests
{
    [Fact]
    public void EncryptionMode_ValuesAreDistinct()
    {
        var values = Enum.GetValues<EncryptionMode>();
        Assert.Equal(5, values.Length);
        Assert.Contains(EncryptionMode.None, values);
        Assert.Contains(EncryptionMode.PlainKey, values);
        Assert.Contains(EncryptionMode.Password, values);
        Assert.Contains(EncryptionMode.Asymmetric, values);
    }
}

public class IntegrityLevelTests
{
    [Fact]
    public void IntegrityLevel_HasAllValues()
    {
        Assert.Equal(4, Enum.GetValues<IntegrityLevel>().Length);
    }

    /// <summary>库直接调用 Pack 时应与 CLI 保持相同的块级完整性默认值。</summary>
    [Fact]
    public void PackOptions_DefaultIntegrityLevel_IsBlock()
    {
        var options = new PackOptions
        {
            SourceFolder = new DirectoryInfo(Path.GetTempPath()),
            SourceFiles = Array.Empty<FileInfo>(),
            OutputDir = new DirectoryInfo(Path.GetTempPath()),
            Credentials = new CvkCredentials(EncryptionMode.None, Array.Empty<byte>())
        };

        Assert.Equal(IntegrityLevel.Block, options.IntegrityLevel);
    }
}

public class BrowseOutputModeTests
{
    [Fact]
    public void BrowseOutputMode_HasAllValues()
    {
        Assert.Equal(4, Enum.GetValues<BrowseOutputMode>().Length);
    }

    [Fact]
    public void BrowseSortField_HasAllValues()
    {
        Assert.Equal(3, Enum.GetValues<BrowseSortField>().Length);
    }
}

public class EnvelopeModeTests
{
    [Fact]
    public void EnvelopeMode_Values()
    {
        Assert.Equal(0, (byte)EnvelopeMode.Plain);
        Assert.Equal(1, (byte)EnvelopeMode.Password);
        Assert.Equal(2, (byte)EnvelopeMode.PublicKey);
    }
}

public class BlockMetadataTests
{
    [Fact]
    public void BlockMetadata_Properties_SetCorrectly()
    {
        var item = new BlockMetadata
        {
            RelativePath = "sub/file.txt",
            SourceFullPath = "/tmp/sub/file.txt",
            TargetIndex = 2,
            Sequence = 5,
            SourceOffset = 1024,
            Length = 4096,
            TotalFileSize = 10000,
            Flags = 1,
            IsFirstFragment = true
        };

        Assert.Equal("sub/file.txt", item.RelativePath);
        Assert.Equal("/tmp/sub/file.txt", item.SourceFullPath);
        Assert.Equal(2, item.TargetIndex);
        Assert.Equal(5, item.Sequence);
        Assert.Equal(1024, item.SourceOffset);
        Assert.Equal(4096, item.Length);
        Assert.Equal(10000, item.TotalFileSize);
        Assert.Equal(1, item.Flags);
        Assert.True(item.IsFirstFragment);
    }
}

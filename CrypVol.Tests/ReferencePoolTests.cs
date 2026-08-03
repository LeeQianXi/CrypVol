using CrypVol.Lib.RefPool;
using Xunit;

namespace CrypVol.Tests;

// Test reference type for pool tests
file sealed class TestReference : IReference<TestReference>
{
    public string? Value { get; set; }

    public void Reset()
    {
        Value = null;
    }
}

file sealed class AnotherReference : IReference<AnotherReference>
{
    public void Reset() { }
}

public class ReferencePoolTests : IDisposable
{
    public void Dispose()
    {
        ReferencePool.ClearAll();
        ReferencePool.EnableStrictCheck = false;
    }

    // ── Acquire (generic) ──

    [Fact]
    public void Acquire_Generic_ReturnsNewInstance()
    {
        var r = ReferencePool.Acquire<TestReference>();
        Assert.NotNull(r);
        Assert.IsType<TestReference>(r);
    }

    [Fact]
    public void Acquire_Generic_ReleasedInstance_Reused()
    {
        var r1 = ReferencePool.Acquire<TestReference>();
        r1.Value = "modified";
        ReferencePool.Release(r1);

        var r2 = ReferencePool.Acquire<TestReference>();
        Assert.Same(r1, r2); // should be the same object
        Assert.Null(r2.Value); // Reset() was called
    }

    [Fact]
    public void Acquire_Generic_MultipleAcquire_ReturnsDifferentInstances()
    {
        var r1 = ReferencePool.Acquire<TestReference>();
        var r2 = ReferencePool.Acquire<TestReference>();
        Assert.NotSame(r1, r2);
    }

    // ── Acquire (non-generic) ──

    [Fact]
    public void Acquire_NonGeneric_ReturnsCorrectType()
    {
        var r = ReferencePool.Acquire(typeof(TestReference));
        Assert.NotNull(r);
        Assert.IsType<TestReference>(r);
    }

    [Fact]
    public void Acquire_NonGeneric_MultipleTypes()
    {
        var r1 = ReferencePool.Acquire<TestReference>();
        var r2 = ReferencePool.Acquire<AnotherReference>();
        Assert.IsType<TestReference>(r1);
        Assert.IsType<AnotherReference>(r2);
    }

    // ── Release ──

    [Fact]
    public void Release_Null_Throws()
    {
        Assert.Throws<Exception>(() => ReferencePool.Release(null!));
    }

    [Fact]
    public void Release_RecyclesObject()
    {
        var r = ReferencePool.Acquire<TestReference>();
        ReferencePool.Release(r);
        // Should not throw
    }

    // ── Add ──

    [Fact]
    public void Add_Generic_IncreasesPool()
    {
        ReferencePool.Add<TestReference>(5);
        var r1 = ReferencePool.Acquire<TestReference>();
        var r2 = ReferencePool.Acquire<TestReference>();
        var r3 = ReferencePool.Acquire<TestReference>();
        Assert.NotSame(r1, r2);
        Assert.NotSame(r2, r3);
    }

    [Fact]
    public void Add_NonGeneric_IncreasesPool()
    {
        ReferencePool.Add(typeof(TestReference), 3);
        // Should be able to acquire without needing new()
        var r = ReferencePool.Acquire<TestReference>();
        Assert.NotNull(r);
    }

    // ── Remove ──

    [Fact]
    public void Remove_Generic_ReducesPool()
    {
        ReferencePool.Add<TestReference>(5);
        ReferencePool.Remove<TestReference>(3);
        // Should not throw - remaining 2 in pool
    }

    [Fact]
    public void Remove_NonGeneric_ReducesPool()
    {
        ReferencePool.Add(typeof(TestReference), 5);
        ReferencePool.Remove(typeof(TestReference), 5);
        // Pool should now be empty but still functional
        var r = ReferencePool.Acquire<TestReference>();
        Assert.NotNull(r);
    }

    [Fact]
    public void Remove_MoreThanAvailable_ClampsToAvailable()
    {
        ReferencePool.Add<TestReference>(2);
        ReferencePool.Remove<TestReference>(100); // should not throw
    }

    // ── RemoveAll ──

    [Fact]
    public void RemoveAll_Generic_EmptiesPool()
    {
        ReferencePool.Add<TestReference>(10);
        ReferencePool.RemoveAll<TestReference>();
        var r = ReferencePool.Acquire<TestReference>();
        Assert.NotNull(r);
        ReferencePool.Release(r);
    }

    [Fact]
    public void RemoveAll_NonGeneric_EmptiesPool()
    {
        ReferencePool.Add(typeof(TestReference), 10);
        ReferencePool.RemoveAll(typeof(TestReference));
        // Pool should still be usable
        var r = ReferencePool.Acquire<TestReference>();
        Assert.NotNull(r);
        ReferencePool.Release(r);
    }

    // ── ClearAll ──

    [Fact]
    public void ClearAll_RemovesAllPools()
    {
        ReferencePool.Acquire<TestReference>();
        ReferencePool.Acquire<AnotherReference>();
        ReferencePool.ClearAll();
        Assert.Equal(0, ReferencePool.Count);
    }

    [Fact]
    public void ClearAll_Afterwards_PoolsRecreated()
    {
        ReferencePool.Acquire<TestReference>();
        ReferencePool.ClearAll();
        var r = ReferencePool.Acquire<TestReference>();
        Assert.NotNull(r);
    }

    // ── GetAllReferencePoolInfos ──

    [Fact]
    public void GetAllReferencePoolInfos_ReturnsCorrectInfo()
    {
        ReferencePool.ClearAll();
        ReferencePool.Acquire<TestReference>();
        ReferencePool.Acquire<AnotherReference>();

        var infos = ReferencePool.GetAllReferencePoolInfos();
        Assert.Equal(2, infos.Length);
        Assert.Contains(infos, i => i.Type == typeof(TestReference));
        Assert.Contains(infos, i => i.Type == typeof(AnotherReference));
    }

    [Fact]
    public void GetAllReferencePoolInfos_Empty_ReturnsEmpty()
    {
        ReferencePool.ClearAll();
        var infos = ReferencePool.GetAllReferencePoolInfos();
        Assert.Empty(infos);
    }

    [Fact]
    public void GetAllReferencePoolInfos_HasCorrectCounters()
    {
        ReferencePool.ClearAll();
        var r = ReferencePool.Acquire<TestReference>();
        ReferencePool.Release(r);

        var infos = ReferencePool.GetAllReferencePoolInfos();
        var info = infos.Single(i => i.Type == typeof(TestReference));
        Assert.Equal(1, info.AcquireReferenceCount);
        Assert.Equal(1, info.ReleaseReferenceCount);
        Assert.Equal(0, info.UsingReferenceCount);
        Assert.Equal(1, info.UnusedReferenceCount);
    }

    // ── EnableStrictCheck ──

    [Fact]
    public void EnableStrictCheck_DoubleRelease_Throws()
    {
        ReferencePool.EnableStrictCheck = true;
        var r = ReferencePool.Acquire<TestReference>();
        ReferencePool.Release(r);
        Assert.Throws<Exception>(() => ReferencePool.Release(r));
    }

    [Fact]
    public void StrictCheck_Disabled_DoubleRelease_NoThrow()
    {
        ReferencePool.EnableStrictCheck = false;
        var r = ReferencePool.Acquire<TestReference>();
        ReferencePool.Release(r);
        // Second release should not throw when strict check is off
        ReferencePool.Release(r);
    }

    // ── Count ──

    [Fact]
    public void Count_ReflectsActivePools()
    {
        ReferencePool.ClearAll();
        Assert.Equal(0, ReferencePool.Count);
        ReferencePool.Acquire<TestReference>();
        Assert.Equal(1, ReferencePool.Count);
        ReferencePool.Acquire<AnotherReference>();
        Assert.Equal(2, ReferencePool.Count);
    }

    // ── ReferencePoolInfo Struct ──

    [Fact]
    public void ReferencePoolInfo_Constructor_PreservesValues()
    {
        var info = new ReferencePoolInfo(typeof(string), 1, 2, 3, 4, 5, 6);
        Assert.Equal(typeof(string), info.Type);
        Assert.Equal(1, info.UnusedReferenceCount);
        Assert.Equal(2, info.UsingReferenceCount);
        Assert.Equal(3, info.AcquireReferenceCount);
        Assert.Equal(4, info.ReleaseReferenceCount);
        Assert.Equal(5, info.AddReferenceCount);
        Assert.Equal(6, info.RemoveReferenceCount);
    }
}

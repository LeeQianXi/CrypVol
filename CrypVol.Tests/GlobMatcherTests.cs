using CrypVol.Lib;
using Xunit;

namespace CrypVol.Tests;

public class GlobMatcherTests
{
    [Fact]
    public void EmptyMatcher_IsActive_False()
    {
        var m = new GlobMatcher();
        Assert.False(m.IsActive);
    }

    [Fact]
    public void EmptyMatcher_AllPass()
    {
        var m = new GlobMatcher();
        Assert.True(m.IsMatch("anything.txt"));
        Assert.True(m.IsMatch("deep/nested/file.bin"));
    }

    [Fact]
    public void IncludeOnly_MatchesPattern()
    {
        var m = new GlobMatcher();
        m.AddInclude("*.md");
        Assert.True(m.IsActive);
        Assert.True(m.IsMatch("readme.md"));
        Assert.False(m.IsMatch("readme.txt"));
    }

    [Fact]
    public void IncludeOnly_MultiplePatterns()
    {
        var m = new GlobMatcher();
        m.AddInclude("*.md");
        m.AddInclude("*.txt");
        Assert.True(m.IsMatch("readme.md"));
        Assert.True(m.IsMatch("notes.txt"));
        Assert.False(m.IsMatch("image.png"));
    }

    [Fact]
    public void ExcludeOnly_NoInclude_AllPassExceptExcluded()
    {
        var m = new GlobMatcher();
        m.AddExclude("*.tmp");
        Assert.True(m.IsActive);
        Assert.True(m.IsMatch("data.bin"));
        Assert.False(m.IsMatch("temp.tmp"));
    }

    [Fact]
    public void IncludeAndExclude_ExcludeTakesPriority()
    {
        var m = new GlobMatcher();
        m.AddInclude("**/*");
        m.AddExclude("**/node_modules/**");
        Assert.True(m.IsMatch("src/app.js"));
        Assert.False(m.IsMatch("node_modules/lodash/index.js"));
        Assert.False(m.IsMatch("src/node_modules/pkg/main.js"));
    }

    [Fact]
    public void GlobPattern_MatchesDirectoryLevels()
    {
        var m = new GlobMatcher();
        m.AddInclude("*/*.md");
        Assert.True(m.IsMatch("docs/readme.md"));
        Assert.False(m.IsMatch("readme.md")); // no directory
        Assert.False(m.IsMatch("a/b/readme.md")); // two levels
    }
}
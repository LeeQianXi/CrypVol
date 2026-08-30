using DotNet.Globbing;

namespace CrypVol.Lib.Utility;

/// <summary>Glob 模式匹配器：支持 include/exclude 双重过滤</summary>
public sealed class GlobMatcher
{
    private readonly List<Glob> _excludeGlobs = [];
    private readonly List<Glob> _includeGlobs = [];

    /// <summary>是否有任何过滤规则（无规则时 IsMatch 永远返回 true）</summary>
    public bool IsActive => _includeGlobs.Count > 0 || _excludeGlobs.Count > 0;

    public void AddInclude(string pattern)
    {
        _includeGlobs.Add(Glob.Parse(pattern));
    }

    public void AddExclude(string pattern)
    {
        _excludeGlobs.Add(Glob.Parse(pattern));
    }

    /// <summary>判断输入是否匹配：必须命中 include（如无则全部通过）且未被 exclude 排除</summary>
    public bool IsMatch(string input)
    {
        if (_includeGlobs.Count > 0 && !_includeGlobs.Any(g => g.IsMatch(input)))
            return false;
        if (_excludeGlobs.Any(g => g.IsMatch(input)))
            return false;
        return true;
    }
}